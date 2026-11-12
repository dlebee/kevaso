// Package controlplane is the control-plane component of kevasod: the API over TLS, the local admin
// socket, the cluster CA, and this host's own Host object with a Ready heartbeat.
//
// `kvoadm init` installs it as a systemd service on the first host; it creates the CA on first start
// and keeps everything under DataDir (store.db, pki/).
package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kcc/acme"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/audit"
	"kevaso.com/core/internal/backup"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controllers/certificate"
	hostcontroller "kevaso.com/core/internal/controllers/host"
	silocontroller "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/issuer"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/mesh"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kcc"
)

// Config is what the control plane needs.
type Config struct {
	ClusterName string
	HostName    string   // this host's name
	Address     string   // its address (in the server certificate and the Host object)
	ExtraNames  []string // more names/IPs for the server certificate (DNS name, 127.0.0.1)
	DataDir     string
	Listen      string // TLS API, e.g. 0.0.0.0:6443
	AdminSocket string // e.g. /run/kevaso/admin.sock
	Heartbeat   time.Duration
	HostLease   time.Duration // a host without a heartbeat this long is lost (default 40s)
	Mesh        bool          // put this host on the WireGuard mesh (Linux; off in tests)
	Clock       clock.Clock
	// Worker, when set, also runs the worker component on this host (one-host clusters).
	Worker *worker.Config
	// CertControllers are cert-controllers registered on this host beyond the built-in ones
	// (acme, internal-ca), and DNSProviders the DNS providers acme's dns01 solvers may name.
	CertControllers kcc.Registry
	DNSProviders    map[string]acme.DNSProvider
	Log             func(format string, args ...any)
}

func (c *Config) defaults() {
	if c.ClusterName == "" {
		c.ClusterName = "kevaso"
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = 30 * time.Second
	}
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Log == nil {
		c.Log = func(string, ...any) {}
	}
}

// Running is a started control plane.
type Running struct {
	APIAddr string // where the TLS API listens
	CA      *pki.CA
	Tokens  *jointoken.Issuer
	done    chan struct{}
	err     error
}

// Wait blocks until the control plane stopped and returns why.
func (r *Running) Wait() error { <-r.done; return r.err }

// Start brings the control plane up and returns once it serves; it stops when ctx ends.
func Start(ctx context.Context, cfg Config) (*Running, error) {
	cfg.defaults()
	if cfg.HostName == "" || cfg.Address == "" || cfg.DataDir == "" || cfg.Listen == "" || cfg.AdminSocket == "" {
		return nil, errors.New("control plane needs a host name, an address, a data dir, a listen address and an admin socket")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	pkiDir := filepath.Join(cfg.DataDir, "pki")
	ca, err := pki.LoadCA(pkiDir)
	if errors.Is(err, os.ErrNotExist) {
		cfg.Log("creating the cluster CA in %s", pkiDir)
		if ca, err = pki.NewCA(cfg.ClusterName, cfg.Clock.Now()); err == nil {
			err = ca.Save(pkiDir)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("cluster CA: %w", err)
	}
	names := append([]string{cfg.HostName, cfg.Address, "127.0.0.1", "localhost"}, cfg.ExtraNames...)
	serverCert, err := ca.ServerCert(names, cfg.Clock.Now(), 365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	st, err := store.OpenSQLite(filepath.Join(cfg.DataDir, "store.db"), 0)
	if err != nil {
		return nil, err
	}
	tokens := &jointoken.Issuer{Store: st, Clock: cfg.Clock}
	_, port, _ := net.SplitHostPort(cfg.Listen)
	iss, err := issuer.New(ctx, st, cfg.Clock, "https://"+net.JoinHostPort(cfg.Address, port))
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("issuer: %w", err)
	}
	auditLog := &audit.File{Path: filepath.Join(cfg.DataDir, "audit.log"), OnError: func(err error) { cfg.Log("audit: %v", err) }}
	iss.Audit = auditLog
	srv, err := apiserver.NewWithAuth(st, cfg.Clock, &apiserver.Auth{CA: ca, Tokens: tokens, Issuer: iss, Audit: auditLog})
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	// The master key for secrets: a root-only file next to the store (design §8.4a).
	localKMS, err := kms.OpenLocal(filepath.Join(cfg.DataDir, "kms", "local.json"))
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("kms: %w", err)
	}
	srv.SetVault(&secrets.Vault{Store: st, KMS: localKMS, Now: cfg.Clock.Now})
	srv.SetKMSAdmin(localKMS)
	srv.SetBackup(func(ctx context.Context, pub []byte) ([]byte, error) {
		ks, _ := localKMS.Status(ctx)
		return backup.Make(ctx, cfg.DataDir, st.Snapshot,
			backup.Manifest{Cluster: cfg.ClusterName, Host: cfg.HostName, Created: cfg.Clock.Now(), KMSKeyID: ks.KeyID}, pub)
	})

	if err := os.MkdirAll(filepath.Dir(cfg.AdminSocket), 0o700); err != nil {
		_ = st.Close()
		return nil, err
	}
	adminL, err := apiserver.ListenAdminSocket(cfg.AdminSocket)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	apiL, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		_ = adminL.Close()
		_ = st.Close()
		return nil, err
	}
	apiSrv := srv.HTTPServer(false)
	apiSrv.TLSConfig = srv.TLSConfig(serverCert)
	adminSrv := srv.HTTPServer(true)

	r := &Running{APIAddr: apiL.Addr().String(), CA: ca, Tokens: tokens, done: make(chan struct{})}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs <- serveErr(apiSrv.ServeTLS(apiL, "", "")) }()
	go func() { defer wg.Done(); errs <- serveErr(adminSrv.Serve(adminL)) }()

	admin, closeInProcess := srv.InProcess() // the components' own way in, not the admin socket
	hbCtx, stopHB := context.WithCancel(ctx)
	go heartbeat(hbCtx, admin, cfg)
	go runControllers(hbCtx, admin, cfg, certDeps{store: st, kms: localKMS, ca: ca})
	if cfg.Mesh {
		m := &mesh.Agent{Client: admin, HostName: cfg.HostName, Dir: filepath.Join(cfg.DataDir, "mesh"), Log: cfg.Log}
		go func() {
			if err := m.Run(hbCtx); err != nil {
				cfg.Log("mesh: %v", err)
			}
		}()
	}
	if cfg.Worker != nil {
		wc := *cfg.Worker
		wc.HostName, wc.Clock, wc.Log, wc.MeshSubnet = cfg.HostName, cfg.Clock, cfg.Log, cfg.Mesh
		if wc.DataDir == "" {
			wc.DataDir = cfg.DataDir
		}
		rts, err := worker.NewRuntimes(wc)
		if err != nil {
			stopHB()
			closeInProcess()
			return nil, err
		}
		go worker.Run(hbCtx, admin, wc, rts)
	}

	go func() {
		select {
		case <-ctx.Done():
		case err := <-errs:
			r.err = err
		}
		stopHB()
		closeInProcess()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = apiSrv.Shutdown(sctx)
		_ = adminSrv.Shutdown(sctx)
		wg.Wait()
		_ = st.Close()
		_ = os.Remove(cfg.AdminSocket)
		close(r.done)
	}()
	cfg.Log("API on https://%s, admin socket %s", r.APIAddr, cfg.AdminSocket)
	return r, nil
}

// runControllers starts the built-in controllers on informers fed through the admin socket.
// certControllers are the built-in cert-controllers plus the ones registered on this host (which
// can't replace a built-in one).
func certControllers(cfg Config, cd certDeps) kcc.Registry {
	r := certificate.BuiltinCertControllers(cd.store, cd.kms, cd.ca, cfg.Clock.Now, cfg.DNSProviders)
	for n, c := range cfg.CertControllers {
		if _, builtin := r[n]; builtin {
			cfg.Log("cert-controller %s: that name is built in; ignored", n)
			continue
		}
		r[n] = c
		cfg.Log("cert-controller %s: %s", n, c.Info().Description)
	}
	for n := range cfg.DNSProviders {
		cfg.Log("dns provider %s registered", n)
	}
	return r
}

// certDeps are what the certificate controller needs beyond the API.
type certDeps struct {
	store store.Store
	kms   kms.KMS
	ca    *pki.CA
}

func runControllers(ctx context.Context, c *client.Client, cfg Config, cd certDeps) {
	silos, hosts, pools := informer.New(c, "Silo"), informer.New(c, "Host"), informer.New(c, "IPPool")
	certs, ingresses, classes, issuers := informer.New(c, "Certificate"), informer.New(c, "Ingress"), informer.New(c, "IngressClass"), informer.New(c, "Issuer")
	if err := certificate.EnsureIssuers(ctx, c); err != nil {
		cfg.Log("built-in issuers: %v", err)
	}
	e := engine.New(cfg.Clock)
	e.OnError = func(ctrl string, k engine.Key, err error, retry time.Duration) {
		cfg.Log("%s: %s: %v (retry in %v)", ctrl, k, err, retry)
	}
	e.Register(&silocontroller.Controller{Client: c, Silos: silos, Hosts: hosts, Pools: pools, Clock: cfg.Clock}, engine.Options{Workers: 1})
	e.Register(&hostcontroller.Controller{Client: c, Hosts: hosts, Clock: cfg.Clock, Lease: cfg.HostLease}, engine.Options{Workers: 1})
	silos.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: k.Name}) })
	hosts.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Host", Name: k.Name}) })
	pools.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "IPPool", Name: k.Name}) })
	cc := &certificate.Controller{Client: c, Store: cd.store, KMS: cd.kms, Clock: cfg.Clock,
		CertControllers: certControllers(cfg, cd),
		Certificates:    certs, Ingresses: ingresses, Classes: classes, Issuers: issuers, Log: cfg.Log}
	e.Register(cc, engine.Options{Workers: 2})
	e.Register(cc.IngressController(), engine.Options{Workers: 1})
	ingressesOf := func(match func(*v1.Ingress) bool) {
		for _, o := range ingresses.List() {
			if ing := o.(*v1.Ingress); match(ing) {
				e.Changed(engine.Key{Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name})
			}
		}
	}
	certs.AddHandler(func(k informer.Key) {
		e.Changed(engine.Key{Kind: "Certificate", Namespace: k.Namespace, Name: k.Name})
		ingressesOf(func(ing *v1.Ingress) bool { return ing.Namespace == k.Namespace && v1.CertificateFor(ing) == k.Name })
	})
	ingresses.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Ingress", Namespace: k.Namespace, Name: k.Name}) })
	issuers.AddHandler(func(k informer.Key) { // an Issuer made or fixed: its certificates try again
		for _, o := range certs.List() {
			if c := o.(*v1.Certificate); c.Spec.Issuer == k.Name {
				e.Changed(engine.Key{Kind: "Certificate", Namespace: c.Namespace, Name: c.Name})
			}
		}
	})
	classes.AddHandler(func(k informer.Key) {
		ingressesOf(func(ing *v1.Ingress) bool { return ing.Spec.IngressClass == k.Name })
	})
	silos.AddHandler(func(k informer.Key) { // a controller's address shows in its Ingresses' status
		for _, o := range classes.List() {
			cl := o.(*v1.IngressClass)
			if cl.Spec.Controller.Namespace == k.Namespace && cl.Spec.Controller.Silo == k.Name {
				ingressesOf(func(ing *v1.Ingress) bool { return ing.Spec.IngressClass == cl.Name })
			}
		}
	})
	for _, inf := range []*informer.Informer{certs, ingresses, classes, issuers} {
		go inf.Run(ctx)
	}
	go silos.Run(ctx)
	go hosts.Run(ctx)
	go pools.Run(ctx)
	e.Run(ctx)
}

func serveErr(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// heartbeat makes sure this host's Host object exists and keeps its Ready condition fresh.
func heartbeat(ctx context.Context, c *client.Client, cfg Config) {
	tick := func() {
		var h v1.Host
		err := c.Get(ctx, "Host", "", cfg.HostName, &h)
		if client.IsNotFound(err) {
			h = v1.Host{
				TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"},
				ObjectMeta: meta.ObjectMeta{Name: cfg.HostName},
				Spec:       v1.HostSpec{Address: cfg.Address, Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{}}},
			}
			if err = c.Create(ctx, &h); err != nil {
				cfg.Log("register host: %v", err)
				return
			}
		} else if err != nil {
			cfg.Log("heartbeat: %v", err)
			return
		} else if h.Spec.Address != cfg.Address { // moved (restored onto a new machine)
			cfg.Log("host %s: address %s → %s", cfg.HostName, h.Spec.Address, cfg.Address)
			h.Spec.Address = cfg.Address
			if err := c.Update(ctx, &h); err != nil {
				cfg.Log("host address: %v", err)
				return
			}
			if err := c.Get(ctx, "Host", "", cfg.HostName, &h); err != nil {
				return
			}
		}
		meta.SetCondition(&h.Status.Conditions, meta.Condition{
			Type: "Ready", Status: meta.ConditionTrue, Reason: "ControlPlaneUp",
			Message: "API serving", ObservedGeneration: h.Generation,
		}, cfg.Clock.Now().UTC().Truncate(time.Second))
		setHeartbeat(&h, cfg.Clock.Now())
		if err := c.UpdateStatus(ctx, &h); err != nil && ctx.Err() == nil {
			cfg.Log("heartbeat status: %v", err)
		}
	}
	tick()
	t := time.NewTicker(cfg.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// setHeartbeat records when the agent last reported (M5's host-loss detection reads it).
func setHeartbeat(h *v1.Host, now time.Time) {
	t := now.UTC().Truncate(time.Second)
	h.Status.LastHeartbeat = &t
}

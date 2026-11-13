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
	kicdrivers "kevaso.com/core/builtin/kic"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/approvals"
	"kevaso.com/core/internal/audit"
	"kevaso.com/core/internal/backup"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controllers/certificate"
	hostcontroller "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/controllers/provider"
	servicecontroller "kevaso.com/core/internal/controllers/service"
	silocontroller "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/controllers/siloset"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/internal/issuer"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/leader"
	"kevaso.com/core/internal/leases"
	"kevaso.com/core/internal/mesh"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/scheduler"
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
	// DefaultIssuers are the Issuers of Ingresses that name none: Public for public classes
	// (default letsencrypt), Private for private ones (default internal-ca).
	DefaultIssuers certificate.Defaults
	// Plugins are the provider plugins (load balancers, volumes, DNS); nil: none. kevasod watches
	// kplugin.Dir for them.
	Plugins *plugins.Registry
	// Approvals: how long requests for a person's yes wait, and how long access may last (§8.7).
	Approvals approvals.Limits
	// Leases: the longest a port may be open on a lease, and the limit when a silo sets none (§7.2d).
	Leases leases.Limits
	Log    func(format string, args ...any)
	// Store is StoreSQLite (default) or StoreEtcd; Etcd configures the embedded member.
	Store string
	Etcd  EtcdConfig
	// More than one system node (systemnodes.go, ADR 0006): Join on a node's first start takes it
	// into an existing cluster; StateOnly runs a light node (the etcd member only); ClusterDNS is
	// the control plane's one name (server certificates, the OIDC issuer); Leader times the
	// controllers' election; MemberEvery is how often the leader looks at the etcd members.
	Join        *JoinConfig
	StateOnly   bool
	ClusterDNS  string
	Leader      leader.Options
	MemberEvery time.Duration
}

func (c *Config) defaults() {
	if c.ClusterName == "" {
		c.ClusterName = "kevaso"
	}
	if c.Heartbeat <= 0 {
		// The worker's period: with a worker here, the heartbeat is also the fence's contact,
		// which must stay well under FenceAfter.
		c.Heartbeat = worker.DefaultHeartbeat
	}
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Log == nil {
		c.Log = func(string, ...any) {}
	}
	if c.HostLease <= 0 {
		c.HostLease = 40 * time.Second
	}
	if c.MemberEvery <= 0 {
		c.MemberEvery = 5 * time.Second
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
	if err := prepareJoin(ctx, &cfg); err != nil {
		return nil, err
	}
	ca, err := loadOrCreateCA(cfg)
	if err != nil {
		return nil, err
	}
	names := append([]string{cfg.HostName, cfg.Address, "127.0.0.1", "localhost"}, cfg.ExtraNames...)
	if cfg.ClusterDNS != "" {
		names = append(names, cfg.ClusterDNS)
	}
	serverCert, err := ca.ServerCert(names, cfg.Clock.Now(), 365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	st, err := openStore(ctx, cfg, ca)
	if err != nil {
		return nil, err
	}
	if cfg.StateOnly {
		return startStateOnly(ctx, cfg, st)
	}
	tokens := &jointoken.Issuer{Store: st, Clock: cfg.Clock}
	_, port, _ := net.SplitHostPort(cfg.Listen)
	issuerHost := cfg.Address
	if cfg.ClusterDNS != "" { // one issuer for every system node: tokens work at any of them
		issuerHost = cfg.ClusterDNS
	}
	iss, err := issuer.New(ctx, st, cfg.Clock, "https://"+net.JoinHostPort(issuerHost, port))
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
	srv.SetLog(cfg.Log)
	srv.SetApprovalLimits(cfg.Approvals)
	srv.SetLeaseLimits(cfg.Leases)
	if cfg.Plugins != nil {
		reg := cfg.Plugins
		srv.SetClasses(func() map[string]scheduler.Class { return provider.Classes(reg) })
	}
	srv.SetVault(&secrets.Vault{Store: st, KMS: localKMS, Now: cfg.Clock.Now})
	srv.SetKMSAdmin(haKMS{localKMS, st})
	if st.etcd != nil {
		j := &joiner{cfg: cfg, st: st, clock: cfg.Clock.Now}
		srv.SetSystemNodeJoiner(j.join)
	}
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
	var contact *worker.Contact // with a worker here: the fence's contact and whether it applies
	if cfg.Worker != nil {
		contact = &worker.Contact{}
	}
	go heartbeat(hbCtx, admin, cfg, cfg.self(r.APIAddr, st), contact)
	// Every system node serves the API; one at a time runs the controllers (systemnodes.go).
	go runLeader(hbCtx, st, cfg, func(ctx context.Context) {
		go expireApprovals(ctx, srv, cfg)
		if st.etcd != nil {
			go runMembers(ctx, admin, st, cfg, cfg.MemberEvery)
		}
		runControllers(ctx, admin, cfg, certDeps{store: st, kms: localKMS, ca: ca})
	})
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
		wc.HostName, wc.Clock, wc.Log, wc.MeshSubnet, wc.Contact = cfg.HostName, cfg.Clock, cfg.Log, cfg.Mesh, contact
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

// expireApprovals marks requests for a person's yes that nobody answered in time, and, less
// often, removes the panes and bundles of silos that are gone.
func expireApprovals(ctx context.Context, srv *apiserver.Server, cfg Config) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := srv.ExpireApprovals(ctx); err != nil && ctx.Err() == nil {
				cfg.Log("approvals: %v", err)
			}
			if err := srv.SweepLeases(ctx); err != nil && ctx.Err() == nil {
				cfg.Log("leases: %v", err)
			}
			if n%6 == 0 {
				if err := srv.SweepPanes(ctx); err != nil && ctx.Err() == nil {
					cfg.Log("panes: %v", err)
				}
			}
		}
	}
}

// runControllers starts the built-in controllers on informers fed through the admin socket.
// certControllers are the built-in cert-controllers plus the ones registered on this host (which
// can't replace a built-in one).
func certControllers(cfg Config, cd certDeps) kcc.Registry {
	r := certificate.BuiltinCertControllers(cd.store, cd.kms, cd.ca, cfg.Clock.Now, cfg.DNSProviders)
	if a, ok := r["acme"].(*acme.Controller); ok && cfg.Plugins != nil {
		a.DNSLookup = func(name string) acme.DNSProvider {
			if _, ok := cfg.Plugins.DNS(name); !ok {
				return nil
			}
			return &provider.DNSProvider{Plugins: cfg.Plugins, Name: name, Owner: "kevaso:" + cfg.ClusterName + "/acme"}
		}
	}
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
	images, sets, services := informer.New(c, "Image"), informer.New(c, "SiloSet"), informer.New(c, "Service")
	sc := &silocontroller.Controller{Client: c, Silos: silos, Hosts: hosts, Pools: pools, Images: images, Clock: cfg.Clock}
	if cfg.Plugins != nil {
		reg := cfg.Plugins
		sc.Classes = func() map[string]scheduler.Class { return provider.Classes(reg) }
	}
	e.Register(sc, engine.Options{Workers: 1})
	e.Register(&hostcontroller.Controller{Client: c, Hosts: hosts, Clock: cfg.Clock, Lease: cfg.HostLease}, engine.Options{Workers: 1})
	silos.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: k.Name}) })
	hosts.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Host", Name: k.Name}) })
	pools.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "IPPool", Name: k.Name}) })
	e.Register(&siloset.Controller{Client: c, Sets: sets, Silos: silos, Clock: cfg.Clock}, engine.Options{Workers: 2})
	e.Register(&servicecontroller.Controller{Client: c, Services: services, Silos: silos, Clock: cfg.Clock}, engine.Options{Workers: 2})
	images.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Image", Namespace: k.Namespace, Name: k.Name}) })
	sets.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "SiloSet", Namespace: k.Namespace, Name: k.Name}) })
	services.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Service", Namespace: k.Namespace, Name: k.Name}) })
	cc := &certificate.Controller{Client: c, Store: cd.store, KMS: cd.kms, Clock: cfg.Clock, Defaults: cfg.DefaultIssuers,
		CertControllers: certControllers(cfg, cd),
		Certificates:    certs, Ingresses: ingresses, Classes: classes, Issuers: issuers, Log: cfg.Log, Silos: silos,
		Refused: func(class *v1.IngressClass, ing *v1.Ingress) (string, string) {
			return ingress.Refused(kicdrivers.Builtin(), class, ing)
		}}
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
		so, _ := silos.Get(k.Namespace, k.Name)
		s, _ := so.(*v1.Silo)
		for _, o := range classes.List() {
			cl := o.(*v1.IngressClass)
			if ctl := cl.Spec.Controller; ctl.Runs(s) || (ctl.Namespace == k.Namespace && ctl.Silo == k.Name) {
				ingressesOf(func(ing *v1.Ingress) bool { return ing.Spec.IngressClass == cl.Name })
			}
		}
	})
	if reg := cfg.Plugins; reg != nil {
		e.Register(&provider.Hosts{Client: c, Hosts: hosts, Plugins: reg}, engine.Options{Workers: 1})
		leaseInf := informer.New(c, "Lease") // a plugin's load balancer has no backend for a closed leased port
		leaseInf.AddHandler(func(k informer.Key) {
			if o, ok := leaseInf.Get(k.Namespace, k.Name); ok {
				e.Changed(engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: o.(*v1.Lease).Spec.Silo})
			}
		})
		go leaseInf.Run(ctx)
		e.Register(&provider.LoadBalancers{Client: c, Silos: silos, Hosts: hosts, Leases: leaseInf, Plugins: reg, Clock: cfg.Clock}, engine.Options{Workers: 2})
		e.Register(&provider.ServiceLoadBalancers{Client: c, Services: services, Hosts: hosts, Plugins: reg, Clock: cfg.Clock}, engine.Options{Workers: 1})
		e.Register(&provider.Volumes{Client: c, Silos: silos, Hosts: hosts, Plugins: reg}, engine.Options{Workers: 2})
		e.Register(&provider.IngressDNS{Client: c, Ingresses: ingresses, Classes: classes, Plugins: reg, Cluster: cfg.ClusterName, Clock: cfg.Clock}, engine.Options{Workers: 1})
		classes.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "IngressClass", Name: k.Name}) })
		// A plugin came or went: everything that may use it looks again.
		reg.OnChange = func() {
			for _, o := range hosts.List() {
				e.Changed(engine.Key{Kind: "Host", Name: o.(*v1.Host).Name})
			}
			for _, o := range silos.List() {
				s := o.(*v1.Silo)
				e.Changed(engine.Key{Kind: "Silo", Namespace: s.Namespace, Name: s.Name})
			}
			for _, o := range ingresses.List() {
				ing := o.(*v1.Ingress)
				e.Changed(engine.Key{Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name})
			}
			for _, o := range services.List() {
				svc := o.(*v1.Service)
				e.Changed(engine.Key{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name})
			}
		}
		go reg.Run(ctx)
	}
	for _, inf := range []*informer.Informer{certs, ingresses, classes, issuers} {
		go inf.Run(ctx)
	}
	go silos.Run(ctx)
	go hosts.Run(ctx)
	go pools.Run(ctx)
	go images.Run(ctx)
	go sets.Run(ctx)
	go services.Run(ctx)
	e.Run(ctx)
}

func serveErr(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// heartbeat makes sure this host's Host object exists and keeps its Ready condition fresh.
// With a worker here (contact set), a heartbeat that got through is also the fence's contact:
// written through the store, so a system node cut off from the majority stops getting it.
func heartbeat(ctx context.Context, c *client.Client, cfg Config, rep selfReport, contact *worker.Contact) {
	tick := func() {
		var h v1.Host
		err := c.Get(ctx, "Host", "", cfg.HostName, &h)
		switch {
		case client.IsNotFound(err):
			h = v1.Host{
				TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"},
				ObjectMeta: meta.ObjectMeta{Name: cfg.HostName},
				Spec:       v1.HostSpec{Address: cfg.Address, Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{}}},
			}
			if err = c.Create(ctx, &h); err != nil {
				cfg.Log("register host: %v", err)
				return
			}
		case err != nil:
			cfg.Log("heartbeat: %v", err)
			return
		case h.Spec.Address != cfg.Address: // moved (restored onto a new machine)
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
		reportSelf(&h, rep)
		if err := c.UpdateStatus(ctx, &h); err != nil {
			if ctx.Err() == nil {
				cfg.Log("heartbeat status: %v", err)
			}
			return
		}
		if contact == nil {
			return
		}
		contact.Mark(cfg.Clock.Now())
		hosts, err := c.List(ctx, "Host", "")
		if err != nil {
			return // undecided stays what it was
		}
		var hs []v1.Host
		for _, raw := range hosts.Items {
			if obj, _, err := v1.Decode(raw); err == nil {
				hs = append(hs, *obj.(*v1.Host))
			}
		}
		contact.SetFence(fence.Applies(hs, cfg.HostName))
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

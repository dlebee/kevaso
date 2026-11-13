// Command kevasod is the agent on every host.
//
//	kevasod control-plane --name HOST --address ADDR [--listen 0.0.0.0:6443] [--data /var/lib/kevaso]
//	        [--admin-socket /run/kevaso/admin.sock] [--cluster NAME] [--extra-name NAME]…
//	        [--store sqlite|etcd] [--etcd-peer-listen HOST:PORT]
//	    the control-plane component (installed by `kvoadm init` as a systemd service)
//
//	kevasod worker --name HOST --server https://CP:6443 [--ca-file /etc/kevaso/ca.crt]
//	        [--token-file /etc/kevaso/join-token] [--data /var/lib/kevaso] [--runtime NAME]…
//	    a worker-only host (installed by `kvoadm host add`): joins with the one-time token the first
//	    time, then runs silos and reports to the control plane, dialing out only
//
//	kevasod admin sign-user --name NAME [--admin-socket PATH] < csr.pem
//	    on a control-plane host, as root: sign a user's CSR through the admin socket; prints JSON
//	    {certificate, ca}. kvoadm runs it over SSH, so the user's key never leaves their machine.
//
//	kevasod admin recovery-key
//	    the recovery key for secrets, made once (kvoadm init prints it); refused after that
//
//	kevasod admin kms-rotate [--new-recovery-key]
//	    a new master key: every secret's data key re-wrapped, the old key retired; with
//	    --new-recovery-key also a new recovery key (the old one leaked), printed once
//
//	kevasod dev [--listen 127.0.0.1:8080] [--data PATH]
//	    the API without auth on loopback, for trying kvo locally
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/builtin/kcc/acme"
	kccexec "kevaso.com/core/builtin/kcc/exec"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/backup"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controlplane"
	"kevaso.com/core/internal/guest"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/mesh"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kcc"
	"kevaso.com/core/sdk/kplugin"
)

const defaultAdminSocket = "/run/kevaso/admin.sock"

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  kevasod control-plane --name HOST --address ADDR [--listen 0.0.0.0:6443] [--data /var/lib/kevaso]
                        [--store sqlite|etcd] [--etcd-peer-listen HOST:PORT]
  kevasod worker --name HOST --server https://CP:6443 [--ca-file F] [--token-file F] [--data D]
  kevasod admin sign-user --name NAME < csr.pem
  kevasod admin recovery-key | kms-rotate [--new-recovery-key] | backup
  kevasod admin restore [--data /var/lib/kevaso] < {"backup":…,"recoveryKey":…}
  kevasod dev [--listen 127.0.0.1:8080] [--data PATH]`)
	os.Exit(2)
}

func main() {
	// A container silo's pause container: hold the network namespace, nothing else.
	if filepath.Base(os.Args[0]) == "kevaso-pause" {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		return
	}
	// Copied into a silo as kvo-guest, the same binary is the guest helper.
	if filepath.Base(os.Args[0]) == "kvo-guest" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := guest.Main(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	var err error
	switch os.Args[1] {
	case "control-plane":
		err = runControlPlane(ctx, os.Args[2:])
	case "worker":
		err = runWorker(ctx, os.Args[2:])
	case "admin":
		switch {
		case len(os.Args) >= 3 && os.Args[2] == "sign-user":
			err = runSignUser(ctx, os.Args[3:])
		case len(os.Args) >= 3 && os.Args[2] == "recovery-key":
			err = runAdminCall(ctx, "/admin/kms/recovery-key", nil, &client.RecoveryKey{})
		case len(os.Args) >= 3 && os.Args[2] == "kms-rotate":
			req := client.KMSRotateRequest{}
			for _, a := range os.Args[3:] {
				if a != "--new-recovery-key" {
					usage()
				}
				req.NewRecoveryKey = true
			}
			err = runAdminCall(ctx, "/admin/kms/rotate", req, &client.KMSRotation{})
		case len(os.Args) >= 3 && os.Args[2] == "backup":
			err = runAdminCall(ctx, "/admin/backup", nil, &client.Backup{})
		case len(os.Args) >= 3 && os.Args[2] == "restore":
			err = runRestore(ctx, os.Args[3:])
		default:
			usage()
		}
	case "dev":
		err = runDev(ctx, os.Args[2:])
	default:
		usage()
	}
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kevasod:", err)
		os.Exit(1)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func runControlPlane(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("control-plane", flag.ExitOnError)
	var cfg controlplane.Config
	var extra multi
	fs.StringVar(&cfg.HostName, "name", "", "this host's name")
	fs.StringVar(&cfg.Address, "address", "", "this host's address")
	fs.StringVar(&cfg.Listen, "listen", "0.0.0.0:6443", "TLS API address")
	fs.StringVar(&cfg.DataDir, "data", "/var/lib/kevaso", "data directory (store, CA)")
	fs.StringVar(&cfg.AdminSocket, "admin-socket", defaultAdminSocket, "admin unix socket")
	fs.StringVar(&cfg.ClusterName, "cluster", "kevaso", "cluster name")
	fs.StringVar(&cfg.Store, "store", controlplane.StoreSQLite, "where objects live: sqlite (one control plane) or etcd (embedded member; migrates <data>/store.db once)")
	fs.StringVar(&cfg.Etcd.ClientListen, "etcd-client-listen", "127.0.0.1:2379", "with --store etcd: the member's client address (keep it on loopback)")
	fs.StringVar(&cfg.Etcd.PeerListen, "etcd-peer-listen", "", "with --store etcd: where the member listens for other members (\"\": nowhere, one member)")
	fs.StringVar(&cfg.Etcd.AdvertisePeer, "etcd-advertise-peer", "", "with --store etcd: the host:port other members dial (default --etcd-peer-listen)")
	fs.StringVar(&cfg.DefaultIssuers.Public, "default-issuer-public", "letsencrypt", "the Issuer of Ingresses on public classes that name none")
	fs.StringVar(&cfg.DefaultIssuers.Private, "default-issuer-private", "internal-ca", "the Issuer of Ingresses on private classes that name none")
	fs.Var(&extra, "extra-name", "more names or IPs for the API certificate (repeatable)")
	fs.BoolVar(&cfg.Mesh, "mesh", true, "put this host on the WireGuard mesh")
	var runtimes, labels multi
	withWorker := fs.Bool("worker", false, "also run the worker component on this host")
	fs.Var(&runtimes, "runtime", "runtime to install for the worker (repeatable; default cloud-hypervisor)")
	fs.Var(&labels, "label", "worker label key=value (repeatable)")
	loop := fs.String("loop-storage", "", "development only: back silo disks with this sparse file when the host has no 'kevaso' volume group")
	loopSize := fs.String("loop-size", "64G", "size of the loop storage file")
	egressCA := fs.String("egress-extra-ca", "", "PEM file the egress gate also trusts for upstream hosts (a company TLS proxy)")
	gwScope := fs.String("openshell-gateway-scope", "namespace", "OpenShell gateways: one per host, namespace or silo")
	var certCtrls, dnsProviders multi
	fs.Var(&certCtrls, "cert-controller", "register a program as a cert-controller Issuers can name: NAME=/path/to/program (repeatable)")
	fs.Var(&dnsProviders, "dns-provider", "register a program as a DNS provider for acme dns01 solvers: NAME=/path/to/program (repeatable)")
	certCtrlDir := fs.String("cert-controllers-dir", "/etc/kevaso/cert-controllers", "every program here is a cert-controller, named after its file")
	dnsDir := fs.String("dns-providers-dir", "/etc/kevaso/dns-providers", "every program here is a DNS provider, named after its file")
	fs.DurationVar(&cfg.Approvals.DefaultWait, "approval-wait", 10*time.Minute, "how long a silo's request for a person's yes waits when it asks for no time")
	fs.DurationVar(&cfg.Approvals.MaxWait, "approval-max-wait", time.Hour, "the longest any request for a person's yes may wait")
	fs.DurationVar(&cfg.Approvals.DefaultFor, "approval-access", 15*time.Minute, "how long approved access lasts when the silo asks for no time")
	fs.DurationVar(&cfg.Approvals.MaxFor, "approval-max-access", 12*time.Hour, "the longest approved access a silo may ask for")
	fs.DurationVar(&cfg.Leases.Max, "lease-max", 24*time.Hour, "the longest a port may be open on a lease; a silo's lease.max above it is refused")
	fs.DurationVar(&cfg.Leases.DefaultMax, "lease-default-max", time.Hour, "the longest lease of a silo whose lease sets no max")
	pluginsDir := fs.String("plugins-dir", kplugin.Dir, "provider plugins' sockets: DIR/NAME/plugin.sock (\"\": none)")
	_ = fs.Parse(args)
	cfg.ExtraNames = extra
	for _, d := range []struct {
		dir  string
		into *multi
	}{{*certCtrlDir, &certCtrls}, {*dnsDir, &dnsProviders}} {
		found, err := kccexec.Discover(d.dir)
		if err != nil {
			return err
		}
		for n, p := range found {
			*d.into = append(*d.into, n+"="+p)
		}
	}
	for _, r := range certCtrls {
		n, p, err := kccexec.ParseRegistration(r)
		if err != nil {
			return fmt.Errorf("--cert-controller %w", err)
		}
		if cfg.CertControllers == nil {
			cfg.CertControllers = kcc.Registry{}
		}
		cfg.CertControllers[n] = &kccexec.CertController{Name: n, Program: p}
	}
	for _, r := range dnsProviders {
		n, p, err := kccexec.ParseRegistration(r)
		if err != nil {
			return fmt.Errorf("--dns-provider %w", err)
		}
		if cfg.DNSProviders == nil {
			cfg.DNSProviders = map[string]acme.DNSProvider{}
		}
		cfg.DNSProviders[n] = &kccexec.DNSProvider{Program: p}
	}
	if *withWorker {
		if len(runtimes) == 0 {
			runtimes = multi{"cloud-hypervisor"}
		}
		lbl := map[string]string{}
		for _, kv := range labels {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("--label %q: want key=value", kv)
			}
			lbl[k] = v
		}
		cfg.Worker = &worker.Config{Runtimes: runtimes, Labels: lbl, EgressExtraCA: *egressCA, GatewayScope: *gwScope,
			Storage: cloudhypervisor.StorageOptions{LoopFile: *loop, LoopSize: *loopSize}}
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	cfg.Log = logger.Printf
	if *pluginsDir != "" {
		cfg.Plugins = &plugins.Registry{Dir: *pluginsDir, Log: logger.Printf}
	}
	r, err := controlplane.Start(ctx, cfg)
	if err != nil {
		return err
	}
	return r.Wait()
}

func runWorker(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("worker", flag.ExitOnError)
	var jc worker.JoinConfig
	fs.StringVar(&jc.HostName, "name", "", "this host's name (as kvoadm host add registered it)")
	fs.StringVar(&jc.Server, "server", "", "the control plane's API URL")
	fs.StringVar(&jc.CAFile, "ca-file", "/etc/kevaso/ca.crt", "the cluster CA")
	fs.StringVar(&jc.TokenFile, "token-file", "/etc/kevaso/join-token", "the one-time join token")
	fs.StringVar(&jc.DataDir, "data", "/var/lib/kevaso", "data directory")
	var runtimes multi
	fs.Var(&runtimes, "runtime", "runtime to install (repeatable; default cloud-hypervisor)")
	loop := fs.String("loop-storage", "", "development only: back silo disks with this sparse file")
	loopSize := fs.String("loop-size", "64G", "size of the loop storage file")
	every := fs.Duration("heartbeat", 10*time.Second, "how often to report")
	withMesh := fs.Bool("mesh", true, "put this host on the WireGuard mesh")
	egressCA := fs.String("egress-extra-ca", "", "PEM file the egress gate also trusts for upstream hosts (a company TLS proxy)")
	gwScope := fs.String("openshell-gateway-scope", "namespace", "OpenShell gateways: one per host, namespace or silo")
	_ = fs.Parse(args)
	if jc.HostName == "" || jc.Server == "" {
		return errors.New("worker needs --name and --server")
	}
	switch {
	case len(runtimes) == 0:
		runtimes = multi{"cloud-hypervisor"}
	case len(runtimes) == 1 && runtimes[0] == "none":
		runtimes = nil
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	var c *client.Client
	for { // the control plane may not be reachable yet: keep trying
		var err error
		if c, err = worker.Join(ctx, jc); err == nil {
			break
		}
		logger.Printf("join: %v (retrying)", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	logger.Printf("joined %s as host %s", jc.Server, jc.HostName)
	contact := &worker.Contact{}
	wc := worker.Config{HostName: jc.HostName, Runtimes: runtimes, DataDir: jc.DataDir, Clock: clock.Real{}, Log: logger.Printf,
		Storage: cloudhypervisor.StorageOptions{LoopFile: *loop, LoopSize: *loopSize}, Contact: contact, MeshSubnet: *withMesh, EgressExtraCA: *egressCA, GatewayScope: *gwScope}
	rts, err := worker.NewRuntimes(wc)
	if err != nil {
		return err
	}
	go worker.Heartbeat(ctx, c, jc.HostName, *every, clock.Real{}, logger.Printf, contact)
	if *withMesh {
		m := &mesh.Agent{Client: c, HostName: jc.HostName, Dir: filepath.Join(jc.DataDir, "mesh"), Log: logger.Printf}
		go func() {
			if err := m.Run(ctx); err != nil {
				logger.Printf("mesh: %v", err)
			}
		}()
	}
	worker.Run(ctx, c, wc, rts)
	return nil
}

func runSignUser(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sign-user", flag.ExitOnError)
	name := fs.String("name", "", "the user's name")
	sock := fs.String("admin-socket", defaultAdminSocket, "admin unix socket")
	wait := fs.Duration("wait", 2*time.Minute, "how long to wait for the control plane to come up")
	_ = fs.Parse(args)
	csr, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	if err != nil {
		return err
	}
	c := client.NewUnix(*sock)
	deadline := time.Now().Add(*wait)
	for {
		cert, ca, err := c.SignUserCSR(ctx, *name, csr)
		if err == nil {
			return json.NewEncoder(os.Stdout).Encode(map[string]string{"certificate": string(cert), "ca": string(ca)})
		}
		var apiErr *client.Error
		if errors.As(err, &apiErr) || time.Now().After(deadline) {
			return err // the server answered (a real refusal), or it never came up
		}
		select { // the service is still starting: the socket isn't there yet
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// runRestore puts a backup into a fresh data directory (before the control plane first starts
// there): {"backup", "recoveryKey"} as JSON on stdin, never on the command line.
func runRestore(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	data := fs.String("data", "/var/lib/kevaso", "data directory")
	_ = fs.Parse(args)
	var req client.RestoreRequest
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 2<<30)).Decode(&req); err != nil {
		return fmt.Errorf("restore: reading the request on stdin: %w", err)
	}
	rk, err := kms.ParseRecoveryKey(req.RecoveryKey)
	if err != nil {
		return err
	}
	m, err := backup.Restore(ctx, req.Backup, rk, *data)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(client.Restored{Cluster: m.Cluster, Host: m.Host, Created: m.Created.Format(time.RFC3339)})
}

// runAdminCall POSTs to the admin socket (as root on a control-plane host) and prints the JSON
// answer: the recovery key (once), or a master key rotation.
func runAdminCall(ctx context.Context, path string, in, out any) error {
	c := client.NewUnix(defaultAdminSocket)
	if err := c.Call(ctx, http.MethodPost, path, in, out); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func runDev(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dev", flag.ExitOnError)
	home, _ := os.UserHomeDir()
	listen := fs.String("listen", "127.0.0.1:8080", "address to serve the API on (loopback only: no auth)")
	data := fs.String("data", filepath.Join(home, ".kevaso", "dev.db"), "SQLite file")
	_ = fs.Parse(args)
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("dev mode has no authentication: listen on loopback only, not %s", *listen)
	}
	if err := os.MkdirAll(filepath.Dir(*data), 0o700); err != nil {
		return err
	}
	st, err := store.OpenSQLite(*data, 0)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		return err
	}
	localKMS, err := kms.OpenLocal(strings.TrimSuffix(*data, filepath.Ext(*data)) + "-kms.json")
	if err != nil {
		return err
	}
	srv.SetVault(&secrets.Vault{Store: st, KMS: localKMS, Now: time.Now})
	hs := &http.Server{Addr: *listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	fmt.Printf("kevasod dev: API on http://%s, data in %s (Ctrl-C to stop)\n", *listen, *data)
	if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

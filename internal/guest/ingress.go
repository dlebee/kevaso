package guest

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"kevaso.com/core/api/client"
)

// The ingress controller (design §7.3): an ordinary silo running `kvo-guest ingress`. Its routes,
// certificates and ACME answers come from the broker, over the silo's own channel, so only a silo
// that is an ingress class's controller gets them. It reaches backends by their private names.

// IngressRoutes is a compiled config: routes by host (longest path first), certificates by host.
type IngressRoutes struct {
	routes     map[string][]client.IngressRoute
	certs      map[string]*tls.Certificate
	challenges map[string]string
}

// CompileIngress turns the broker's config into lookups. Pure.
func CompileIngress(cfg *client.IngressConfig) *IngressRoutes {
	r := &IngressRoutes{routes: map[string][]client.IngressRoute{}, certs: map[string]*tls.Certificate{}, challenges: map[string]string{}}
	if cfg == nil {
		return r
	}
	for _, rt := range cfg.Routes {
		h := strings.ToLower(rt.Host)
		r.routes[h] = append(r.routes[h], rt)
	}
	for h, rs := range r.routes { // longest prefix first
		for i := 1; i < len(rs); i++ {
			for j := i; j > 0 && len(rs[j].Path) > len(rs[j-1].Path); j-- {
				rs[j], rs[j-1] = rs[j-1], rs[j]
			}
		}
		r.routes[h] = rs
	}
	for _, c := range cfg.Certs {
		pair, err := tls.X509KeyPair(c.Bundle, c.Bundle)
		if err != nil {
			continue
		}
		for _, h := range c.Hosts {
			r.certs[strings.ToLower(h)] = &pair
		}
	}
	for t, k := range cfg.Challenges {
		r.challenges[t] = k
	}
	return r
}

// Route finds the route for a request's host and path.
func (r *IngressRoutes) Route(host, path string) (client.IngressRoute, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, rt := range r.routes[strings.ToLower(strings.TrimSuffix(host, "."))] {
		if strings.HasPrefix(path, rt.Path) {
			return rt, true
		}
	}
	return client.IngressRoute{}, false
}

// Ingress serves HTTP on :80 and HTTPS on :443 with the config it keeps fetching.
type Ingress struct {
	Dial      Dialer
	HTTPAddr  string // default :80
	HTTPSAddr string // default :443
	Every     time.Duration
	Log       func(string, ...any)
	cur       atomic.Pointer[IngressRoutes]
}

func (in *Ingress) log(f string, a ...any) {
	if in.Log != nil {
		in.Log(f, a...)
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "kvo-guest ingress: "+f+"\n", a...)
	}
}

// Refresh fetches the config once.
func (in *Ingress) Refresh(ctx context.Context) error {
	resp, err := Call(ctx, in.Dial, client.BrokerRequest{Op: client.OpIngress})
	if err != nil {
		return err
	}
	in.cur.Store(CompileIngress(resp.Ingress))
	return nil
}

// Handler is the HTTP handler; tls says whether the request came in over HTTPS.
func (in *Ingress) Handler(tlsSide bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := in.cur.Load()
		if cfg == nil {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		if token, ok := strings.CutPrefix(r.URL.Path, "/.well-known/acme-challenge/"); ok && !tlsSide {
			if ka, ok := cfg.challenges[token]; ok {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(ka))
				return
			}
			http.NotFound(w, r)
			return
		}
		rt, ok := cfg.Route(r.Host, r.URL.Path)
		if !ok {
			http.Error(w, "no route for this host", http.StatusNotFound)
			return
		}
		if rt.TLS && !tlsSide {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}
		target := &url.URL{Scheme: "http", Host: rt.Backend}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(p *httputil.ProxyRequest) {
				p.SetURL(target)
				p.Out.Host = p.In.Host
				p.SetXForwarded()
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				in.log("%s → %s: %v", rt.Ingress, rt.Backend, err)
				http.Error(w, "the backend isn't answering", http.StatusBadGateway)
			},
		}
		proxy.ServeHTTP(w, r)
	})
}

// Run serves until ctx ends, refreshing the config every few seconds.
func (in *Ingress) Run(ctx context.Context) error {
	every := in.Every
	if every <= 0 {
		every = 3 * time.Second
	}
	for in.cur.Load() == nil {
		if err := in.Refresh(ctx); err != nil {
			in.log("config: %v (retrying)", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(every):
			}
		}
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := in.Refresh(ctx); err != nil {
					in.log("config: %v (keeping the last one)", err)
				}
			}
		}
	}()
	httpAddr, httpsAddr := in.HTTPAddr, in.HTTPSAddr
	if httpAddr == "" {
		httpAddr = ":80"
	}
	if httpsAddr == "" {
		httpsAddr = ":443"
	}
	plain := &http.Server{Addr: httpAddr, Handler: in.Handler(false), ReadHeaderTimeout: 30 * time.Second}
	secure := &http.Server{Addr: httpsAddr, Handler: in.Handler(true), ReadHeaderTimeout: 30 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := in.cur.Load().certs[strings.ToLower(h.ServerName)]; c != nil {
				return c, nil
			}
			return nil, errors.New("no certificate for " + h.ServerName)
		}}}
	errs := make(chan error, 2)
	go func() { errs <- plain.ListenAndServe() }()
	go func() { errs <- secure.ListenAndServeTLS("", "") }()
	in.log("serving on %s and %s", httpAddr, httpsAddr)
	select {
	case <-ctx.Done():
		_ = plain.Close()
		_ = secure.Close()
		return ctx.Err()
	case err := <-errs:
		return err
	}
}

const ingressUnit = `[Unit]
Description=Kevaso ingress controller
After=network-online.target kvo-guest.service

[Service]
ExecStart=/usr/local/bin/kvo-guest ingress
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`

// InstallIngress makes `kvo-guest ingress` a service of the (VM) silo, started now and at every boot.
func InstallIngress() error {
	if err := os.WriteFile("/etc/systemd/system/kevaso-ingress.service", []byte(ingressUnit), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "kevaso-ingress.service"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

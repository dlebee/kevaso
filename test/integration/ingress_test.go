package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kic/nginx"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controllers/certificate"
	"kevaso.com/core/internal/ingress/ingresstest"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// selfSigned is a certificate and key for host (PEM, chain then key, as a TLS Secret holds them).
func selfSigned(t *testing.T, host string, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})...)
}

// The ingress path (design §7.3): publishing on a public class is its own permission, and a stock
// proxy is driven from outside. The agent of the controller silo's host gets the class's desired
// state, renders it with the nginx driver and applies it through the runtime's exec: written,
// checked, reloaded once; nothing touched while nothing changes; a broken annotation refused
// without touching the running config; a renewal writes only the new certificate (and the lines
// naming it) and reloads; deleting the Ingress removes its route and its key.
func TestIngress(t *testing.T) {
	c := newCluster(t)
	for _, n := range []string{"kevaso-system", "payments"} {
		_ = c.admin.Create(c.ctx, ns(n))
	}
	if err := c.admin.Create(c.ctx, &v1.IngressClass{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IngressClass"},
		ObjectMeta: meta.ObjectMeta{Name: "public"}, Spec: v1.IngressClassSpec{Public: true,
			Controller: v1.IngressController{Driver: "nginx", Silo: "ingress-public", Namespace: "kevaso-system"}}}); err != nil {
		t.Fatal(err)
	}
	ing := func(name string) *v1.Ingress {
		return &v1.Ingress{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Ingress"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "payments"},
			Spec: v1.IngressSpec{IngressClass: "public", Hosts: []string{"api.example.com"}, Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "api", Port: "http"}}}}}
	}
	// Who may publish on a public class.
	_ = c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "ed", Namespace: "payments"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"}, Subjects: []v1.Subject{{Kind: "User", Name: "ed"}}})
	_ = c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "ada", Namespace: "payments"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"}, Subjects: []v1.Subject{{Kind: "User", Name: "ada"}}})
	if err := c.as(t, "ed").Create(c.ctx, ing("by-ed")); status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "publish-public") {
		t.Fatalf("editor publishing on a public class: %v", err)
	}
	bad := ing("bad")
	bad.Spec.IngressClass = "nope"
	if err := c.admin.Create(c.ctx, bad); status(err) != http.StatusUnprocessableEntity {
		t.Fatalf("a class that doesn't exist: %v", err)
	}

	// The certificate as the certificate controller would leave it (it has its own tests).
	cert1 := selfSigned(t, "api.example.com", 1)
	if err := c.admin.Create(c.ctx, &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: "api-tls", Namespace: "payments"}, Spec: v1.SecretSpec{Value: cert1}}); err != nil {
		t.Fatal(err)
	}

	// hv1 runs both silos; its agent has only a worker's credentials.
	proxy := ingresstest.New()
	rt := fake.New()
	rt.Handler = func(id kri.ID, cmd []string, stdin []byte) (string, int) {
		if id.Name == "ingress-public" {
			return proxy.Handle(cmd, stdin)
		}
		return "", 0
	}
	var logMu sync.Mutex
	var logs bytes.Buffer
	a := &agent.Agent{Client: c.host(t, "hv1"), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
		IngressEvery: 50 * time.Millisecond, Log: func(f string, args ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			fmt.Fprintf(&logs, f+"\n", args...)
		}}
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	go a.Run(ctx)
	place := func(name, ns string, ports []v1.SiloPort, svc *v1.SiloService) {
		t.Helper()
		s := containerSilo(name, ns, "docker")
		s.Spec.Ports = ports
		s.Spec.Service = svc
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host = "hv1"
		if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	place("ingress-public", "kevaso-system", []v1.SiloPort{{Name: "http", Port: 80}, {Name: "https", Port: 443}},
		&v1.SiloService{Ports: []v1.ServicePort{{Port: "http"}, {Port: "https"}}})
	place("api", "payments", []v1.SiloPort{{Name: "http", Port: 8080}}, &v1.SiloService{Ports: []v1.ServicePort{{Port: "http"}}})
	if err := c.as(t, "ada").Create(c.ctx, ing("api")); err != nil {
		t.Fatalf("admin publishing: %v", err)
	}

	wait := func(what string, ok func(files map[string][]byte, writes []string, reloads int) bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			files, writes, reloads := proxy.Snapshot()
			if ok(files, writes, reloads) {
				return
			}
			if time.Now().After(deadline) {
				logMu.Lock()
				t.Fatalf("%s: reloads %d, writes %v\nconfig:\n%s\nagent:\n%s", what, reloads, writes, files[nginx.ConfigPath], logs.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	certFiles := func(files map[string][]byte) []string {
		var out []string
		for f := range files {
			if strings.HasPrefix(f, nginx.CertDir+"/") {
				out = append(out, f)
			}
		}
		return out
	}

	// An Ingress appears: its nginx config is written, checked and reloaded, once.
	wait("first apply", func(files map[string][]byte, _ []string, reloads int) bool {
		cfg := string(files[nginx.ConfigPath])
		return reloads == 1 && strings.Contains(cfg, "server_name api.example.com;") && strings.Contains(cfg, "proxy_pass http://10.64.0.4:8080;") &&
			len(certFiles(files)) == 1
	})
	files, writes, _ := proxy.Snapshot()
	firstCert := certFiles(files)[0]
	k := bytes.Index(cert1, []byte("-----BEGIN EC"))
	if want := string(cert1[:k]) + "\n" + string(cert1[k:]); string(files[firstCert]) != want {
		t.Fatalf("the certificate file isn't the chain and key:\n%s", files[firstCert])
	}
	if _, ok := files[nginx.ConfigPath+".next"]; ok {
		t.Fatal("the staged config was left behind")
	}
	var check, reload int
	ran := proxy.Commands()
	for i, r := range ran {
		if strings.HasPrefix(r, "nginx -t") {
			check = i
		}
		if r == "nginx -s reload" {
			reload = i
		}
	}
	if check == 0 || reload < check || !strings.Contains(ran[check], nginx.ConfigPath+".next") {
		t.Fatalf("checked the staged config before reloading? %v", ran)
	}
	waitClass := func(what string, ok func(*v1.IngressClass) bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var cl v1.IngressClass
			if err := c.admin.Get(c.ctx, "IngressClass", "", "public", &cl); err == nil && ok(&cl) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("class status %s: %+v", what, cl.Status)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitClass("applied", func(cl *v1.IngressClass) bool {
		cd := meta.FindCondition(cl.Status.Conditions, "Applied")
		return cd != nil && cd.Status == meta.ConditionTrue && len(cl.Status.Controllers) == 1 && cl.Status.Controllers[0].Host == "hv1" && cl.Status.Controllers[0].Applied != ""
	})

	// Nothing changes: nothing is touched.
	time.Sleep(300 * time.Millisecond)
	if _, w, r := proxy.Snapshot(); r != 1 || len(w) != len(writes) {
		t.Fatalf("unchanged, yet touched: reloads %d, writes %v", r, w)
	}

	// A broken annotation: refused, the running config untouched, and said on the class.
	var cur v1.Ingress
	if err := c.admin.Get(c.ctx, "Ingress", "payments", "api", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Annotations = map[string]string{"nginx/proxy-body-size": "a lot; include /etc/passwd", "caddy/whatever": "ignored by nginx"}
	if err := c.admin.Update(c.ctx, &cur); err != nil {
		t.Fatal(err)
	}
	waitClass("refused", func(cl *v1.IngressClass) bool {
		cd := meta.FindCondition(cl.Status.Conditions, "Applied")
		return cd != nil && cd.Status == meta.ConditionFalse && cd.Reason == "Rejected" && len(cl.Status.Controllers) == 1 &&
			strings.Contains(cl.Status.Controllers[0].Rejected, "proxy-body-size") && len(cl.Status.Controllers[0].Blamed) == 1 && cl.Status.Controllers[0].Blamed[0] == "payments/api"
	})
	if _, w, r := proxy.Snapshot(); r != 1 || len(w) != len(writes) {
		t.Fatalf("a refused annotation touched the proxy: reloads %d, writes %v", r, w)
	}
	// Held, an ACME challenge still gets served (one refused Ingress mustn't stop every
	// certificate in the class): the last good config plus the challenge, and the class still
	// says why it's held. Found on the metal machine: Let's Encrypt's HTTP-01 got a 404.
	chal := certificate.HTTP01Solver{Store: c.store, Now: time.Now}
	token := "tok-held-0123456789abcdefABCDEF_-"
	if err := chal.Present(c.ctx, "other.example.com", token, token+".thumb"); err != nil {
		t.Fatal(err)
	}
	wait("a challenge served while held", func(files map[string][]byte, _ []string, reloads int) bool {
		return reloads == 2 && strings.Contains(string(files[nginx.ConfigPath]), token)
	})
	waitClass("still refused", func(cl *v1.IngressClass) bool {
		cd := meta.FindCondition(cl.Status.Conditions, "Applied")
		return cd != nil && cd.Status == meta.ConditionFalse && len(cl.Status.Controllers) == 1 && len(cl.Status.Controllers[0].Blamed) == 1
	})
	if err := chal.CleanUp(c.ctx, token); err != nil {
		t.Fatal(err)
	}
	wait("the challenge gone, held", func(files map[string][]byte, _ []string, reloads int) bool {
		return reloads == 3 && !strings.Contains(string(files[nginx.ConfigPath]), token)
	})
	_, writes, _ = proxy.Snapshot()

	// Fixed (the annotation dropped): the same config as before, so still nothing to do.
	if err := c.admin.Get(c.ctx, "Ingress", "payments", "api", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Annotations = nil
	if err := c.admin.Update(c.ctx, &cur); err != nil {
		t.Fatal(err)
	}
	waitClass("fixed", func(cl *v1.IngressClass) bool {
		cd := meta.FindCondition(cl.Status.Conditions, "Applied")
		return cd != nil && cd.Status == meta.ConditionTrue
	})
	if _, w, r := proxy.Snapshot(); r != 3 || len(w) != len(writes) {
		t.Fatalf("back to the running config, yet touched: reloads %d, writes %v", r, w)
	}

	// A renewal: the new certificate is written, the config's lines naming it change, one reload,
	// and the old key is gone.
	cfgBefore := string(files[nginx.ConfigPath])
	var sec v1.Secret
	if err := c.admin.Get(c.ctx, "Secret", "payments", "api-tls", &sec); err != nil {
		t.Fatal(err)
	}
	cert2 := selfSigned(t, "api.example.com", 2)
	sec.Spec.Value = cert2
	if err := c.admin.Update(c.ctx, &sec); err != nil {
		t.Fatal(err)
	}
	wait("renewal", func(files map[string][]byte, _ []string, reloads int) bool {
		cs := certFiles(files)
		return reloads == 4 && len(cs) == 1 && cs[0] != firstCert
	})
	files, w2, _ := proxy.Snapshot()
	newCert := certFiles(files)[0]
	if got := w2[len(writes):]; len(got) != 2 || got[0] != newCert || got[1] != nginx.ConfigPath+".next" {
		t.Fatalf("a renewal wrote %v", got)
	}
	if want := strings.ReplaceAll(cfgBefore, firstCert, newCert); string(files[nginx.ConfigPath]) != want {
		t.Fatalf("a renewal changed more than the certificate's lines:\n%s", files[nginx.ConfigPath])
	}

	// The Ingress goes: its route and its key go.
	if err := c.admin.Delete(c.ctx, "Ingress", "payments", "api"); err != nil {
		t.Fatal(err)
	}
	wait("deleted", func(files map[string][]byte, _ []string, reloads int) bool {
		return reloads == 5 && !strings.Contains(string(files[nginx.ConfigPath]), "api.example.com") && len(certFiles(files)) == 0
	})

	// Keys never reach a log.
	logMu.Lock()
	defer logMu.Unlock()
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Fatalf("a key in the agent's log:\n%s", logs.String())
	}
}

// Package certificate is the certificate controller (design §7.3): cert-manager style, built into
// the control plane. An Ingress with TLS gets a Certificate for its hosts; a Certificate gets a
// certificate from its Issuer (ACME with HTTP-01, or the cluster's own CA) into a Secret, and a new
// one before it expires.
//
// HTTP-01 challenges are answered by the ingress controller silos: the controller keeps the
// pending tokens in the store, and they go into each class's desired state with its routes, which
// the class's driver renders into the stock proxy's config (internal/ingress, design §7.3).
package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kcc/acme"
	"kevaso.com/core/builtin/kcc/internalca"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kcc"
)

// Internal store kinds.
const (
	KindChallenge = "ACMEChallenge"       // a pending HTTP-01 token → its key authorization
	KindState     = "CertControllerState" // a cert-controller's per-issuer state, sealed
)

// Labels on what the controller makes.
const (
	LabelIngress     = "kevaso.com/ingress"     // on a Certificate made for an Ingress
	LabelCertificate = "kevaso.com/certificate" // on the Secret a Certificate fills
)

// Built-in issuers, made at start if missing.
const (
	IssuerLetsEncrypt = "letsencrypt"
	IssuerInternal    = "internal-ca"
)

// Challenge is a pending HTTP-01 answer.
type Challenge struct {
	Token   string    `json:"token"`
	KeyAuth string    `json:"keyAuth"`
	Host    string    `json:"host"`
	Expires time.Time `json:"expires"`
}

// Controller reconciles Ingresses into Certificates and Certificates into Secrets.
type Controller struct {
	Client       *client.Client
	Store        store.Store // challenges and ACME account keys
	KMS          kms.KMS
	Clock        clock.Clock
	Certificates *informer.Informer
	Ingresses    *informer.Informer
	Classes      *informer.Informer
	Issuers      *informer.Informer
	Log          func(string, ...any)
	// CertControllers are the cert-controllers Issuers may name (built in: acme, internal-ca).
	CertControllers kcc.Registry
	// Defaults are the issuers of Ingresses that name none.
	Defaults Defaults
	// Silos, if set, find a SiloSet controller's silos (their public address shows on Ingresses).
	Silos *informer.Informer
	// Refused, if set, says why an Ingress isn't served as it is ("" if it is): its class's driver
	// refuses it, or the proxy refused a configuration and blames it (design §7.3).
	Refused func(class *v1.IngressClass, ing *v1.Ingress) (reason, msg string)
}

func (c *Controller) log(f string, a ...any) {
	if c.Log != nil {
		c.Log(f, a...)
	}
}

// Name implements engine.Controller.
func (c *Controller) Name() string { return "certificate" }

// Kind implements engine.Controller (Ingress keys come in too, with Kind "Ingress").
func (c *Controller) Kind() string { return "Certificate" }

// Ingresses is the controller's other half: Ingress → Certificate and the Ingress's status. The
// engine routes keys by kind, so it's registered as a controller of its own.
func (c *Controller) IngressController() engine.Controller { return ingressController{c} }

type ingressController struct{ c *Controller }

func (i ingressController) Name() string { return "ingress-certificate" }
func (i ingressController) Kind() string { return "Ingress" }
func (i ingressController) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	return engine.Result{}, i.c.reconcileIngress(ctx, k)
}

// EnsureIssuers makes the built-in issuers if they're missing.
func EnsureIssuers(ctx context.Context, cl *client.Client) error {
	for _, is := range []*v1.Issuer{
		{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Issuer"}, ObjectMeta: meta.ObjectMeta{Name: IssuerLetsEncrypt},
			Spec: v1.IssuerSpec{ACME: &v1.ACMEIssuer{Server: v1.LetsEncrypt}}},
		{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Issuer"}, ObjectMeta: meta.ObjectMeta{Name: IssuerInternal},
			Spec: v1.IssuerSpec{InternalCA: true}},
	} {
		if err := cl.Create(ctx, is); err != nil && !client.IsAlreadyExists(err) {
			return err
		}
	}
	return nil
}

// Reconcile implements engine.Controller.
func (c *Controller) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	o, ok := c.Certificates.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	return c.reconcileCertificate(ctx, o.(*v1.Certificate))
}

// ── Ingress → Certificate ────────────────────────────────────────────────────

// Defaults are the cluster's issuers for Ingresses that name none (the control plane's config).
type Defaults struct {
	Public  string // default letsencrypt
	Private string // default internal-ca
}

// IssuerFor is the Issuer an Ingress's certificate comes from ("" if Kevaso makes none for it:
// tls.none, or its own secretName). Pure.
func IssuerFor(ing *v1.Ingress, class *v1.IngressClass, d Defaults) string {
	switch t := ing.Spec.TLS; {
	case t.None || t.SecretName != "":
		return ""
	case t.Issuer != "":
		return t.Issuer
	case class != nil && class.Spec.Public:
		if d.Public != "" {
			return d.Public
		}
		return IssuerLetsEncrypt
	}
	if d.Private != "" {
		return d.Private
	}
	return IssuerInternal
}

// DesiredCertificate is the Certificate an Ingress needs (nil: none). Pure.
func DesiredCertificate(ing *v1.Ingress, class *v1.IngressClass, d Defaults) *v1.Certificate {
	issuer := IssuerFor(ing, class, d)
	if issuer == "" {
		return nil
	}
	hosts := append([]string(nil), ing.Spec.Hosts...)
	slices.Sort(hosts)
	name := v1.CertificateFor(ing)
	return &v1.Certificate{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Certificate"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ing.Namespace, Labels: map[string]string{LabelIngress: ing.Name}},
		Spec:       v1.CertificateSpec{Hosts: hosts, Issuer: issuer, SecretName: name},
	}
}

func (c *Controller) reconcileIngress(ctx context.Context, k engine.Key) error {
	o, ok := c.Ingresses.Get(k.Namespace, k.Name)
	if !ok {
		// Gone: remove the Certificate made for it (and its Secret).
		for _, co := range c.Certificates.List() {
			cert := co.(*v1.Certificate)
			if cert.Namespace == k.Namespace && cert.Labels[LabelIngress] == k.Name {
				if err := c.Client.Delete(ctx, "Certificate", cert.Namespace, cert.Name); err != nil && !client.IsNotFound(err) {
					return err
				}
				if err := c.Client.Delete(ctx, "Secret", cert.Namespace, cert.Spec.SecretName); err != nil && !client.IsNotFound(err) {
					return err
				}
			}
		}
		return nil
	}
	ing := o.(*v1.Ingress)
	var class *v1.IngressClass
	if co, ok := c.Classes.Get("", ing.Spec.IngressClass); ok {
		class = co.(*v1.IngressClass)
	}
	want := DesiredCertificate(ing, class, c.Defaults)
	if want != nil {
		var cur v1.Certificate
		err := c.Client.Get(ctx, "Certificate", want.Namespace, want.Name, &cur)
		switch {
		case client.IsNotFound(err):
			if err := c.Client.Create(ctx, want); err != nil && !client.IsAlreadyExists(err) {
				return err
			}
		case err != nil:
			return err
		case !slices.Equal(cur.Spec.Hosts, want.Spec.Hosts) || cur.Spec.Issuer != want.Spec.Issuer:
			cur.Spec = want.Spec
			if err := c.Client.Update(ctx, &cur); err != nil {
				return err
			}
		}
	}
	// Status: where to point the hosts, and whether the certificate is there.
	for attempt := 0; attempt < 3; attempt++ {
		var cur v1.Ingress
		if err := c.Client.Get(ctx, "Ingress", ing.Namespace, ing.Name, &cur); err != nil {
			return err
		}
		before := statusKey(cur.Status)
		cur.Status.Address = c.controllerAddress(ctx, class)
		ready, reason, msg := true, "Ready", "routes served by the class's controller"
		if class == nil {
			ready, reason, msg = false, "NoClass", "ingress class "+ing.Spec.IngressClass+" doesn't exist"
		} else if c.Refused != nil {
			if why, m := c.Refused(class, ing); why != "" {
				ready, reason, msg = false, why, m
			}
		}
		if want != nil {
			cur.Status.Certificate = want.Name
			var cert v1.Certificate
			if err := c.Client.Get(ctx, "Certificate", want.Namespace, want.Name, &cert); err == nil {
				if cd := meta.FindCondition(cert.Status.Conditions, "Ready"); cd == nil || cd.Status != meta.ConditionTrue {
					ready, reason, msg = false, "CertificatePending", "waiting for certificate "+want.Name
					if cd != nil && cd.Message != "" {
						msg += ": " + cd.Message
					}
				}
			}
		}
		st := meta.ConditionFalse
		if ready {
			st = meta.ConditionTrue
		}
		meta.SetCondition(&cur.Status.Conditions, meta.Condition{Type: "Ready", Status: st, Reason: reason, Message: msg, ObservedGeneration: cur.Generation}, c.now())
		if statusKey(cur.Status) == before {
			return nil
		}
		err := c.Client.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return err
	}
	return nil
}

func (c *Controller) controllerAddress(ctx context.Context, class *v1.IngressClass) string {
	if class == nil {
		return ""
	}
	ctl := class.Spec.Controller
	if c.Silos != nil {
		var addrs []string
		for _, o := range c.Silos.List() {
			if s := o.(*v1.Silo); ctl.Runs(s) && s.Status.Service.Front() != "" {
				addrs = append(addrs, s.Status.Service.Front())
			}
		}
		slices.Sort(addrs)
		if len(addrs) > 0 {
			return addrs[0]
		}
		return ""
	}
	if ctl.Silo == "" {
		return ""
	}
	var s v1.Silo
	if err := c.Client.Get(ctx, "Silo", ctl.Namespace, ctl.Silo, &s); err != nil {
		return ""
	}
	return s.Status.Service.Front()
}

func (c *Controller) now() time.Time { return c.Clock.Now().UTC().Truncate(time.Second) }

// ── Certificate → Secret ─────────────────────────────────────────────────────

// RenewAfter is when to get the next certificate: at two thirds of its lifetime (Let's Encrypt's
// 90 days → after 60). Pure.
func RenewAfter(notBefore, notAfter time.Time) time.Time {
	return notBefore.Add(notAfter.Sub(notBefore) * 2 / 3)
}

// needsIssue reports whether the certificate must be (re)issued now, and if not, when to look again.
func (c *Controller) needsIssue(ctx context.Context, cert *v1.Certificate) (bool, time.Duration) {
	st := cert.Status
	ready := meta.FindCondition(st.Conditions, "Ready")
	if ready != nil && ready.Status != meta.ConditionTrue && ready.ObservedGeneration == cert.Generation && st.NextAttempt != nil {
		if wait := st.NextAttempt.Sub(c.Clock.Now()); wait > 0 && !c.fixed(cert, ready.Reason) {
			return false, wait // backing off after a failure
		}
	}
	if ready == nil || ready.Status != meta.ConditionTrue || st.RenewAfter == nil || ready.ObservedGeneration != cert.Generation {
		return true, 0
	}
	var sec v1.Secret
	if err := c.Client.Get(ctx, "Secret", cert.Namespace, cert.Spec.SecretName, &sec); err != nil || sec.Status.Version == 0 {
		return true, 0
	}
	if wait := st.RenewAfter.Sub(c.Clock.Now()); wait > 0 {
		return false, wait
	}
	return true, 0
}

func (c *Controller) reconcileCertificate(ctx context.Context, cert *v1.Certificate) (engine.Result, error) {
	issue, wait := c.needsIssue(ctx, cert)
	if !issue {
		return engine.Result{RequeueAfter: min(wait, 12*time.Hour)}, nil
	}
	var is v1.Issuer
	if err := c.Client.Get(ctx, "Issuer", "", cert.Spec.Issuer, &is); err != nil {
		return engine.Result{}, c.fail(ctx, cert, "NoIssuer", fmt.Sprintf("issuer %s: %v", cert.Spec.Issuer, err))
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return engine.Result{}, err
	}
	name, config := is.CertController()
	cc, err := c.CertControllers.Get(name)
	if err != nil {
		return engine.Result{}, c.fail(ctx, cert, "NoCertController", fmt.Sprintf("issuer %s: %v", is.Name, err))
	}
	// The key is made here; the cert-controller only ever sees the CSR.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cert.Spec.Hosts[0]}, DNSNames: cert.Spec.Hosts}, key)
	if err != nil {
		return engine.Result{}, err
	}
	chain, err := cc.Issue(ctx, kcc.Request{Issuer: is.Name, Config: config, Hosts: cert.Spec.Hosts, CSR: csr})
	if err == nil && len(chain) == 0 {
		err = errors.New("the cert-controller returned no certificate")
	}
	if err != nil {
		return engine.Result{}, c.fail(ctx, cert, "IssueFailed", fmt.Sprintf("%s: %v", name, err))
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return engine.Result{}, err
	}
	bundle, err := Bundle(chain, key)
	if err != nil {
		return engine.Result{}, err
	}
	if err := c.writeSecret(ctx, cert, bundle); err != nil {
		return engine.Result{}, err
	}
	nb, na := leaf.NotBefore.UTC(), leaf.NotAfter.UTC()
	ra := RenewAfter(nb, na)
	c.log("certificate %s/%s: issued by %s for %s, valid until %s", cert.Namespace, cert.Name, cert.Spec.Issuer, strings.Join(cert.Spec.Hosts, ","), na.Format(time.RFC3339))
	return engine.Result{RequeueAfter: min(ra.Sub(c.Clock.Now()), 12*time.Hour)}, c.setStatus(ctx, cert, func(st *v1.CertificateStatus, gen int64) {
		st.NotBefore, st.NotAfter, st.RenewAfter, st.Serial = &nb, &na, &ra, leaf.SerialNumber.Text(16)
		st.FailedAttempts, st.NextAttempt = 0, nil
		meta.SetCondition(&st.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "Issued",
			Message: "valid until " + na.Format("2006-01-02"), ObservedGeneration: gen}, c.now())
	})
}

// fixed: the failure was a missing Issuer or cert-controller, and it's there now (no need to wait
// out the backoff once someone fixes the setup).
func (c *Controller) fixed(cert *v1.Certificate, reason string) bool {
	if reason != "NoIssuer" && reason != "NoCertController" || c.Issuers == nil {
		return false
	}
	o, ok := c.Issuers.Get("", cert.Spec.Issuer)
	if !ok {
		return false
	}
	name, _ := o.(*v1.Issuer).CertController()
	_, err := c.CertControllers.Get(name)
	return err == nil
}

// Backoff is how long to wait before the next try after n failures in a row: 1 minute, doubling, at
// most an hour. Pure.
func Backoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := time.Minute
	for i := 1; i < n && d < time.Hour; i++ {
		d *= 2
	}
	return min(d, time.Hour)
}

func (c *Controller) fail(ctx context.Context, cert *v1.Certificate, reason, msg string) error {
	var wait time.Duration
	err := c.setStatus(ctx, cert, func(st *v1.CertificateStatus, gen int64) {
		if r := meta.FindCondition(st.Conditions, "Ready"); r == nil || r.ObservedGeneration != gen || r.Status == meta.ConditionTrue {
			st.FailedAttempts = 0 // a new spec, or it was fine before: start over
		}
		st.FailedAttempts++
		wait = Backoff(st.FailedAttempts)
		next := c.now().Add(wait)
		st.NextAttempt = &next
		meta.SetCondition(&st.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: reason, Message: msg, ObservedGeneration: gen}, c.now())
	})
	c.log("certificate %s/%s: %s (next try in %v)", cert.Namespace, cert.Name, msg, wait)
	if err != nil {
		return err // couldn't record it: the engine retries
	}
	return nil // the status change wakes us; needsIssue waits until NextAttempt
}

func (c *Controller) setStatus(ctx context.Context, cert *v1.Certificate, mutate func(*v1.CertificateStatus, int64)) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Certificate
		if err := c.Client.Get(ctx, "Certificate", cert.Namespace, cert.Name, &cur); err != nil {
			return err
		}
		mutate(&cur.Status, cur.Generation)
		err := c.Client.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return err
	}
	return errors.New("certificate kept changing")
}

// Bundle is the Secret's value: the certificate chain, then the private key (PEM).
func Bundle(chain [][]byte, key *ecdsa.PrivateKey) ([]byte, error) {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})...), nil
}

// ParseBundle reads a Secret's value back into a TLS certificate.
func ParseBundle(b []byte) (tls.Certificate, error) { return tls.X509KeyPair(b, b) }

func (c *Controller) writeSecret(ctx context.Context, cert *v1.Certificate, bundle []byte) error {
	defer clear(bundle)
	for attempt := 0; attempt < 3; attempt++ {
		var sec v1.Secret
		err := c.Client.Get(ctx, "Secret", cert.Namespace, cert.Spec.SecretName, &sec)
		switch {
		case client.IsNotFound(err):
			sec = v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
				ObjectMeta: meta.ObjectMeta{Name: cert.Spec.SecretName, Namespace: cert.Namespace, Labels: map[string]string{LabelCertificate: cert.Name}},
				Spec:       v1.SecretSpec{Value: bundle, AllowedDelivery: []string{v1.DeliverBroker, v1.DeliverFile}}}
			err = c.Client.Create(ctx, &sec)
		case err != nil:
			return err
		default:
			sec.Spec.Value = bundle
			err = c.Client.Update(ctx, &sec)
		}
		if client.IsConflict(err) || client.IsAlreadyExists(err) {
			continue
		}
		return err
	}
	return errors.New("secret kept changing")
}

// ── what the built-in acme cert-controller gets from the control plane ───────

// HTTP01Solver keeps HTTP-01 answers in the store, where every ingress class's desired state
// finds them (Pending): the cluster's ingress controllers serve them on port 80.
type HTTP01Solver struct {
	Store store.Store
	Now   func() time.Time
}

// Present implements acme.Solver.
func (s *HTTP01Solver) Present(ctx context.Context, host, token, keyAuth string) error {
	b, _ := json.Marshal(Challenge{Token: token, KeyAuth: keyAuth, Host: host, Expires: s.Now().Add(10 * time.Minute)})
	if _, err := s.Store.Create(ctx, store.Key{Kind: KindChallenge, Name: token}, b); err != nil && !errors.Is(err, store.ErrExists) {
		return err
	}
	return nil
}

// CleanUp implements acme.Solver.
func (s *HTTP01Solver) CleanUp(ctx context.Context, token string) error {
	o, err := s.Store.Get(ctx, store.Key{Kind: KindChallenge, Name: token})
	if err != nil {
		return nil
	}
	_, err = s.Store.Delete(ctx, o.Key, o.Revision)
	return err
}

// SealedStore keeps a cert-controller's per-issuer state in the store, sealed by the KMS.
type SealedStore struct {
	Store store.Store
	KMS   kms.KMS
}

func stateKey(issuer, k string) store.Key { return store.Key{Kind: KindState, Name: issuer + "." + k} }
func stateAAD(issuer, k string) []byte    { return []byte("kcc-state/" + issuer + "/" + k) }

// Get implements acme.Store.
func (s *SealedStore) Get(ctx context.Context, issuer, k string) ([]byte, error) {
	o, err := s.Store.Get(ctx, stateKey(issuer, k))
	if errors.Is(err, store.ErrNotFound) {
		return nil, acme.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var sealed kms.Sealed
	if err := json.Unmarshal(o.Data, &sealed); err != nil {
		return nil, err
	}
	return kms.Open(ctx, s.KMS, sealed, stateAAD(issuer, k))
}

// Put implements acme.Store.
func (s *SealedStore) Put(ctx context.Context, issuer, k string, v []byte) error {
	sealed, err := kms.Seal(ctx, s.KMS, v, stateAAD(issuer, k))
	if err != nil {
		return err
	}
	b, _ := json.Marshal(sealed)
	cur, err := s.Store.Get(ctx, stateKey(issuer, k))
	if errors.Is(err, store.ErrNotFound) {
		_, err = s.Store.Create(ctx, stateKey(issuer, k), b)
		return err
	}
	if err != nil {
		return err
	}
	_, err = s.Store.Update(ctx, stateKey(issuer, k), b, cur.Revision)
	return err
}

// BuiltinCertControllers are the cert-controllers every control plane has; dns are the DNS
// providers registered on this control-plane host, for acme's dns01 solvers.
func BuiltinCertControllers(st store.Store, k kms.KMS, ca *pki.CA, now func() time.Time, dns map[string]acme.DNSProvider) kcc.Registry {
	return kcc.Registry{
		"acme": &acme.Controller{HTTP01: &HTTP01Solver{Store: st, Now: now}, DNSProviders: dns, Store: &SealedStore{Store: st, KMS: k}},
		"internal-ca": &internalca.Controller{Sign: func(csr []byte, hosts []string) ([][]byte, error) {
			return ca.SignServerCSR(csr, hosts, now(), 90*24*time.Hour)
		}},
	}
}

// Pending lists the HTTP-01 answers ingress controllers should serve (token → key authorization).
func Pending(ctx context.Context, s store.Store, now time.Time) (map[string]string, error) {
	objs, _, err := s.List(ctx, store.Selector{Kind: KindChallenge})
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, o := range objs {
		var ch Challenge
		if json.Unmarshal(o.Data, &ch) == nil && now.Before(ch.Expires) {
			out[ch.Token] = ch.KeyAuth
		}
	}
	return out, nil
}

var _ engine.Controller = (*Controller)(nil)

// Package certificate is the certificate controller (design §7.3): cert-manager style, built into
// the control plane. An Ingress with TLS gets a Certificate for its hosts; a Certificate gets a
// certificate from its Issuer (ACME with HTTP-01, or the cluster's own CA) into a Secret, and a new
// one before it expires.
//
// HTTP-01 challenges are answered by the ingress controller silos: the controller keeps the
// pending tokens in the store, and the ingress controllers get them through the broker with their
// routes.
package certificate

import (
	"context"
	"crypto"
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
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

// Internal store kinds.
const (
	KindChallenge = "ACMEChallenge" // a pending HTTP-01 token → its key authorization
	KindAccount   = "ACMEAccount"   // an Issuer's ACME account key, sealed
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
	CA           *pki.CA
	Clock        clock.Clock
	Certificates *informer.Informer
	Ingresses    *informer.Informer
	Classes      *informer.Informer
	Issuers      *informer.Informer
	Log          func(string, ...any)
	// ACMEHTTP, if set, is the HTTP client for ACME servers (tests).
	ACMEHTTP *http.Client
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
	if k.Kind == "Ingress" {
		return engine.Result{}, c.reconcileIngress(ctx, k)
	}
	o, ok := c.Certificates.Get(k.Namespace, k.Name)
	if !ok {
		return engine.Result{}, nil
	}
	return c.reconcileCertificate(ctx, o.(*v1.Certificate))
}

// ── Ingress → Certificate ────────────────────────────────────────────────────

// TLSMode is an Ingress's TLS mode: as set, or acme on a public class and internal-ca otherwise.
func TLSMode(ing *v1.Ingress, class *v1.IngressClass) string {
	if ing.Spec.TLS.Mode != "" {
		return ing.Spec.TLS.Mode
	}
	if class != nil && class.Spec.Public {
		return v1.TLSAcme
	}
	return v1.TLSInternalCA
}

// DesiredCertificate is the Certificate an Ingress needs (nil: none, tls.mode none). Pure.
func DesiredCertificate(ing *v1.Ingress, class *v1.IngressClass) *v1.Certificate {
	mode := TLSMode(ing, class)
	if mode == v1.TLSNone {
		return nil
	}
	issuer := IssuerInternal
	if mode == v1.TLSAcme {
		issuer = IssuerLetsEncrypt
		if class != nil && class.Spec.Issuer != "" {
			issuer = class.Spec.Issuer
		}
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
	want := DesiredCertificate(ing, class)
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
		before := fmt.Sprintf("%+v", cur.Status)
		cur.Status.Address = c.controllerAddress(ctx, class)
		ready, reason, msg := true, "Ready", "routes served by the class's controller"
		if class == nil {
			ready, reason, msg = false, "NoClass", "ingress class "+ing.Spec.IngressClass+" doesn't exist"
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
		if fmt.Sprintf("%+v", cur.Status) == before {
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
	var s v1.Silo
	if err := c.Client.Get(ctx, "Silo", class.Spec.Controller.Namespace, class.Spec.Controller.Silo, &s); err != nil {
		return ""
	}
	return s.Status.Service.PublicIP
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
	var chain [][]byte
	switch {
	case is.Spec.InternalCA:
		chain, err = c.internalCA(cert.Spec.Hosts, key)
	case is.Spec.ACME != nil:
		chain, err = c.acmeIssue(ctx, &is, cert.Spec.Hosts, key)
	default:
		err = errors.New("the issuer has neither acme nor internalCA")
	}
	if err != nil {
		return engine.Result{}, c.fail(ctx, cert, "IssueFailed", err.Error())
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
		meta.SetCondition(&st.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "Issued",
			Message: "valid until " + na.Format("2006-01-02"), ObservedGeneration: gen}, c.now())
	})
}

func (c *Controller) fail(ctx context.Context, cert *v1.Certificate, reason, msg string) error {
	c.log("certificate %s/%s: %s", cert.Namespace, cert.Name, msg)
	_ = c.setStatus(ctx, cert, func(st *v1.CertificateStatus, gen int64) {
		meta.SetCondition(&st.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: reason, Message: msg, ObservedGeneration: gen}, c.now())
	})
	return errors.New(msg) // retried with backoff
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

// ── issuers ──────────────────────────────────────────────────────────────────

func (c *Controller) internalCA(hosts []string, key *ecdsa.PrivateKey) ([][]byte, error) {
	if c.CA == nil {
		return nil, errors.New("no cluster CA here")
	}
	tc, err := c.CA.ServerCertForKey(hosts, key, c.Clock.Now(), 90*24*time.Hour)
	if err != nil {
		return nil, err
	}
	return tc.Certificate, nil
}

// acmeClient is the issuer's ACME client, with its account (made on first use, key sealed).
func (c *Controller) acmeClient(ctx context.Context, is *v1.Issuer) (*acme.Client, error) {
	hc := c.ACMEHTTP
	if hc == nil && is.Spec.ACME.ServerCA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(is.Spec.ACME.ServerCA)) {
			return nil, errors.New("acme.serverCA: no certificate")
		}
		hc = &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	}
	key, fresh, err := c.accountKey(ctx, is.Name)
	if err != nil {
		return nil, err
	}
	cl := &acme.Client{Key: key, DirectoryURL: is.Spec.ACME.Server, HTTPClient: hc, UserAgent: "kevaso"}
	if fresh {
		acct := &acme.Account{}
		if is.Spec.ACME.Email != "" {
			acct.Contact = []string{"mailto:" + is.Spec.ACME.Email}
		}
		if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
			return nil, fmt.Errorf("acme account: %w", err)
		}
	}
	return cl, nil
}

type accountRecord struct {
	Sealed     kms.Sealed `json:"sealed"`
	Registered bool       `json:"registered"`
}

func (c *Controller) accountKey(ctx context.Context, issuer string) (crypto.Signer, bool, error) {
	k := store.Key{Kind: KindAccount, Name: issuer}
	aad := []byte("acme-account/" + issuer)
	if o, err := c.Store.Get(ctx, k); err == nil {
		var r accountRecord
		if err := json.Unmarshal(o.Data, &r); err != nil {
			return nil, false, err
		}
		der, err := kms.Open(ctx, c.KMS, r.Sealed, aad)
		if err != nil {
			return nil, false, err
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		clear(der)
		if err != nil {
			return nil, false, err
		}
		return key.(crypto.Signer), false, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, false, err
	}
	sealed, err := kms.Seal(ctx, c.KMS, der, aad)
	clear(der)
	if err != nil {
		return nil, false, err
	}
	b, _ := json.Marshal(accountRecord{Sealed: sealed, Registered: true})
	if _, err := c.Store.Create(ctx, k, b); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// acmeIssue runs an ACME order with HTTP-01 for every host, the answers served by the ingress
// controllers (they read pending challenges from the store through the broker).
func (c *Controller) acmeIssue(ctx context.Context, is *v1.Issuer, hosts []string, key *ecdsa.PrivateKey) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cl, err := c.acmeClient(ctx, is)
	if err != nil {
		return nil, err
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(hosts...))
	if err != nil {
		return nil, fmt.Errorf("acme order: %w", err)
	}
	var tokens []string
	defer func() {
		for _, t := range tokens {
			if o, err := c.Store.Get(context.WithoutCancel(ctx), store.Key{Kind: KindChallenge, Name: t}); err == nil {
				_, _ = c.Store.Delete(context.WithoutCancel(ctx), o.Key, o.Revision)
			}
		}
	}()
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return nil, err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var ch *acme.Challenge
		for _, x := range z.Challenges {
			if x.Type == "http-01" {
				ch = x
			}
		}
		if ch == nil {
			return nil, fmt.Errorf("%s: the ACME server offers no http-01 challenge", z.Identifier.Value)
		}
		keyAuth, err := cl.HTTP01ChallengeResponse(ch.Token)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(Challenge{Token: ch.Token, KeyAuth: keyAuth, Host: z.Identifier.Value, Expires: c.Clock.Now().Add(10 * time.Minute)})
		if _, err := c.Store.Create(ctx, store.Key{Kind: KindChallenge, Name: ch.Token}, b); err != nil && !errors.Is(err, store.ErrExists) {
			return nil, err
		}
		tokens = append(tokens, ch.Token)
		// Give the ingress controllers a moment to pick the answer up before the server checks.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(ChallengePickup):
		}
		if _, err := cl.Accept(ctx, ch); err != nil {
			return nil, fmt.Errorf("%s: accept: %w", z.Identifier.Value, err)
		}
		if _, err := cl.WaitAuthorization(ctx, z.URI); err != nil {
			return nil, fmt.Errorf("%s: %w (does %s point at the ingress controller, on port 80?)", z.Identifier.Value, err, z.Identifier.Value)
		}
	}
	if _, err := cl.WaitOrder(ctx, order.URI); err != nil {
		return nil, fmt.Errorf("acme order: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts}, key)
	if err != nil {
		return nil, err
	}
	der, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("acme finalize: %w", err)
	}
	return der, nil
}

// ChallengePickup is how long the controller waits for ingress controllers to have a new answer
// (they poll for it every few seconds).
var ChallengePickup = 6 * time.Second

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

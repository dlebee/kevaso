package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/rbac"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
)

// Secrets (design §8.4–8.6). A Secret object never holds its value: a value sent with a write is
// sealed into the vault and dropped before the object is stored, so get, list and watch can't
// return it. People read a value only through GET …/secrets/NAME/value, with read-value, and never
// for a write-only secret. Naming a secret in a Grant needs use on it, and so does giving a silo a
// Grant: being able to create silos doesn't give you every secret in the namespace.

// maxSecretValue is the largest value a secret can hold.
const maxSecretValue = 64 << 10

// prepareSecret takes the value out of a Secret being written and returns it (or a generated one)
// to seal once the object is stored. nil means the value doesn't change.
func (s *Server) prepareSecret(ctx context.Context, t target, obj meta.Object) ([]byte, error) {
	sec, ok := obj.(*v1.Secret)
	if !ok || t.status {
		return nil, nil
	}
	value := sec.Spec.Value
	sec.Spec.Value = nil
	if len(value) > maxSecretValue {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: spec.value is %d bytes, at most %d", sec.Name, len(value), maxSecretValue)
	}
	var old *v1.Secret
	if cur, err := s.store.Get(ctx, t.key()); err == nil {
		if o, _, err := v1.Decode(cur.Data); err == nil {
			old = o.(*v1.Secret)
		}
	}
	if old != nil && old.Spec.Type != sec.Spec.Type {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: spec.type can't change (delete and re-create it)", sec.Name)
	}
	if value == nil && sec.Spec.Generate && (old == nil || s.vault == nil || !s.vault.Has(ctx, old)) {
		v, err := secrets.Generate(sec.Spec.Type)
		if err != nil {
			return nil, errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: %v", sec.Name, err)
		}
		value = v
	}
	if value == nil {
		return nil, nil
	}
	if s.vault == nil {
		return nil, errf(http.StatusServiceUnavailable, "Unavailable", "this server has no KMS: it can't keep secret values")
	}
	if _, err := secrets.PublicKey(sec.Spec.Type, value); err != nil {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: %v", sec.Name, err)
	}
	return value, nil
}

// storeSecretValue seals value for the stored secret and records the new version in its status.
func (s *Server) storeSecretValue(ctx context.Context, o store.Object, value []byte) (store.Object, error) {
	defer clear(value)
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return o, err
	}
	st, err := s.vault.Put(ctx, obj.(*v1.Secret), value)
	if err != nil {
		return o, err
	}
	for attempt := 0; attempt < 5; attempt++ {
		cur, err := s.store.Get(ctx, o.Key)
		if err != nil {
			return o, err
		}
		obj, _, err := v1.Decode(cur.Data)
		if err != nil {
			return o, err
		}
		sec := obj.(*v1.Secret)
		sec.Status = st
		_, data, err := toMap(sec)
		if err != nil {
			return o, err
		}
		next, err := s.store.Update(ctx, o.Key, data, cur.Revision)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		return next, err
	}
	return o, errors.New("secret keeps changing; its value is stored, its status will catch up")
}

// secretValue serves GET …/secrets/NAME/value (RBAC already checked read-value).
func (s *Server) secretValue(ctx context.Context, w http.ResponseWriter, t target) {
	o, err := s.store.Get(ctx, t.key())
	if err != nil {
		writeErr(w, err)
		return
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		writeErr(w, err)
		return
	}
	sec := obj.(*v1.Secret)
	if !sec.Readable() {
		writeErr(w, errf(http.StatusForbidden, "Forbidden", "secret %s/%s is write-only: nobody can read its value back, only silos can use it", sec.Namespace, sec.Name))
		return
	}
	if s.vault == nil {
		writeErr(w, errf(http.StatusServiceUnavailable, "Unavailable", "this server has no KMS"))
		return
	}
	value, ver, err := s.vault.Value(ctx, sec)
	if errors.Is(err, secrets.ErrNoValue) {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "secret %s/%s has no value yet", sec.Namespace, sec.Name))
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	defer clear(value)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, client.SecretValue{Value: value, Version: ver})
}

// person reports whether ctx's caller is a person or service account (RBAC applies), not the admin
// socket, kevasod itself or a host.
func person(ctx context.Context) (user string, ok bool) {
	id, found := IdentityFrom(ctx)
	if !found || id == LocalAdmin || id == Component || id.Type == "host" {
		return "", false
	}
	return id.Name, true
}

// canUseSecrets checks use on each named secret in ns, with each secret's labels (for selector
// rules), and that each existing secret allows the delivery asked for.
func (s *Server) canUseSecrets(ctx context.Context, ns string, uses map[string][]string) error {
	names := make([]string, 0, len(uses))
	for n := range uses {
		names = append(names, n)
	}
	slices.Sort(names)
	user, isPerson := person(ctx)
	var p *rbac.Policy
	if isPerson && s.auth != nil {
		var err error
		if p, err = s.policy.Policy(ctx); err != nil {
			return err
		}
	}
	for _, name := range names {
		var sec *v1.Secret
		if o, err := s.store.Get(ctx, store.Key{Kind: "Secret", Namespace: ns, Name: name}); err == nil {
			if obj, _, err := v1.Decode(o.Data); err == nil {
				sec = obj.(*v1.Secret)
			}
		}
		if p != nil {
			a := rbac.Attributes{User: user, Groups: GroupsFrom(ctx), Verb: v1.VerbUse, Resource: "secrets", Namespace: ns, Name: name}
			if sec != nil {
				a.Labels = sec.Labels
			}
			if d := p.Authorize(a); !d.Allowed {
				return errf(http.StatusForbidden, "Forbidden", "%s may not use secret %s (needs use on secrets): %s", user, name, d.Reason)
			}
		}
		if sec != nil {
			for _, mode := range uses[name] {
				if !sec.Allows(mode) {
					return errf(http.StatusUnprocessableEntity, "Invalid", "secret %s doesn't allow delivery %s (it allows %s)", name, mode, allowedList(sec))
				}
			}
		}
	}
	return nil
}

func allowedList(sec *v1.Secret) string {
	var out []string
	for _, m := range v1.Deliveries {
		if sec.Allows(m) {
			out = append(out, m)
		}
	}
	return fmt.Sprint(out)
}

// grantUses is what a grant asks of each secret: name → delivery modes.
func grantUses(g *v1.Grant) map[string][]string {
	uses := map[string][]string{}
	for _, sec := range g.Spec.Secrets {
		uses[sec.Name] = append(uses[sec.Name], sec.Delivery())
	}
	if g.Spec.Operations != nil && g.Spec.Operations.Sign != nil {
		k := g.Spec.Operations.Sign.KeyRef
		uses[k] = append(uses[k], v1.DeliverSign)
	}
	return uses
}

// checkSecretUse: writing a Grant needs use on every secret it names; giving a silo a Grant it
// didn't have needs use on every secret that Grant names.
func (s *Server) checkSecretUse(ctx context.Context, t target, obj meta.Object) error {
	if t.status {
		return nil
	}
	switch o := obj.(type) {
	case *v1.Grant:
		return s.canUseSecrets(ctx, t.namespace, grantUses(o))
	case *v1.Silo:
		if _, ok := person(ctx); !ok || s.auth == nil {
			return nil
		}
		var had []string
		if cur, err := s.store.Get(ctx, t.key()); err == nil {
			if prev, _, err := v1.Decode(cur.Data); err == nil {
				had = prev.(*v1.Silo).Spec.Grants
			}
		}
		for _, g := range o.Spec.Grants {
			if slices.Contains(had, g) {
				continue
			}
			cur, err := s.store.Get(ctx, store.Key{Kind: "Grant", Namespace: t.namespace, Name: g})
			if errors.Is(err, store.ErrNotFound) {
				return errf(http.StatusUnprocessableEntity, "Invalid", "silo %s: grant %q doesn't exist in namespace %s", o.Name, g, t.namespace)
			}
			if err != nil {
				return err
			}
			gobj, _, err := v1.Decode(cur.Data)
			if err != nil {
				return err
			}
			if err := s.canUseSecrets(ctx, t.namespace, grantUses(gobj.(*v1.Grant))); err != nil {
				return fmt.Errorf("giving silo %s grant %s: %w", o.Name, g, err)
			}
		}
	}
	return nil
}

// secretLabels are a stored secret's labels (nil if it doesn't exist), for RBAC selector rules.
func (s *Server) secretLabels(ctx context.Context, t target) map[string]string {
	if t.kind.Kind != "Secret" || t.name == "" {
		return nil
	}
	o, err := s.store.Get(ctx, t.key())
	if err != nil {
		return nil
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return nil
	}
	if l := obj.GetObjectMeta().Labels; l != nil {
		return l
	}
	return map[string]string{}
}

// visibleSecret decides, for a caller who may only list some secrets, whether one is shown.
func (s *Server) visibleSecret(ctx context.Context, o store.Object) bool {
	id, _ := IdentityFrom(ctx)
	p, err := s.policy.Policy(ctx)
	if err != nil {
		return false
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return false
	}
	m := obj.GetObjectMeta()
	labels := m.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return p.Authorize(rbac.Attributes{User: id.Name, Groups: GroupsFrom(ctx), Verb: "list", Resource: "secrets", Namespace: m.Namespace, Name: m.Name, Labels: labels}).Allowed
}

// SetVault gives the server its secret vault (sealing needs a KMS).
func (s *Server) SetVault(v *secrets.Vault) { s.vault = v }

// Vault is the server's secret vault (nil without a KMS).
func (s *Server) Vault() *secrets.Vault { return s.vault }

// KMSAdmin is what the admin socket's KMS endpoints need: the local KMS, to escrow and rotate.
type KMSAdmin interface {
	EscrowKeys(recoveryPublic []byte) (kms.Escrow, error)
	Rotate() (string, error)
	Retire() error
}

// SetKMSAdmin enables /admin/kms/* (admin socket only).
func (s *Server) SetKMSAdmin(k KMSAdmin) { s.kmsAdmin = k }

// kmsEndpoints serves, through the admin socket only:
//
//	POST /admin/kms/recovery-key  make the recovery key, once: it's returned and never again
//	POST /admin/kms/rotate        new master key; every data key re-wrapped; old key retired
func (s *Server) kmsEndpoints(w http.ResponseWriter, r *http.Request, caller pki.Identity) {
	if caller != LocalAdmin {
		writeErr(w, errf(http.StatusForbidden, "Forbidden", "the KMS is managed only through the admin socket"))
		return
	}
	if s.kmsAdmin == nil || s.vault == nil || r.Method != http.MethodPost {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "%s %s", r.Method, r.URL.Path))
		return
	}
	ctx := r.Context()
	switch r.URL.Path {
	case "/admin/kms/recovery-key":
		if secrets.HasEscrow(ctx, s.store) {
			writeErr(w, errf(http.StatusConflict, "AlreadyExists", "the recovery key was already made (kvoadm init printed it); it's never shown again"))
			return
		}
		rk := kms.NewRecoveryKey()
		pub, err := rk.Public()
		if err != nil {
			writeErr(w, err)
			return
		}
		esc, err := s.kmsAdmin.EscrowKeys(pub)
		if err == nil {
			err = secrets.SaveEscrow(ctx, s.store, esc)
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, client.RecoveryKey{RecoveryKey: rk.String()})
	case "/admin/kms/rotate":
		id, err := s.kmsAdmin.Rotate()
		if err != nil {
			writeErr(w, err)
			return
		}
		n, err := s.vault.RewrapAll(ctx)
		if err != nil {
			writeErr(w, fmt.Errorf("re-wrapping data keys (the old key is kept, run rotate again): %w", err))
			return
		}
		if pub := secrets.EscrowPublic(ctx, s.store); pub != nil {
			esc, err := s.kmsAdmin.EscrowKeys(pub)
			if err == nil {
				err = secrets.SaveEscrow(ctx, s.store, esc)
			}
			if err != nil {
				writeErr(w, fmt.Errorf("escrowing the new key (the old key is kept): %w", err))
				return
			}
		}
		if err := s.kmsAdmin.Retire(); err != nil {
			writeErr(w, err)
			return
		}
		if pub := secrets.EscrowPublic(ctx, s.store); pub != nil { // the escrow now holds only the current key
			if esc, err := s.kmsAdmin.EscrowKeys(pub); err == nil {
				_ = secrets.SaveEscrow(ctx, s.store, esc)
			}
		}
		writeJSON(w, http.StatusOK, client.KMSRotation{KeyID: id, Rewrapped: n})
	default:
		writeErr(w, errf(http.StatusNotFound, "NotFound", "%s", r.URL.Path))
	}
}

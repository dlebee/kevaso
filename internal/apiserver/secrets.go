package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/policy"
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

// secretWrite is what a write to a Secret (or a ClusterSecret) carries from prepareSecret to the
// guards and the commit: every key the secret will hold (nil: unchanged), whether the write brought
// them all (value or data, not setData or removeKeys), and whether they have been sealed already.
type secretWrite struct {
	data   map[string][]byte
	whole  bool // value or data: every key was given in this write (only such a write may loosen)
	sticky bool // the value it changes was written write-only: so is this one (K-060)
	sealed bool // sealed before the object was committed (a loosening write): nothing left to do after
}

// newKeys is the set of keys a write leaves the secret with: value (the key value) or data
// replace every key; setData and removeKeys change some and keep the rest, from old (the keys it
// holds now; nil, ErrNoValue when none). nil: the write changes no key.
func newKeys(what, name string, value []byte, data, set map[string][]byte, remove []string, old func() (map[string][]byte, error)) (map[string][]byte, bool, error) {
	forms := 0
	for _, given := range []bool{value != nil, data != nil, set != nil || remove != nil} {
		if given {
			forms++
		}
	}
	bad := func(f string, a ...any) error {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %s", what, name, fmt.Sprintf(f, a...))
	}
	var out map[string][]byte
	whole := false
	switch {
	case forms == 0:
		return nil, false, nil
	case forms > 1:
		return nil, false, bad("a write carries spec.value, spec.data, or spec.setData and spec.removeKeys: one of them")
	case value != nil:
		out, whole = map[string][]byte{v1.ValueKey: value}, true
	case data != nil:
		if len(data) == 0 {
			return nil, false, bad("spec.data needs at least one key")
		}
		out, whole = map[string][]byte{}, true
		for k, b := range data {
			if b == nil {
				b = []byte{}
			}
			out[k] = b
		}
	default:
		cur, err := old()
		if err != nil && !errors.Is(err, secrets.ErrNoValue) {
			return nil, false, err
		}
		out = cur
		if out == nil {
			out = map[string][]byte{}
		}
		for _, k := range remove {
			if _, both := set[k]; both {
				secrets.Clear(out)
				return nil, false, bad("key %q is both in spec.setData and spec.removeKeys", k)
			}
			if _, ok := out[k]; !ok {
				secrets.Clear(out)
				return nil, false, bad("spec.removeKeys: it has no key %q", k)
			}
			clear(out[k])
			delete(out, k)
		}
		for k, b := range set {
			if b == nil {
				b = []byte{}
			}
			clear(out[k])
			out[k] = b
		}
		if len(out) == 0 {
			return nil, false, bad("a secret keeps at least one key: delete it instead")
		}
	}
	keys, size := secrets.Keys(out)
	if p := v1.KeyProblems(keys); len(p) > 0 {
		secrets.Clear(out)
		return nil, false, bad("%s", strings.Join(p, "; "))
	}
	if size > maxSecretValue {
		secrets.Clear(out)
		return nil, false, bad("its keys hold %d bytes, at most %d", size, maxSecretValue)
	}
	return out, whole, nil
}

type secretWriteKey struct{}

func secretWriteFrom(ctx context.Context) *secretWrite {
	sw, _ := ctx.Value(secretWriteKey{}).(*secretWrite)
	return sw
}

// checkLoosening is the K-018 rule, run on the object as it will be stored (after mutation
// policies, so a policy can't flip a setting past it): a secret may become readable, or allow a
// delivery mode it didn't, only in a write that brings a new value.
func checkLoosening(ctx context.Context, old, obj meta.Object) error {
	next, ok := obj.(*v1.Secret)
	prev, _ := old.(*v1.Secret)
	if !ok || prev == nil {
		return nil
	}
	if kind(prev) != kind(next) { // also here, so a policy can't turn a signing key into a readable secret
		return errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: spec.type can't change (delete and re-create it)", next.Name)
	}
	if !loosens(prev, next) {
		return nil
	}
	if sw := secretWriteFrom(ctx); sw != nil && sw.data != nil && sw.whole {
		return nil
	}
	return errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: spec.valueReadable, spec.allowedDelivery, and a registry secret's spec.server or spec.username can't be changed without every key again (spec.value or spec.data, not spec.setData) in the same write (a value made write-only, or kept to one registry, stays so)", next.Name)
}

func kind(s *v1.Secret) string {
	if s.Spec.Type == "" {
		return v1.SecretOpaque
	}
	return s.Spec.Type
}

// sealBeforeLoosening: a write that loosens a secret, with its new value, replaces the value before
// the object is committed, so there is never a moment when the looser object is stored and the old
// value is still in the vault. It returns the object to commit, with the new version in its status,
// and a function that puts the previous value back when the commit does not stay. The caller runs
// this after the checks that can refuse the write. The vault write is skipped on a dry run, and
// when the write is stale (the commit would refuse it).
func (s *Server) sealBeforeLoosening(ctx context.Context, old meta.Object, data []byte, current, expected int64) ([]byte, func(), error) {
	sw := secretWriteFrom(ctx)
	prev, _ := old.(*v1.Secret)
	if sw == nil || sw.data == nil || !sw.whole || prev == nil || s.vault == nil || dryRun(ctx) {
		return data, nil, nil
	}
	obj, _, err := v1.Decode(data)
	if err != nil {
		return nil, nil, err
	}
	next, ok := obj.(*v1.Secret)
	if !ok || !loosens(prev, next) {
		return data, nil, nil
	}
	if current != expected {
		return nil, nil, store.ErrConflict
	}
	key := store.Key{Kind: secrets.KindValue, Namespace: next.Namespace, Name: next.Name}
	var prior []byte
	had := false
	if cur, err := s.store.Get(ctx, key); err == nil {
		prior = bytes.Clone(cur.Data)
		had = true
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	st, err := s.vault.Put(ctx, next, sw.data, false)
	if err != nil {
		return nil, nil, err
	}
	sw.sealed = true
	next.Status = st
	_, data, err = toMap(next)
	restore := func() { s.restoreSecretValue(ctx, key, prior, had) }
	if err != nil {
		restore()
		return nil, nil, err
	}
	return data, restore, nil
}

// restoreSecretValue puts back the vault record a refused loosening write replaced.
func (s *Server) restoreSecretValue(ctx context.Context, key store.Key, prior []byte, had bool) {
	for range 4 {
		cur, err := s.store.Get(ctx, key)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if !had {
				return
			}
			if _, err = s.store.Create(ctx, key, prior); err == nil || errors.Is(err, store.ErrExists) {
				return
			}
		case err != nil:
			return
		case had:
			if _, err = s.store.Update(ctx, key, prior, cur.Revision); err == nil {
				return
			}
			if !errors.Is(err, store.ErrConflict) {
				return
			}
		default:
			if _, err = s.store.Delete(ctx, key, cur.Revision); err == nil || errors.Is(err, store.ErrNotFound) {
				return
			}
			if !errors.Is(err, store.ErrConflict) {
				return
			}
		}
	}
}

// prepareSecret takes the keys out of a Secret being written and returns every key it will hold
// (or a generated value) to seal once the object is stored. nil means no key changes.
func (s *Server) prepareSecret(ctx context.Context, t target, obj meta.Object) (*secretWrite, error) {
	sec, ok := obj.(*v1.Secret)
	if !ok || t.status {
		return nil, nil
	}
	sp := &sec.Spec
	value, data, set, remove := sp.Value, sp.Data, sp.SetData, sp.RemoveKeys
	sp.Value, sp.Data, sp.SetData, sp.RemoveKeys = nil, nil, nil, nil
	var old *v1.Secret
	if cur, err := s.store.Get(ctx, t.key()); err == nil {
		if o, _, err := v1.Decode(cur.Data); err == nil {
			old = o.(*v1.Secret)
		}
	}
	if old != nil && old.Spec.Type != sec.Spec.Type {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: spec.type can't change (delete and re-create it)", sec.Name)
	}
	if value == nil && data == nil && set == nil && remove == nil && sec.Spec.Generate && (old == nil || s.vault == nil || !s.vault.Has(ctx, old)) {
		v, err := secrets.Generate(sec.Spec.Type)
		if err != nil {
			return nil, errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: %v", sec.Name, err)
		}
		value = v
	}
	sticky := false
	keys, whole, err := newKeys("Secret", sec.Name, value, data, set, remove, func() (map[string][]byte, error) {
		if old == nil || s.vault == nil {
			return nil, secrets.ErrNoValue
		}
		sticky = s.vault.WrittenWriteOnly(ctx, old)
		d, _, err := s.vault.Value(ctx, old)
		return d, err
	})
	if err != nil || keys == nil {
		return nil, err
	}
	if s.vault == nil {
		secrets.Clear(keys)
		return nil, errf(http.StatusServiceUnavailable, "Unavailable", "this server has no KMS: it can't keep secret values")
	}
	if t := kind(sec); t != v1.SecretOpaque {
		if _, ok := keys[v1.ValueKey]; !ok || len(keys) != 1 {
			secrets.Clear(keys)
			return nil, errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: a %s secret holds one value, the key %q (spec.value): no other key", sec.Name, t, v1.ValueKey)
		}
	}
	if _, err := secrets.PublicKey(sec.Spec.Type, keys[v1.ValueKey]); err != nil {
		secrets.Clear(keys)
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: %v", sec.Name, err)
	}
	return &secretWrite{data: keys, whole: whole, sticky: sticky && !whole}, nil
}

// loosens reports whether next lets more of the stored value out than old does: a person can read
// it, or a delivery mode is allowed that wasn't.
func loosens(old, next *v1.Secret) bool {
	if registryBindingLoosens(old, next) { // a registry secret's server or username
		return true
	}
	if !old.Readable() && next.Readable() {
		return true
	}
	for _, m := range []string{v1.DeliverBroker, v1.DeliverInject, v1.DeliverFile, v1.DeliverEnv, v1.DeliverSign} {
		if !old.Allows(m) && next.Allows(m) {
			return true
		}
	}
	return false
}

// registryBindingLoosens reports whether a registry secret's server or username changed. The
// stored password is for that server: pointing it somewhere else, or at another user, is a new
// value's write.
func registryBindingLoosens(old, next *v1.Secret) bool {
	if kind(old) != v1.SecretRegistry || kind(next) != v1.SecretRegistry {
		return false
	}
	return v1.RegistryBinding(old.Spec.Server) != v1.RegistryBinding(next.Spec.Server) || old.Spec.Username != next.Spec.Username
}

// storeSecretValue seals the keys for the stored secret and records the new version in its status.
func (s *Server) storeSecretValue(ctx context.Context, o store.Object, data map[string][]byte, sticky bool) (store.Object, error) {
	defer secrets.Clear(data)
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return o, err
	}
	st, err := s.vault.Put(ctx, obj.(*v1.Secret), data, sticky)
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

// secretValue serves GET …/secrets/NAME/value[?key=KEY] (RBAC already checked read-value).
func (s *Server) secretValue(ctx context.Context, w http.ResponseWriter, t target, key string) {
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
	data, ver, err := s.vault.PersonValue(ctx, sec)
	if errors.Is(err, secrets.ErrWriteOnly) {
		writeErr(w, errf(http.StatusForbidden, "Forbidden", "secret %s/%s: this value was written while it was write-only, so nobody can read it back; write a new value to make it readable", sec.Namespace, sec.Name))
		return
	}
	if errors.Is(err, secrets.ErrNoValue) {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "secret %s/%s has no value yet", sec.Namespace, sec.Name))
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	defer secrets.Clear(data)
	writeKeys(w, "secret "+sec.Namespace+"/"+sec.Name, data, ver, key)
}

// writeKeys answers a /value read: every key, or with key only that one (404 when it isn't one).
func writeKeys(w http.ResponseWriter, what string, data map[string][]byte, ver int64, key string) {
	w.Header().Set("Cache-Control", "no-store")
	if key == "" {
		writeJSON(w, http.StatusOK, client.SecretValue{Data: data, Version: ver})
		return
	}
	b, ok := data[key]
	if !ok {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "%s has no key %q", what, key))
		return
	}
	writeJSON(w, http.StatusOK, client.SecretValue{Value: b, Version: ver})
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

// secretUse is one way a grant uses a secret: a delivery, and the key it names ("" for every key).
type secretUse struct{ mode, key string }

// canUseSecrets checks use on each named secret in ns, with each secret's labels (for selector
// rules), and that each existing secret allows the delivery asked for and has the key named (an
// inject with no key needs a secret with one key).
func (s *Server) canUseSecrets(ctx context.Context, ns string, uses map[string][]secretUse) error {
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
			have := sec.Status.Keys
			for _, u := range uses[name] {
				if !sec.Allows(u.mode) {
					return errf(http.StatusUnprocessableEntity, "Invalid", "secret %s doesn't allow delivery %s (it allows %s)", name, u.mode, allowedList(sec))
				}
				if len(have) == 0 {
					continue // no value yet: its keys aren't known
				}
				if u.key != "" && !slices.Contains(have, u.key) {
					return errf(http.StatusUnprocessableEntity, "Invalid", "secret %s has no key %q (its keys: %s)", name, u.key, strings.Join(have, ", "))
				}
				if u.mode == v1.DeliverInject && u.key == "" && len(have) > 1 {
					return errf(http.StatusUnprocessableEntity, "Invalid", "secret %s has %d keys (%s): an inject adds one, so name it (key: …)", name, len(have), strings.Join(have, ", "))
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

// grantUses is what a grant asks of each secret: name → delivery modes and keys.
func grantUses(g *v1.Grant) map[string][]secretUse {
	uses := map[string][]secretUse{}
	for _, sec := range g.Spec.Secrets {
		uses[sec.Name] = append(uses[sec.Name], secretUse{sec.Delivery(), sec.Key})
	}
	if g.Spec.Operations != nil && g.Spec.Operations.Sign != nil {
		k := g.Spec.Operations.Sign.KeyRef
		uses[k] = append(uses[k], secretUse{mode: v1.DeliverSign})
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
		var had []string
		if prev, ok := s.stored(ctx, t).(*v1.Silo); ok {
			had = prev.Spec.Grants
		}
		return s.checkNewGrants(ctx, t, "silo "+o.Name, had, o.Spec.Grants)
	case *v1.SiloSet:
		// The set's controller creates its instances as the component: the author's use is
		// checked here, on the template, as it is on a silo.
		var had []string
		if prev, ok := s.stored(ctx, t).(*v1.SiloSet); ok {
			had = prev.Spec.Template.Grants
		}
		return s.checkNewGrants(ctx, t, "siloset "+o.Name, had, o.Spec.Template.Grants)
	}
	return nil
}

// checkNewGrants: a person giving what (a silo, or a set's template) a Grant it didn't have needs
// use on every secret that Grant names.
func (s *Server) checkNewGrants(ctx context.Context, t target, what string, had, grants []string) error {
	if _, ok := person(ctx); !ok || s.auth == nil {
		return nil
	}
	for _, g := range grants {
		if slices.Contains(had, g) {
			continue
		}
		cur, err := s.store.Get(ctx, store.Key{Kind: "Grant", Namespace: t.namespace, Name: g})
		if errors.Is(err, store.ErrNotFound) {
			return errf(http.StatusUnprocessableEntity, "Invalid", "%s: grant %q doesn't exist in namespace %s", what, g, t.namespace)
		}
		if err != nil {
			return err
		}
		gobj, _, err := v1.Decode(cur.Data)
		if err != nil {
			return err
		}
		if err := s.canUseSecrets(ctx, t.namespace, grantUses(gobj.(*v1.Grant))); err != nil {
			return fmt.Errorf("giving %s grant %s: %w", what, g, err)
		}
	}
	return nil
}

// checkOpenShellPolicyNames: a person giving a silo (or a set's template) an OpenShellPolicy it
// didn't have needs that object to exist, the same 422 as a missing grant. Other runtimes are
// refused by semantic, which names the runtime; this check stays quiet for them.
func (s *Server) checkOpenShellPolicyNames(ctx context.Context, t target, obj meta.Object) error {
	var what, runtime string
	var had, names []string
	switch o := obj.(type) {
	case *v1.Silo:
		what, runtime, names = "silo "+o.Name, o.Spec.Runtime, o.Spec.OpenShellPolicies
		if prev, ok := s.stored(ctx, t).(*v1.Silo); ok {
			had = prev.Spec.OpenShellPolicies
		}
	case *v1.SiloSet:
		what, runtime, names = "siloset "+o.Name, o.Spec.Template.Runtime, o.Spec.Template.OpenShellPolicies
		if prev, ok := s.stored(ctx, t).(*v1.SiloSet); ok {
			had = prev.Spec.Template.OpenShellPolicies
		}
	default:
		return nil
	}
	if !policy.SelfEnforced(runtime) {
		return nil
	}
	if _, ok := person(ctx); !ok || s.auth == nil {
		return nil
	}
	for _, name := range names {
		if slices.Contains(had, name) {
			continue
		}
		_, err := s.store.Get(ctx, store.Key{Kind: "OpenShellPolicy", Namespace: t.namespace, Name: name})
		if errors.Is(err, store.ErrNotFound) {
			return errf(http.StatusUnprocessableEntity, "Invalid", "%s: openshell policy %q doesn't exist in namespace %s", what, name, t.namespace)
		}
		if err != nil {
			return err
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

// SetBackup enables POST /admin/backup (admin socket only): make returns a backup sealed to the
// recovery key's public half it's given.
func (s *Server) SetBackup(make func(ctx context.Context, recoveryPublic []byte) ([]byte, error)) {
	s.backup = make
}

func (s *Server) backupEndpoint(w http.ResponseWriter, r *http.Request, caller pki.Identity) {
	if caller != LocalAdmin {
		writeErr(w, errf(http.StatusForbidden, "Forbidden", "backups are made only through the admin socket"))
		return
	}
	if s.backup == nil || r.Method != http.MethodPost {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "%s %s", r.Method, r.URL.Path))
		return
	}
	pub := secrets.EscrowPublic(r.Context(), s.store)
	if pub == nil {
		writeErr(w, errf(http.StatusConflict, "NoRecoveryKey", "no recovery key yet: kvoadm init makes it, and backups are sealed to it"))
		return
	}
	b, err := s.backup(r.Context(), pub)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, client.Backup{Backup: b})
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
		var req client.KMSRotateRequest
		if r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
				writeErr(w, errf(http.StatusBadRequest, "BadRequest", "rotate: %v", err))
				return
			}
		}
		// A new recovery key (the old one leaked): the new master key below is escrowed only to it,
		// so the leaked key opens nothing backed up from now on.
		pub := secrets.EscrowPublic(ctx, s.store)
		var rk kms.RecoveryKey
		if req.NewRecoveryKey {
			rk = kms.NewRecoveryKey()
			var err error
			if pub, err = rk.Public(); err != nil {
				writeErr(w, err)
				return
			}
		}
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
		escrow := func() error {
			if pub == nil {
				return nil
			}
			esc, err := s.kmsAdmin.EscrowKeys(pub)
			if err == nil {
				err = secrets.SaveEscrow(ctx, s.store, esc)
			}
			return err
		}
		if err := escrow(); err != nil { // before retiring: a crash here still leaves a usable escrow
			writeErr(w, fmt.Errorf("escrowing the new key (the old key is kept): %w", err))
			return
		}
		if err := s.kmsAdmin.Retire(); err != nil {
			writeErr(w, err)
			return
		}
		if err := escrow(); err != nil { // now it holds only the current key
			writeErr(w, fmt.Errorf("escrow after retiring the old key: %w", err))
			return
		}
		resp := client.KMSRotation{KeyID: id, Rewrapped: n}
		if rk != nil {
			resp.RecoveryKey = rk.String()
			w.Header().Set("Cache-Control", "no-store")
		}
		writeJSON(w, http.StatusOK, resp)
	default:
		writeErr(w, errf(http.StatusNotFound, "NotFound", "%s", r.URL.Path))
	}
}

// checkRuntimeFit refuses, for a silo on a runtime that enforces grants itself (OpenShell: no
// network card, egress only through its proxy), what that runtime can't do, instead of accepting it
// and never opening it: services and allowFrom (nothing reaches it), another egress address, and
// grants it can't enforce (address ranges, UDP, deliveries other than inject).
func (s *Server) checkRuntimeFit(ctx context.Context, t target, obj meta.Object) error {
	silo, ok := obj.(*v1.Silo)
	if !ok || t.status {
		return nil
	}
	if err := s.checkContainerFit(ctx, t, silo); err != nil {
		return err
	}
	if !policy.SelfEnforced(silo.Spec.Runtime) {
		return nil
	}
	rt := silo.Spec.Runtime
	var problems []string
	if silo.Spec.Service != nil {
		problems = append(problems, rt+" has no network interface, so no service: reach it with kvo exec")
	}
	if stops, _ := silo.StopsOnControlPlaneLoss(); stops {
		// K-080, until the owner decides: its gateway restarts a sandbox outside Kevaso.
		problems = append(problems, "onControlPlaneLoss: Stop isn't available on "+rt+": its gateway brings its sandboxes back by itself (a restart of the gateway, a reboot), so nothing keeps it stopped without the control plane")
	}
	if src := silo.Spec.Network.Egress.Source; src != "" && src != v1.EgressHost {
		problems = append(problems, rt+"'s traffic leaves from the host's address only (egress.source: host)")
	}
	var grants []*v1.Grant
	for _, name := range silo.Spec.Grants {
		o, err := s.store.Get(ctx, store.Key{Kind: "Grant", Namespace: t.namespace, Name: name})
		if err != nil {
			continue // checkSecretUse reports missing grants
		}
		if g, _, err := v1.Decode(o.Data); err == nil {
			grants = append(grants, g.(*v1.Grant))
		}
	}
	var policies []*v1.OpenShellPolicy
	for _, name := range silo.Spec.OpenShellPolicies {
		o, err := s.store.Get(ctx, store.Key{Kind: "OpenShellPolicy", Namespace: t.namespace, Name: name})
		if err != nil {
			continue // checkOpenShellPolicyNames reports missing policies
		}
		if p, _, err := v1.Decode(o.Data); err == nil {
			policies = append(policies, p.(*v1.OpenShellPolicy))
		}
	}
	problems = append(problems, policy.Check(silo, grants, policies)...)
	if len(problems) > 0 {
		return errf(http.StatusUnprocessableEntity, "Invalid", "Silo %s: %s", silo.Name, strings.Join(problems, "; "))
	}
	return nil
}

// containerRuntime reports the container family's own runtimes (on the host's bridge).
func containerRuntime(rt string) bool { return rt == "docker" || rt == "podman" }

// checkContainerFit: command and volumes are container features for now. Containers get every
// delivery: a file secret in a folder under /run (the host mounts that folder read-only), and an
// env secret with a warning, since the engine keeps its value where whoever runs the host's docker
// or podman sees it (ADR 0009 addendum).
func (s *Server) checkContainerFit(ctx context.Context, t target, silo *v1.Silo) error {
	rt := silo.Spec.Runtime
	var problems []string
	if !containerRuntime(rt) {
		if len(silo.Spec.Command()) > 0 {
			problems = append(problems, "command is for container silos (docker, podman); "+rt+" boots its image")
		}
		if rt == v1.RuntimeTart {
			problems = append(problems, macSiloProblems(silo)...)
		}
		if rt == "cloud-hypervisor" {
			problems = append(problems, s.vmVolumeProblems(silo)...)
		} else if len(silo.Spec.Volumes) > 0 && !policy.SelfEnforced(rt) {
			problems = append(problems, "extra volumes on "+rt+" come later (container silos and cloud-hypervisor have them now)")
		}
		if policy.SelfEnforced(rt) && len(silo.Spec.Volumes) > 0 {
			problems = append(problems, "volumes on "+rt+" come later: /sandbox is what persists")
		}
	} else {
		for _, name := range silo.Spec.Grants {
			o, err := s.store.Get(ctx, store.Key{Kind: "Grant", Namespace: t.namespace, Name: name})
			if err != nil {
				continue
			}
			g, _, err := v1.Decode(o.Data)
			if err != nil {
				continue
			}
			for _, sec := range g.(*v1.Grant).Spec.Secrets {
				switch sec.Delivery() {
				case v1.DeliverFile:
					// The shape it has now (a file, or a folder of keys); unknown yet: one file.
					have := []string{v1.ValueKey}
					if cur := s.secretNamed(ctx, t.namespace, sec.Name); cur != nil && len(cur.Status.Keys) > 0 {
						have = cur.Status.Keys
					}
					k := sec.Key
					if k == "" {
						k = have[0]
					}
					p := sec.FilePath(k, have)
					if why := v1.ContainerFileProblem(p); why != "" {
						problems = append(problems, fmt.Sprintf("grant %s: secret %s: %s", name, sec.Name, why))
					}
				case v1.DeliverEnv:
					if !s.envKeptOut(ctx, silo) {
						warn(ctx, EnvOnContainerWarning(silo.Name, name, sec.Name, rt))
					}
				}
			}
		}
	}
	if len(problems) > 0 {
		return errf(http.StatusUnprocessableEntity, "Invalid", "Silo %s: %s", silo.Name, strings.Join(problems, "; "))
	}
	return nil
}

// envKeptOut reports whether the silo's variables stay out of the engine's records wherever it can
// run: every Ready host of its runtime (only its own once it's placed) starts its containers
// through Kevaso's OCI runtime (the worker reports it, RuntimeStatus.EnvOutsideEngine). With no
// such host known yet, no.
func (s *Server) envKeptOut(ctx context.Context, silo *v1.Silo) bool {
	hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
	if err != nil {
		return false
	}
	n := 0
	for _, h := range hosts {
		if silo.Status.Host != "" && h.Name != silo.Status.Host {
			continue
		}
		rs, ok := h.Status.Runtimes[silo.Spec.Runtime]
		if !ok || rs.State != "Ready" {
			continue
		}
		if !rs.EnvOutsideEngine {
			return false
		}
		n++
	}
	return n > 0
}

// EnvOnContainerWarning is the warning for an env secret on a container silo where the host can't
// keep the value from the engine (podman, rootless docker, a default runtime other than runc, no
// Kevaso OCI runtime registered): with --env-file the engine keeps it in the container's config.
func EnvOnContainerWarning(silo, grant, secret, rt string) string {
	return fmt.Sprintf("silo %s: grant %s: secret %s is delivered as an environment variable, and %s records it on that worker (its config, without Kevaso's OCI runtime): "+
		"the value is visible in the engine's records on that worker (%s inspect, its files on disk) to anyone who can read them. "+
		"Files don't have this weakness: deliver it as a file (or through the local endpoint)", silo, grant, secret, rt, rt)
}

// vmVolumeProblems: what a cloud-hypervisor silo's volumes and disk can't be (ADR 0006). A volume
// can't replace the guest's root; the root disk can only live on a mount class (an image file on
// its folder, so it moves with the silo), not on a device class.
func (s *Server) vmVolumeProblems(silo *v1.Silo) []string {
	var problems []string
	for _, v := range silo.Spec.Volumes {
		if path.Clean(v.MountPath) == "/" {
			problems = append(problems, "volume "+v.Name+": mountPath / is the VM's own disk")
		}
	}
	if d, ok := v1.DiskVolume(silo); ok {
		if c, known := s.classMap()[d.Class]; known && !c.Mount {
			problems = append(problems, "disk.class "+d.Class+": a VM's disk can live on a mount class (an image file on it), not a device class yet")
		}
	}
	return problems
}

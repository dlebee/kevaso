package apiserver

import (
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
	problems = append(problems, policy.Check(silo, grants)...)
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
					p := sec.Path
					if p == "" {
						p = "/run/secrets/" + sec.Name
					}
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
	return fmt.Sprintf("silo %s: grant %s: secret %s goes in as an environment variable, which %s keeps in the container's config on a host without Kevaso's OCI runtime: "+
		"anyone with access to the host's %s sees its value (%s inspect), and it's on the host's disk with that config; "+
		"deliver it as a file or through the local endpoint to keep it out", silo, grant, secret, rt, rt, rt)
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

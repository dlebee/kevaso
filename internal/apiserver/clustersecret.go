package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/rbac"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
)

// ClusterSecrets (hack/design/clustersecret.md). The object never holds its value: a value sent
// with a write is sealed into the vault and dropped before the object is stored. Status is the
// server's: a caller's status is dropped on create and on update, and /status is refused.
// Who may manage, list or read a value is authorizeClusterSecret.

// prepareClusterSecret takes the value out of a ClusterSecret being written. nil means the value
// doesn't change. A create with no value is refused: there is nothing to seal.
func (s *Server) prepareClusterSecret(ctx context.Context, t target, obj meta.Object) ([]byte, error) {
	cs, ok := obj.(*v1.ClusterSecret)
	if !ok || t.status {
		return nil, nil
	}
	value := cs.Spec.Value
	cs.Spec.Value = nil
	cs.Status = v1.ClusterSecretStatus{} // the server sets status; the caller's is never stored
	if len(value) > maxSecretValue {
		return nil, errf(http.StatusUnprocessableEntity, "Invalid", "ClusterSecret %s: spec.value is %d bytes, at most %d", cs.Name, len(value), maxSecretValue)
	}
	_, err := s.store.Get(ctx, t.key())
	creating := errors.Is(err, store.ErrNotFound)
	if err != nil && !creating {
		return nil, err
	}
	if value == nil {
		if creating {
			return nil, errf(http.StatusUnprocessableEntity, "Invalid", "ClusterSecret %s: needs a value (kvo create clustersecret %s --from-file FILE|-)", cs.Name, cs.Name)
		}
		return nil, nil
	}
	if s.vault == nil {
		return nil, errf(http.StatusServiceUnavailable, "Unavailable", "this server has no KMS: it can't keep secret values")
	}
	return value, nil
}

// withClusterStatus forces the status the server owns onto the bytes about to be stored, so a
// caller or a mutation policy can't set version or changedAt.
func withClusterStatus(data []byte, st v1.ClusterSecretStatus) ([]byte, error) {
	obj, _, err := v1.Decode(data)
	if err != nil {
		return nil, err
	}
	cs, ok := obj.(*v1.ClusterSecret)
	if !ok {
		return data, nil
	}
	cs.Status = st
	_, out, err := toMap(cs)
	return out, err
}

// storeClusterSecretValue seals value for the stored cluster secret and records the new version.
func (s *Server) storeClusterSecretValue(ctx context.Context, o store.Object, value []byte) (store.Object, error) {
	defer clear(value)
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return o, err
	}
	cs := obj.(*v1.ClusterSecret)
	ver, err := s.vault.PutCluster(ctx, cs, value)
	if err != nil {
		return o, err
	}
	now := s.clock.Now().UTC().Truncate(time.Second)
	for attempt := 0; attempt < 5; attempt++ {
		cur, err := s.store.Get(ctx, o.Key)
		if err != nil {
			return o, err
		}
		obj, _, err := v1.Decode(cur.Data)
		if err != nil {
			return o, err
		}
		cs = obj.(*v1.ClusterSecret)
		cs.Status = v1.ClusterSecretStatus{Version: ver, ChangedAt: &now}
		_, data, err := toMap(cs)
		if err != nil {
			return o, err
		}
		next, err := s.store.Update(ctx, o.Key, data, cur.Revision)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		return next, err
	}
	return o, errors.New("clustersecret keeps changing; its value is stored, its status will catch up")
}

// clusterSecretValue serves GET …/clustersecrets/NAME/value. Authorization already decided
// who may have it: a cluster-admin, a pinned ClusterRole, or a host reading for a plugin.
func (s *Server) clusterSecretValue(ctx context.Context, w http.ResponseWriter, t target) {
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
	cs := obj.(*v1.ClusterSecret)
	if s.vault == nil {
		writeErr(w, errf(http.StatusServiceUnavailable, "Unavailable", "this server has no KMS"))
		return
	}
	value, ver, err := s.vault.ClusterValue(ctx, cs)
	if errors.Is(err, secrets.ErrNoValue) {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "clustersecret %s has no value yet", cs.Name))
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

// hostCertificate reports a worker's certificate or a system node's (role control-plane).
func hostCertificate(id pki.Identity) bool {
	return id.Type == "host" && (id.Role == "worker" || id.Role == "control-plane")
}

// hostForPlugin is a host certificate's read of clustersecret name. Allowed only with
// ?for=PLUGIN, and only when that plugin's controller service account would itself be allowed
// the read. Install records the account's name; it lives in kevaso-system.
func (s *Server) hostForPlugin(ctx context.Context, r *http.Request, name string) (bool, string, error) {
	plugin := r.URL.Query().Get("for")
	if plugin == "" {
		return false, "a host reads a clustersecret's value only with ?for=PLUGIN", nil
	}
	o, err := s.store.Get(ctx, store.Key{Kind: "Plugin", Name: plugin})
	if errors.Is(err, store.ErrNotFound) {
		return false, fmt.Sprintf("plugin %s may not read clustersecret %s", plugin, name), nil
	}
	if err != nil {
		return false, "", err
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return false, "", err
	}
	pl, ok := obj.(*v1.Plugin)
	if !ok || pl.Spec.Controller == nil {
		return false, fmt.Sprintf("plugin %s may not read clustersecret %s", plugin, name), nil
	}
	user := pluginServiceAccountUser(pl.Spec.Controller.ServiceAccount)
	if user == "" {
		return false, fmt.Sprintf("plugin %s may not read clustersecret %s", plugin, name), nil
	}
	p, err := s.policy.Policy(ctx)
	if err != nil {
		return false, "", err
	}
	d := p.Authorize(rbac.Attributes{User: user, Verb: "get", Resource: rbac.ClusterSecretValue, Name: name})
	if !d.Allowed {
		return false, fmt.Sprintf("plugin %s may not read clustersecret %s", plugin, name), nil
	}
	return true, "host for plugin " + plugin, nil
}

// pluginServiceAccountUser is the RBAC user for a Plugin's spec.controller.serviceAccount.
// kvoadm plugin install stores the account's name; the account is in v1.PluginNamespace.
func pluginServiceAccountUser(sa string) string {
	sa = strings.TrimSpace(sa)
	if sa == "" {
		return ""
	}
	return rbac.ServiceAccountUser(v1.PluginNamespace, sa)
}

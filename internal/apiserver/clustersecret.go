package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/operators"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/rbac"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
)

// ClusterSecrets (hack/design/clustersecret.md). The object never holds its value: a value sent
// with a write is sealed into the vault and dropped before the object is stored. Status is the
// server's: a caller's status is dropped on create and on update, and /status is refused.
// Who may manage, list or read a value is authorizeClusterSecret.

// prepareClusterSecret takes the keys out of a ClusterSecret being written. nil means no key
// changes. A create with no value is refused: there is nothing to seal.
func (s *Server) prepareClusterSecret(ctx context.Context, t target, obj meta.Object) (*secretWrite, error) {
	cs, ok := obj.(*v1.ClusterSecret)
	if !ok || t.status {
		return nil, nil
	}
	sp := &cs.Spec
	data, set, remove := sp.Data, sp.SetData, sp.RemoveKeys
	sp.Data, sp.SetData, sp.RemoveKeys = nil, nil, nil
	cs.Status = v1.ClusterSecretStatus{} // the server sets status; the caller's is never stored
	cur, err := s.store.Get(ctx, t.key())
	creating := errors.Is(err, store.ErrNotFound)
	if err != nil && !creating {
		return nil, err
	}
	keys, whole, err := newKeys("ClusterSecret", cs.Name, data, set, remove, func() (map[string][]byte, error) {
		if creating || s.vault == nil {
			return nil, secrets.ErrNoValue
		}
		o, _, err := v1.Decode(cur.Data)
		if err != nil {
			return nil, err
		}
		d, _, err := s.vault.ClusterValue(ctx, o.(*v1.ClusterSecret))
		return d, err
	})
	if err != nil {
		return nil, err
	}
	if keys == nil {
		if creating {
			return nil, errf(http.StatusUnprocessableEntity, "Invalid", "ClusterSecret %s: needs at least one key (kvo create clustersecret %s --from-file KEY=FILE)", cs.Name, cs.Name)
		}
		return nil, nil
	}
	if s.vault == nil {
		secrets.Clear(keys)
		return nil, errf(http.StatusServiceUnavailable, "Unavailable", "this server has no KMS: it can't keep secret values")
	}
	return &secretWrite{data: keys, whole: whole}, nil
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
func (s *Server) storeClusterSecretValue(ctx context.Context, o store.Object, data map[string][]byte) (store.Object, error) {
	defer secrets.Clear(data)
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return o, err
	}
	cs := obj.(*v1.ClusterSecret)
	ver, err := s.vault.PutCluster(ctx, cs, data)
	keys, _ := secrets.Keys(data)
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
		cs.Status = v1.ClusterSecretStatus{Version: ver, ChangedAt: &now, Keys: keys}
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

// clusterSecretValue serves GET …/clustersecrets/NAME/value[?key=KEY]. Authorization already
// decided who may have it: a cluster-admin, a pinned ClusterRole, or a host reading for a plugin.
func (s *Server) clusterSecretValue(ctx context.Context, w http.ResponseWriter, t target, key string) {
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
	data, ver, err := s.vault.ClusterValue(ctx, cs)
	if errors.Is(err, secrets.ErrNoValue) {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "clustersecret %s has no value yet", cs.Name))
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	defer secrets.Clear(data)
	writeKeys(w, "clustersecret "+cs.Name, data, ver, key)
}

// hostCertificate reports a worker's certificate or a system node's (role control-plane).
func hostCertificate(id pki.Identity) bool {
	return id.Type == "host" && (id.Role == "worker" || id.Role == "control-plane")
}

// hostForPlugin is a host certificate's read of clustersecret name. Allowed only with
// ?for=PLUGIN&side=node|controller, where PLUGIN is a DNS label. side=node is checked as
// service account plugin-PLUGIN-node; side=controller as plugin-PLUGIN. A worker certificate
// may ask only for the node side. A control-plane certificate may ask for either (a system
// node can also be a worker). A provider plugin has no Plugin object: install creates the
// account for the side it installs, and the admin binds it. The host has no access of its own.
func (s *Server) hostForPlugin(ctx context.Context, id pki.Identity, r *http.Request, name string) (bool, string, error) {
	plugin := r.URL.Query().Get("for")
	side := r.URL.Query().Get("side")
	if plugin == "" {
		return false, "a host reads a clustersecret's value only with ?for=PLUGIN&side=node|controller", nil
	}
	if meta.ValidateName(plugin) != nil {
		return false, fmt.Sprintf("plugin %s may not read clustersecret %s", plugin, name), nil
	}
	switch side {
	case "node", "controller":
	default:
		return false, "a host reads a clustersecret's value with side=node or side=controller", nil
	}
	if id.Role == "worker" && side != "node" { // a worker certificate asks only for the node side
		return false, "a worker reads a clustersecret only for a plugin's node side (side=node)", nil
	}
	account := operators.ServiceAccountForSide(plugin, side)
	user := rbac.ServiceAccountUser(v1.PluginNamespace, account)
	p, err := s.policy.Policy(ctx)
	if err != nil {
		return false, "", err
	}
	d := p.Authorize(rbac.Attributes{User: user, Verb: "get", Resource: rbac.ClusterSecretValue, Name: name})
	if !d.Allowed {
		return false, fmt.Sprintf("plugin %s %s side may not read clustersecret %s", plugin, side, name), nil
	}
	return true, "host for plugin " + plugin + " " + side + " side", nil
}

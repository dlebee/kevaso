package apiserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
)

// ClusterSecrets (hack/design/clustersecret.md). The object never holds its value: a value sent
// with a write is sealed into the vault and dropped before the object is stored. Status is the
// server's: a caller's status is dropped on create and on update, and /status is refused.
// Creating, updating, deleting, getting and listing is a cluster-admin's. The value route is a
// cluster-admin's reveal, or a host certificate's when the secret names that host.

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

// clusterSecretValue serves GET …/clustersecrets/NAME/value. Authorization already allowed a
// cluster-admin or a host certificate; a host still has to be one the secret names.
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
	if id, ok := IdentityFrom(ctx); ok && id.Type == "host" {
		if !hostCertificate(id) || !cs.ForHost(id.Name) {
			writeErr(w, errf(http.StatusForbidden, "Forbidden", "host %s may not read clustersecret %s", id.Name, cs.Name))
			return
		}
	}
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

package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/panes"
	"kevaso.com/core/internal/store"
)

// Panes on the control plane (design §10.1). The silo's host fetches its reports and bundles and
// relays them (the silo named by the host, as for secrets: ADR 0009); the control plane checks the
// limits again, keeps the latest report
// per pane as a Pane object, and keeps HTML bundles as opaque blobs: weighed and hashed, never
// read. A bundle leaves only through GET …/panes/NAME/bundle, as a download no browser renders.
// Its format (ADR 0007, v1.PaneBundleMaxBytes) is between the silo and the panes app: nothing
// here parses it, and nothing should.

// bundleKind is where bundles are stored: not an API kind, so the generic API never serves one.
const bundleKind = "PaneBundle"

// storedBundle is a bundle in the store.
type storedBundle struct {
	Silo     string    `json:"silo"`
	SiloUID  string    `json:"siloUID"`
	Digest   string    `json:"digest"`
	Uploaded time.Time `json:"uploaded"`
	Data     []byte    `json:"data"` // opaque
}

type paneRates struct {
	mu      sync.Mutex
	buckets map[string]panes.Bucket // by silo uid
}

func (r *paneRates) take(uid string, l panes.Limits, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buckets == nil {
		r.buckets = map[string]panes.Bucket{}
	}
	b, ok := panes.Take(r.buckets[uid], l, now)
	r.buckets[uid] = b
	return ok
}

func bundleName(silo, digest string) string {
	return silo + "-" + strings.TrimPrefix(digest, "sha256:")
}

// silosPanes lists a silo's panes.
func (s *Server) silosPanes(ctx context.Context, silo *v1.Silo) ([]*v1.Pane, error) {
	objs, _, err := s.store.List(ctx, store.Selector{Kind: "Pane", Namespace: silo.Namespace})
	if err != nil {
		return nil, err
	}
	var out []*v1.Pane
	for _, o := range objs {
		obj, _, err := v1.Decode(o.Data)
		if err != nil {
			continue
		}
		if p := obj.(*v1.Pane); p.Spec.SiloUID == silo.UID {
			out = append(out, p)
		}
	}
	return out, nil
}

// brokerPane answers OpPane and OpPaneBundle.
func (s *Server) brokerPane(ctx context.Context, call *brokerCall, req client.BrokerRequest) (client.BrokerResponse, string, bool) {
	fail := func(err error) (client.BrokerResponse, string, bool) {
		return client.BrokerResponse{Error: "pane: " + err.Error()}, err.Error(), false
	}
	silo, l, now := call.silo, panes.Defaults, s.clock.Now()
	if !silo.Spec.Panes.On() {
		return fail(panes.ErrOff)
	}
	if !s.paneRates.take(silo.UID, l, now) {
		return fail(panes.ErrRate)
	}
	if req.Op == client.OpPaneBundle {
		allowHTML := false
		for _, k := range silo.Spec.Panes.Allow {
			allowHTML = allowHTML || k == v1.PaneHTML
		}
		if !allowHTML {
			return fail(panes.ErrKind)
		}
		digest := panes.Digest(req.Payload)
		if err := panes.CheckBundle(digest, req.Payload, l); err != nil {
			return fail(err)
		}
		if err := s.putBundle(ctx, silo, digest, req.Payload, now); err != nil {
			return fail(err)
		}
		return client.BrokerResponse{Digest: digest}, fmt.Sprintf("pane bundle %s, %d bytes", digest, len(req.Payload)), true
	}
	if req.Pane == nil {
		return fail(errors.New("no report"))
	}
	r := *req.Pane
	r.Silo, r.SiloUID = silo.Name, silo.UID // who it is comes from the host, never the report
	existing, err := s.silosPanes(ctx, silo)
	if err != nil {
		return fail(err)
	}
	var names []string
	for _, p := range existing {
		names = append(names, p.Spec.Pane)
	}
	if err := panes.Check(silo.Spec.Panes, r, names, l); err != nil {
		return fail(err)
	}
	if r.Kind == v1.PaneHTML {
		if _, err := s.store.Get(ctx, store.Key{Kind: bundleKind, Namespace: silo.Namespace, Name: bundleName(silo.Name, r.Bundle)}); err != nil {
			return fail(fmt.Errorf("bundle %s: upload it first (pane-bundle)", r.Bundle))
		}
	}
	if err := s.putPane(ctx, silo, r, now); err != nil {
		return fail(err)
	}
	return client.BrokerResponse{}, "pane " + r.Pane + " (" + r.Kind + ")", true
}

func (s *Server) putPane(ctx context.Context, silo *v1.Silo, r v1.PaneReport, now time.Time) error {
	key := store.Key{Kind: "Pane", Namespace: silo.Namespace, Name: panes.Name(silo.Name, r.Pane)}
	for range 5 {
		p := &v1.Pane{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Pane"},
			ObjectMeta: meta.ObjectMeta{Namespace: key.Namespace, Name: key.Name}, Spec: r}
		at := now.UTC()
		p.Status.UpdatedAt = &at
		cur, err := s.store.Get(ctx, key)
		var rev int64
		switch {
		case err == nil:
			obj, _, derr := v1.Decode(cur.Data)
			if derr != nil {
				return derr
			}
			old := obj.(*v1.Pane)
			if old.Spec.SiloUID == silo.UID {
				p.ObjectMeta, p.Status.Updates = old.ObjectMeta, old.Status.Updates
			} else { // an earlier silo of the same name: start over
				p.UID, p.CreationTimestamp = newUID(), &at
			}
			p.ResourceVersion, rev = "", cur.Revision
		case errors.Is(err, store.ErrNotFound):
			p.UID, p.CreationTimestamp = newUID(), &at
		default:
			return err
		}
		p.Status.Updates++
		p.Generation = p.Status.Updates
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if rev == 0 {
			_, err = s.store.Create(ctx, key, data)
		} else {
			_, err = s.store.Update(ctx, key, data, rev)
		}
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) {
			continue
		}
		return err
	}
	return errors.New("pane kept changing")
}

// putBundle stores a bundle, keeping at most a few per silo (the oldest unused ones go), so a silo
// can't fill the store by uploading new bundles.
func (s *Server) putBundle(ctx context.Context, silo *v1.Silo, digest string, b []byte, now time.Time) error {
	key := store.Key{Kind: bundleKind, Namespace: silo.Namespace, Name: bundleName(silo.Name, digest)}
	data, err := json.Marshal(storedBundle{Silo: silo.Name, SiloUID: silo.UID, Digest: digest, Uploaded: now.UTC(), Data: b})
	if err != nil {
		return err
	}
	if cur, err := s.store.Get(ctx, key); err == nil {
		_, err = s.store.Update(ctx, key, data, cur.Revision)
		return err
	}
	if _, err := s.store.Create(ctx, key, data); err != nil && !errors.Is(err, store.ErrExists) {
		return err
	}
	// Keep: the bundles current panes use, plus the newest ones, up to maxPanes+2.
	keep := 4
	if silo.Spec.Panes.MaxPanes > 0 {
		keep = silo.Spec.Panes.MaxPanes
	}
	keep += 2
	used := map[string]bool{digest: true}
	if ps, err := s.silosPanes(ctx, silo); err == nil {
		for _, p := range ps {
			used[p.Spec.Bundle] = true
		}
	}
	objs, _, err := s.store.List(ctx, store.Selector{Kind: bundleKind, Namespace: silo.Namespace})
	if err != nil {
		return err
	}
	type entry struct {
		o store.Object
		b storedBundle
	}
	var mine []entry
	for _, o := range objs {
		var sb storedBundle
		if json.Unmarshal(o.Data, &sb) == nil && sb.SiloUID == silo.UID {
			mine = append(mine, entry{o, sb})
		}
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].b.Uploaded.After(mine[j].b.Uploaded) })
	for i, e := range mine {
		if i >= keep && !used[e.b.Digest] {
			_, _ = s.store.Delete(ctx, e.o.Key, e.o.Revision)
		}
	}
	return nil
}

// paneBundle serves GET …/panes/NAME/bundle: the bytes as they were uploaded, as a download that
// nothing sniffs, renders or runs (RBAC: get on panes, checked in wrap).
func (s *Server) paneBundle(w http.ResponseWriter, r *http.Request, t target) {
	if r.Method != http.MethodGet {
		writeErr(w, errf(http.StatusMethodNotAllowed, "MethodNotAllowed", "%s %s", r.Method, r.URL.Path))
		return
	}
	ctx := r.Context()
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
	p := obj.(*v1.Pane)
	if p.Spec.Kind != v1.PaneHTML {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "pane %s is a status pane: it has no bundle", p.Name))
		return
	}
	bo, err := s.store.Get(ctx, store.Key{Kind: bundleKind, Namespace: t.namespace, Name: bundleName(p.Spec.Silo, p.Spec.Bundle)})
	if err != nil {
		writeErr(w, err)
		return
	}
	var sb storedBundle
	if err := json.Unmarshal(bo.Data, &sb); err != nil || sb.SiloUID != p.Spec.SiloUID {
		writeErr(w, errf(http.StatusNotFound, "NotFound", "bundle %s is gone", p.Spec.Bundle))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="pane.bundle"`)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Kevaso-Digest", sb.Digest)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sb.Data)
}

// SweepPanes removes the panes and bundles of silos that are gone.
func (s *Server) SweepPanes(ctx context.Context) error {
	silos, err := listAs[*v1.Silo](ctx, s.store, "Silo")
	if err != nil {
		return err
	}
	alive := map[string]bool{}
	for _, x := range silos {
		alive[x.UID] = true
	}
	objs, _, err := s.store.List(ctx, store.Selector{Kind: "Pane"})
	if err != nil {
		return err
	}
	for _, o := range objs {
		if obj, _, err := v1.Decode(o.Data); err == nil && !alive[obj.(*v1.Pane).Spec.SiloUID] {
			_, _ = s.store.Delete(ctx, o.Key, o.Revision)
		}
	}
	bs, _, err := s.store.List(ctx, store.Selector{Kind: bundleKind})
	if err != nil {
		return err
	}
	for _, o := range bs {
		var sb storedBundle
		if json.Unmarshal(o.Data, &sb) == nil && !alive[sb.SiloUID] {
			_, _ = s.store.Delete(ctx, o.Key, o.Revision)
		}
	}
	return nil
}

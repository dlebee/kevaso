package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/internal/names"
	"kevaso.com/core/internal/store"
)

// What a worker host may read (hack/design/worker-reads.md). Role control-plane is not a worker
// and is not narrowed here.
type workerScope int

const (
	workerNone workerScope = iota
	workerCluster
	workerRelated
)

// workerReadScope is the read scope of one kind for a worker certificate.
func workerReadScope(kind string) workerScope {
	switch kind {
	case "Host", "Silo", "Service", "IngressClass":
		// Silo is cluster-wide on purpose: allowFrom, DNS and the egress denylist need every
		// silo's addresses, and mayRemove reads a silo that has moved to another host. The API
		// returns the whole object.
		return workerCluster
	case "Grant", "Secret", "Lease", "Ingress", "OpenShellPolicy": // a worker reads an OpenShellPolicy only when a silo on it names it
		return workerRelated
	default:
		return workerNone
	}
}

func workerReadableKind(kind string) bool { return workerReadScope(kind) != workerNone }

// workerObjectRead is a GET of an object (or its status), not a subresource.
func workerObjectRead(t target) bool {
	return !t.value && !t.exec && !t.token && !t.move && !t.restoreSettle && t.stream == "" && t.lease == "" && t.answer == "" && !t.bundle && !t.scale
}

// workerRuns reports whether host is running silo: it is placed there, or a move is taking it
// to or from there.
func workerRuns(silo *v1.Silo, host string) bool {
	if silo == nil {
		return false
	}
	on := silo.Status.Host == host || silo.Status.MovingFrom == host // a worker reads for a silo moving to or from it
	return on
}

func objKey(namespace, name string) string { return namespace + "/" + name }

func (s *Server) listStored(ctx context.Context, kind, namespace string) ([]store.Object, error) {
	objs, _, err := s.store.List(ctx, store.Selector{Kind: kind, Namespace: namespace})
	return objs, err
}

func decodeStore[T any](o store.Object) (*T, error) {
	var out T
	if err := json.Unmarshal(o.Data, &out); err != nil {
		return nil, fmt.Errorf("stored %s: %w", o.Key, err)
	}
	return &out, nil
}

type placedSilo struct {
	rev  int64
	silo *v1.Silo
}

// placedSilos lists silos and which of them this host is running. all is every silo in the
// selector, which ingress targeting needs in order to see who owns a service name.
func (s *Server) placedSilos(ctx context.Context, host, namespace string) (placed []placedSilo, all []*v1.Silo, revs map[string]int64, err error) {
	objs, err := s.listStored(ctx, "Silo", namespace)
	if err != nil {
		return nil, nil, nil, err
	}
	revs = map[string]int64{}
	for _, o := range objs {
		silo, err := decodeStore[v1.Silo](o)
		if err != nil {
			return nil, nil, nil, err
		}
		all = append(all, silo)
		revs[objKey(silo.Namespace, silo.Name)] = o.Revision
		if workerRuns(silo, host) {
			placed = append(placed, placedSilo{rev: o.Revision, silo: silo})
		}
	}
	return placed, all, revs, nil
}

func bump(out map[string]int64, key string, rev int64) {
	if rev > out[key] {
		out[key] = rev
	}
}

// relations is the set of objects of kind that a worker host may read, and the revision of the
// write that put each one on the host (the latest of the objects that make the link).
func (s *Server) relations(ctx context.Context, host, kind, namespace string) (map[string]int64, error) {
	switch kind {
	case "Grant":
		return s.grantRelations(ctx, host, namespace)
	case "OpenShellPolicy":
		return s.policyRelations(ctx, host, namespace)
	case "Secret":
		return s.secretRelations(ctx, host, namespace)
	case "Lease":
		return s.leaseRelations(ctx, host, namespace)
	case "Ingress":
		return s.ingressRelations(ctx, host, namespace)
	default:
		return nil, fmt.Errorf("a worker has no related read of %s", kind)
	}
}

func (s *Server) grantRelations(ctx context.Context, host, namespace string) (map[string]int64, error) {
	placed, _, _, err := s.placedSilos(ctx, host, namespace)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, p := range placed {
		for _, name := range p.silo.Spec.Grants {
			if name == "" {
				continue
			}
			bump(out, objKey(p.silo.Namespace, name), p.rev)
		}
	}
	return out, nil
}

func (s *Server) policyRelations(ctx context.Context, host, namespace string) (map[string]int64, error) {
	placed, _, _, err := s.placedSilos(ctx, host, namespace)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, p := range placed {
		for _, name := range p.silo.Spec.OpenShellPolicies {
			if name == "" {
				continue
			}
			bump(out, objKey(p.silo.Namespace, name), p.rev)
		}
	}
	return out, nil
}

func (s *Server) secretRelations(ctx context.Context, host, namespace string) (map[string]int64, error) {
	placed, _, _, err := s.placedSilos(ctx, host, namespace)
	if err != nil {
		return nil, err
	}
	gobjs, err := s.listStored(ctx, "Grant", namespace)
	if err != nil {
		return nil, err
	}
	grants := map[string]*v1.Grant{}
	grev := map[string]int64{}
	for _, o := range gobjs {
		g, err := decodeStore[v1.Grant](o)
		if err != nil {
			return nil, err
		}
		k := objKey(g.Namespace, g.Name)
		grants[k] = g
		grev[k] = o.Revision
	}
	out := map[string]int64{}
	for _, p := range placed {
		for _, name := range p.silo.Spec.Grants {
			g := grants[objKey(p.silo.Namespace, name)]
			if g == nil {
				continue
			}
			rev := p.rev
			if grev[objKey(g.Namespace, g.Name)] > rev {
				rev = grev[objKey(g.Namespace, g.Name)]
			}
			for _, sn := range g.SecretNames() {
				bump(out, objKey(p.silo.Namespace, sn), rev)
			}
		}
		// The pull secret the silo names. A namespace default pull secret is resolved by the
		// broker at pull time; the worker does not read that object.
		if p.silo.Spec.Container != nil && p.silo.Spec.Container.Pull != nil && p.silo.Spec.Container.Pull.SecretRef != "" {
			bump(out, objKey(p.silo.Namespace, p.silo.Spec.Container.Pull.SecretRef), p.rev)
		}
	}
	return out, nil
}

func (s *Server) leaseRelations(ctx context.Context, host, namespace string) (map[string]int64, error) {
	placed, _, _, err := s.placedSilos(ctx, host, namespace)
	if err != nil {
		return nil, err
	}
	objs, err := s.listStored(ctx, "Lease", namespace)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, o := range objs {
		l, err := decodeStore[v1.Lease](o)
		if err != nil {
			return nil, err
		}
		for _, p := range placed {
			if p.silo.UID != "" && l.Namespace == p.silo.Namespace && l.Spec.Silo == p.silo.Name && l.Spec.SiloUID == p.silo.UID {
				bump(out, objKey(l.Namespace, l.Name), p.rev)
			}
		}
	}
	return out, nil
}

func (s *Server) ingressRelations(ctx context.Context, host, namespace string) (map[string]int64, error) {
	_, silos, siloRev, err := s.placedSilos(ctx, host, namespace)
	if err != nil {
		return nil, err
	}
	sobjs, err := s.listStored(ctx, "Service", namespace)
	if err != nil {
		return nil, err
	}
	var svcs []*v1.Service
	svcRev := map[string]int64{}
	for _, o := range sobjs {
		svc, err := decodeStore[v1.Service](o)
		if err != nil {
			return nil, err
		}
		svcs = append(svcs, svc)
		svcRev[objKey(svc.Namespace, svc.Name)] = o.Revision
	}
	iobjs, err := s.listStored(ctx, "Ingress", namespace)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, o := range iobjs {
		ing, err := decodeStore[v1.Ingress](o)
		if err != nil {
			return nil, err
		}
		var linker int64
		hit := false
		for _, rule := range ing.Spec.Rules {
			_, owner := names.Owner(ing.Namespace, rule.Service.Name, silos, svcs)
			for silo := range ingress.Targets(silos, svcs, ing.Namespace, rule.Service) {
				if !workerRuns(silo, host) {
					continue
				}
				hit = true
				if rev := siloRev[objKey(silo.Namespace, silo.Name)]; rev > linker {
					linker = rev
				}
				if owner != nil {
					if rev := svcRev[objKey(owner.Namespace, owner.Name)]; rev > linker {
						linker = rev
					}
				}
			}
		}
		if hit {
			out[objKey(ing.Namespace, ing.Name)] = linker
		}
	}
	return out, nil
}

// workerRelatedGet allows a GET of one related object when it is on this host. A missing object
// is allowed through, so the handler answers 404 rather than pretending it exists.
func (s *Server) workerRelatedGet(ctx context.Context, host string, t target) (bool, error) {
	if _, err := s.store.Get(ctx, t.key()); errors.Is(err, store.ErrNotFound) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	rel, err := s.relations(ctx, host, t.kind.Kind, t.namespace)
	if err != nil {
		return false, err
	}
	_, ok := rel[objKey(t.namespace, t.name)]
	return ok, nil
}

// keepRelated drops listed objects a worker host may not read.
func (s *Server) keepRelated(ctx context.Context, kind, namespace string, objs []store.Object) ([]store.Object, error) {
	host, _ := ctx.Value(hostReadKey).(string)
	rel, err := s.relations(ctx, host, kind, namespace)
	if err != nil {
		return nil, err
	}
	var out []store.Object
	for _, o := range objs {
		if _, ok := rel[objKey(o.Namespace, o.Name)]; !ok { // a worker's list leaves out what is not on it
			continue
		}
		out = append(out, o)
	}
	return out, nil
}

// shownState is an object a worker watch has already sent, at the revision it sent.
type shownState struct {
	rev int64
	raw json.RawMessage
}

// watchRelated streams one related kind. Objects the client already had at from are not sent
// again. An object that becomes related is sent once, as it is now: revisions from before the
// link are not replayed. An object that stops being related is reported deleted, as it was last
// sent, so a later state the host may no longer read is not.
func (s *Server) watchRelated(ctx context.Context, w http.ResponseWriter, from int64, host string, t target) {
	kindCh, err := s.store.Watch(ctx, store.Selector{Kind: t.kind.Kind, Namespace: t.namespace}, from)
	if err != nil {
		writeErr(w, err)
		return
	}
	siloCh, err := s.store.Watch(ctx, store.Selector{Kind: "Silo", Namespace: t.namespace}, from)
	if err != nil {
		writeErr(w, err)
		return
	}
	var grantCh, svcCh <-chan store.Event
	if t.kind.Kind == "Secret" {
		grantCh, err = s.store.Watch(ctx, store.Selector{Kind: "Grant", Namespace: t.namespace}, from)
		if err != nil {
			writeErr(w, err)
			return
		}
	}
	if t.kind.Kind == "Ingress" {
		svcCh, err = s.store.Watch(ctx, store.Selector{Kind: "Service", Namespace: t.namespace}, from)
		if err != nil {
			writeErr(w, err)
			return
		}
	}
	ww := &workerWatch{s: s, ctx: ctx, host: host, kind: t.kind.Kind, namespace: t.namespace, from: from, shown: map[string]shownState{}}
	if err := ww.prime(); err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	ww.enc = json.NewEncoder(w)
	ww.flusher = flusher
	if err := ww.flushPrime(); err != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-kindCh:
			if !ok {
				return
			}
			if err := ww.onKind(ev); err != nil {
				return
			}
		case _, ok := <-siloCh:
			if !ok {
				return
			}
			if err := ww.refresh(); err != nil {
				return
			}
		case _, ok := <-grantCh:
			if !ok {
				return
			}
			if err := ww.refresh(); err != nil {
				return
			}
		case _, ok := <-svcCh:
			if !ok {
				return
			}
			if err := ww.refresh(); err != nil {
				return
			}
		}
	}
}

type workerWatch struct {
	s         *Server
	ctx       context.Context
	enc       *json.Encoder
	flusher   http.Flusher
	host      string
	kind      string
	namespace string
	from      int64
	shown     map[string]shownState
	pending   []shownState // current objects to send once the headers are written
	pendingTy []string
}

func (w *workerWatch) prime() error {
	rel, err := w.s.relations(w.ctx, w.host, w.kind, w.namespace)
	if err != nil {
		return err
	}
	objs, err := w.s.listStored(w.ctx, w.kind, w.namespace)
	if err != nil {
		return err
	}
	for _, o := range objs {
		k := objKey(o.Namespace, o.Name)
		linker, ok := rel[k]
		if !ok {
			continue
		}
		raw, err := render(o)
		if err != nil {
			return err
		}
		// Unchanged since from: the client's list already has it.
		if o.Revision <= w.from && linker <= w.from {
			w.shown[k] = shownState{rev: w.from, raw: raw}
			continue
		}
		w.shown[k] = shownState{rev: o.Revision, raw: raw}
		w.pending = append(w.pending, w.shown[k])
		w.pendingTy = append(w.pendingTy, string(store.Added))
	}
	return nil
}

func (w *workerWatch) flushPrime() error {
	for i, sh := range w.pending {
		if err := w.send(w.pendingTy[i], sh.raw); err != nil {
			return err
		}
	}
	w.pending, w.pendingTy = nil, nil
	return nil
}

func (w *workerWatch) send(typ string, raw json.RawMessage) error {
	if err := w.enc.Encode(WatchEvent{Type: typ, Object: raw}); err != nil {
		return err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return nil
}

// drop tells the client the object is gone, as it was last sent.
func (w *workerWatch) drop(left shownState) error {
	if err := w.send(string(store.Deleted), left.raw); err != nil { // a watch drops an object that is no longer on this host
		return err
	}
	return nil
}

// refresh recomputes what is on the host after a silo, grant or service changed.
func (w *workerWatch) refresh() error {
	rel, err := w.s.relations(w.ctx, w.host, w.kind, w.namespace)
	if err != nil {
		return err
	}
	objs, err := w.s.listStored(w.ctx, w.kind, w.namespace)
	if err != nil {
		return err
	}
	cur := map[string]store.Object{}
	for _, o := range objs {
		k := objKey(o.Namespace, o.Name)
		if _, ok := rel[k]; ok {
			cur[k] = o
		}
	}
	for k, o := range cur {
		if _, ok := w.shown[k]; ok {
			continue
		}
		raw, err := render(o)
		if err != nil {
			return err
		}
		w.shown[k] = shownState{rev: o.Revision, raw: raw}
		if err := w.send(string(store.Added), raw); err != nil {
			return err
		}
	}
	for k, left := range w.shown {
		if _, ok := cur[k]; ok {
			continue
		}
		delete(w.shown, k)
		if err := w.drop(left); err != nil {
			return err
		}
	}
	for k, o := range cur {
		sh := w.shown[k]
		if o.Revision <= sh.rev {
			continue
		}
		raw, err := render(o)
		if err != nil {
			return err
		}
		w.shown[k] = shownState{rev: o.Revision, raw: raw}
		if err := w.send(string(store.Modified), raw); err != nil {
			return err
		}
	}
	return nil
}

// onKind delivers one change of the watched kind, never a revision from before the object was on
// this host.
func (w *workerWatch) onKind(ev store.Event) error {
	if w.namespace != "" && ev.Object.Namespace != w.namespace {
		return nil
	}
	key := objKey(ev.Object.Namespace, ev.Object.Name)
	if ev.Type == store.Deleted {
		left, ok := w.shown[key]
		if !ok {
			return nil
		}
		delete(w.shown, key)
		return w.drop(left)
	}
	cur, err := w.s.store.Get(w.ctx, ev.Object.Key)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	rel, err := w.s.relations(w.ctx, w.host, w.kind, w.namespace)
	if err != nil {
		return err
	}
	_, vis := rel[key]
	if sh, ok := w.shown[key]; ok {
		have := sh.rev
		curRev := cur.Revision
		stale := ev.Object.Revision <= have || ev.Object.Revision < curRev // a watch does not replay an object from before it was on this host
		if stale {
			return nil
		}
		if !vis {
			delete(w.shown, key)
			return w.drop(sh)
		}
		raw, err := render(ev.Object)
		if err != nil {
			return err
		}
		w.shown[key] = shownState{rev: ev.Object.Revision, raw: raw}
		return w.send(string(ev.Type), raw)
	}
	if !vis || ev.Object.Revision != cur.Revision {
		return nil
	}
	raw, err := render(cur)
	if err != nil {
		return err
	}
	w.shown[key] = shownState{rev: cur.Revision, raw: raw}
	return w.send(string(store.Added), raw)
}

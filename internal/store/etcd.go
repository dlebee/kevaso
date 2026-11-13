package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"go.etcd.io/etcd/api/v3/mvccpb"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// Etcd is the Store of a highly available control plane: every control plane's embedded etcd
// member is one voter of the same cluster (research E021). Each control plane talks to its own
// member; etcd keeps them consistent.
//
// # Revisions
//
// Kevaso's revision is etcd's revision plus a fixed Base:
//
//	kevaso revision = etcd mod_revision + Base
//
// Base is 0 for a store that started on etcd. When a SQLite store migrates in (MigrateSQLite),
// Base is the SQLite store's last revision, so revisions keep growing across the move and an
// informer never sees one go backwards. Base is kept in etcd itself (metaKey) and read at open.
//
// etcd's revision counts every write to the whole keyspace, so Kevaso's is still one global
// counter, but the store's own bookkeeping (metaKey) takes revisions too: they are writes that no
// watch reports, just like a write to another kind.
//
// # History and compaction
//
// A watch from revision R asks etcd for events from R+1-Base. The store keeps `keep` revisions of
// history by compacting etcd to (revision - keep + 1) as it writes; etcd then refuses older starts
// and the store returns ErrCompacted, the error informers answer by re-listing. A revision ahead
// of the store's own (one from another store's history, e.g. SQLite's before a migration, which
// compacts everything up to the move) is ErrCompacted too: a client can only have learned such a
// revision somewhere else, so it must re-list. A watch that etcd cancels while it runs (compacted
// under it, leader lost) closes its channel, which also means: re-list.
//
// # Keys
//
// An object lives at <prefix>o/<kind>/<namespace>/<name>; kinds and namespaces can't hold "/",
// names may. List sorts by (namespace, name) itself rather than trusting etcd's byte order.
type Etcd struct {
	cli    *clientv3.Client
	prefix string
	keep   int64
	base   int64

	ctx    context.Context // ends with Close: every watch's parent
	cancel context.CancelFunc

	mu          sync.Mutex
	compactedTo int64 // the etcd revision this store last compacted to
	closed      bool
	wg          sync.WaitGroup
}

// DefaultEtcdPrefix is where Kevaso keeps its keys in etcd.
const DefaultEtcdPrefix = "/kevaso/"

// EtcdMeta is the store's own record in etcd, at <prefix>meta.
type EtcdMeta struct {
	// Base is added to etcd revisions (the SQLite revision a migration started from; 0 if none).
	Base int64 `json:"base"`
	// Migration: "" when the store started on etcd, "running" while a SQLite store is copied in,
	// "done" once it was (it never runs again).
	Migration string `json:"migration,omitempty"`
	// MigratedObjects and MigratedFrom describe the migration, for people.
	MigratedObjects int    `json:"migratedObjects,omitempty"`
	MigratedFrom    string `json:"migratedFrom,omitempty"`
}

// OpenEtcd uses the etcd cluster behind cli as a store, keeping at least `keep` revisions of
// watch history (default 10000). The store doesn't close cli. The first open of an empty etcd
// records the store's meta (Base 0); a store left mid-migration can only be opened by
// MigrateSQLite, which finishes it.
func OpenEtcd(ctx context.Context, cli *clientv3.Client, keep int) (*Etcd, error) {
	return openEtcd(ctx, cli, DefaultEtcdPrefix, keep, false)
}

func openEtcd(ctx context.Context, cli *clientv3.Client, prefix string, keep int, migrating bool) (*Etcd, error) {
	if keep <= 0 {
		keep = 10000
	}
	e := &Etcd{cli: cli, prefix: prefix, keep: int64(keep)}
	m, ok, err := e.readMeta(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		m = EtcdMeta{}
		if err := e.initMeta(ctx, m); err != nil {
			return nil, err
		}
	}
	if m.Migration == "running" && !migrating {
		return nil, errors.New("etcd store: a SQLite migration didn't finish; start the control plane with --store etcd on the data dir that holds store.db to finish it")
	}
	e.base = m.Base
	e.ctx, e.cancel = context.WithCancel(context.Background())
	return e, nil
}

func (e *Etcd) metaKey() string { return e.prefix + "meta" }

func (e *Etcd) objPrefix() string { return e.prefix + "o/" }

func (e *Etcd) readMeta(ctx context.Context) (EtcdMeta, bool, error) {
	var m EtcdMeta
	r, err := e.cli.Get(ctx, e.metaKey())
	if err != nil {
		return m, false, fmt.Errorf("etcd store meta: %w", err)
	}
	if len(r.Kvs) == 0 {
		return m, false, nil
	}
	if err := json.Unmarshal(r.Kvs[0].Value, &m); err != nil {
		return m, false, fmt.Errorf("etcd store meta: %w", err)
	}
	return m, true, nil
}

// initMeta writes the meta if no one did yet (two control planes opening at once agree).
func (e *Etcd) initMeta(ctx context.Context, m EtcdMeta) error {
	b, _ := json.Marshal(m)
	_, err := e.cli.Txn(ctx).If(clientv3.Compare(clientv3.CreateRevision(e.metaKey()), "=", 0)).
		Then(clientv3.OpPut(e.metaKey(), string(b))).Commit()
	return err
}

func (e *Etcd) writeMeta(ctx context.Context, m EtcdMeta) error {
	b, _ := json.Marshal(m)
	_, err := e.cli.Put(ctx, e.metaKey(), string(b))
	return err
}

// Base is what the store adds to etcd's revisions.
func (e *Etcd) Base() int64 { return e.base }

func (e *Etcd) key(k Key) (string, error) {
	if k.Kind == "" || strings.Contains(k.Kind, "/") || strings.Contains(k.Namespace, "/") {
		return "", fmt.Errorf("key %q: kind and namespace can't be empty or hold '/'", k)
	}
	return e.objPrefix() + k.Kind + "/" + k.Namespace + "/" + k.Name, nil
}

func (e *Etcd) selPrefix(sel Selector) (string, error) {
	if sel.Kind == "" || strings.Contains(sel.Kind, "/") || strings.Contains(sel.Namespace, "/") {
		return "", fmt.Errorf("selector %+v: kind can't be empty, kind and namespace can't hold '/'", sel)
	}
	p := e.objPrefix() + sel.Kind + "/"
	if sel.Namespace != "" {
		p += sel.Namespace + "/"
	}
	return p, nil
}

func (e *Etcd) parse(k []byte) (Key, bool) {
	rest, ok := strings.CutPrefix(string(k), e.objPrefix())
	if !ok {
		return Key{}, false
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 {
		return Key{}, false
	}
	return Key{Kind: parts[0], Namespace: parts[1], Name: parts[2]}, true
}

func (e *Etcd) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	return nil
}

func (e *Etcd) object(k Key, kv *mvccpb.KeyValue) Object {
	return Object{Key: k, Revision: kv.ModRevision + e.base, Data: kv.Value}
}

// Get implements Store.
func (e *Etcd) Get(ctx context.Context, key Key) (Object, error) {
	if err := e.check(ctx); err != nil {
		return Object{}, err
	}
	ek, err := e.key(key)
	if err != nil {
		return Object{}, err
	}
	r, err := e.cli.Get(ctx, ek)
	if err != nil {
		return Object{}, err
	}
	if len(r.Kvs) == 0 {
		return Object{}, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	return e.object(key, r.Kvs[0]), nil
}

// List implements Store.
func (e *Etcd) List(ctx context.Context, sel Selector) ([]Object, int64, error) {
	if err := e.check(ctx); err != nil {
		return nil, 0, err
	}
	p, err := e.selPrefix(sel)
	if err != nil {
		return nil, 0, err
	}
	r, err := e.cli.Get(ctx, p, clientv3.WithPrefix())
	if err != nil {
		return nil, 0, err
	}
	out := make([]Object, 0, len(r.Kvs))
	for _, kv := range r.Kvs {
		if k, ok := e.parse(kv.Key); ok {
			out = append(out, e.object(k, kv))
		}
	}
	sortObjects(out)
	return out, r.Header.Revision + e.base, nil
}

// all lists every object of every kind, in key order, and the revision then.
func (e *Etcd) all(ctx context.Context) ([]Object, int64, error) {
	r, err := e.cli.Get(ctx, e.objPrefix(), clientv3.WithPrefix())
	if err != nil {
		return nil, 0, err
	}
	out := make([]Object, 0, len(r.Kvs))
	for _, kv := range r.Kvs {
		if k, ok := e.parse(kv.Key); ok {
			out = append(out, e.object(k, kv))
		}
	}
	sortAll(out)
	return out, r.Header.Revision + e.base, nil
}

// Create implements Store.
func (e *Etcd) Create(ctx context.Context, key Key, data []byte) (Object, error) {
	if err := key.Validate(); err != nil {
		return Object{}, err
	}
	if err := e.check(ctx); err != nil {
		return Object{}, err
	}
	ek, err := e.key(key)
	if err != nil {
		return Object{}, err
	}
	r, err := e.cli.Txn(ctx).If(clientv3.Compare(clientv3.CreateRevision(ek), "=", 0)).
		Then(clientv3.OpPut(ek, string(data))).Commit()
	if err != nil {
		return Object{}, err
	}
	if !r.Succeeded {
		return Object{}, fmt.Errorf("%s: %w", key, ErrExists)
	}
	return e.wrote(ctx, key, r.Header.Revision, data), nil
}

// Update implements Store.
func (e *Etcd) Update(ctx context.Context, key Key, data []byte, expected int64) (Object, error) {
	if err := e.check(ctx); err != nil {
		return Object{}, err
	}
	ek, err := e.key(key)
	if err != nil {
		return Object{}, err
	}
	r, err := e.cli.Txn(ctx).If(
		clientv3.Compare(clientv3.CreateRevision(ek), ">", 0),
		clientv3.Compare(clientv3.ModRevision(ek), "=", expected-e.base),
	).Then(clientv3.OpPut(ek, string(data))).Else(clientv3.OpGet(ek)).Commit()
	if err != nil {
		return Object{}, err
	}
	if !r.Succeeded {
		return Object{}, e.refused(key, r, expected)
	}
	return e.wrote(ctx, key, r.Header.Revision, data), nil
}

// Delete implements Store.
func (e *Etcd) Delete(ctx context.Context, key Key, expected int64) (Object, error) {
	if err := e.check(ctx); err != nil {
		return Object{}, err
	}
	ek, err := e.key(key)
	if err != nil {
		return Object{}, err
	}
	cmps := []clientv3.Cmp{clientv3.Compare(clientv3.CreateRevision(ek), ">", 0)}
	if expected != 0 {
		cmps = append(cmps, clientv3.Compare(clientv3.ModRevision(ek), "=", expected-e.base))
	}
	r, err := e.cli.Txn(ctx).If(cmps...).Then(clientv3.OpDelete(ek, clientv3.WithPrevKV())).Else(clientv3.OpGet(ek)).Commit()
	if err != nil {
		return Object{}, err
	}
	if !r.Succeeded {
		return Object{}, e.refused(key, r, expected)
	}
	d := r.Responses[0].GetResponseDeleteRange()
	var last []byte
	if len(d.PrevKvs) > 0 {
		last = d.PrevKvs[0].Value
	}
	return e.wrote(ctx, key, r.Header.Revision, last), nil
}

// refused says why a conditional write's Else branch ran: the object is gone, or it moved on.
func (e *Etcd) refused(key Key, r *clientv3.TxnResponse, expected int64) error {
	g := r.Responses[0].GetResponseRange()
	if g == nil || len(g.Kvs) == 0 {
		return fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	return fmt.Errorf("%s at %d, expected %d: %w", key, g.Kvs[0].ModRevision+e.base, expected, ErrConflict)
}

// wrote returns the object a write made and trims history.
func (e *Etcd) wrote(ctx context.Context, key Key, rev int64, data []byte) Object {
	e.compact(ctx, rev)
	return Object{Key: key, Revision: rev + e.base, Data: append([]byte(nil), data...)}
}

// compact drops history older than `keep` revisions, in steps of keep/100 so a busy store doesn't
// compact on every write. Compaction is cluster-wide: whichever control plane gets there first does
// it, and a compaction behind another's is refused by etcd and ignored here.
func (e *Etcd) compact(ctx context.Context, rev int64) {
	to := rev - e.keep + 1
	step := max(e.keep/100, 1)
	e.mu.Lock()
	if to <= 1 || to < e.compactedTo+step {
		e.mu.Unlock()
		return
	}
	e.compactedTo = to
	e.mu.Unlock()
	if _, err := e.cli.Compact(ctx, to); err != nil && !errors.Is(err, rpctypes.ErrCompacted) {
		e.mu.Lock()
		e.compactedTo = 0 // try again on the next write
		e.mu.Unlock()
	}
}

// Revision implements Store.
func (e *Etcd) Revision(ctx context.Context) (int64, error) {
	if err := e.check(ctx); err != nil {
		return 0, err
	}
	return e.etcdRevision(ctx)
}

func (e *Etcd) etcdRevision(ctx context.Context) (int64, error) {
	r, err := e.cli.Get(ctx, e.metaKey(), clientv3.WithCountOnly())
	if err != nil {
		return 0, err
	}
	return r.Header.Revision + e.base, nil
}

// Watch implements Store.
func (e *Etcd) Watch(ctx context.Context, sel Selector, from int64) (<-chan Event, error) {
	if err := e.check(ctx); err != nil {
		return nil, err
	}
	p, err := e.selPrefix(sel)
	if err != nil {
		return nil, err
	}
	cur, err := e.etcdRevision(ctx)
	if err != nil {
		return nil, err
	}
	if from > cur {
		return nil, fmt.Errorf("watch from %d, the store is at %d (a revision from another history): %w", from, cur, ErrCompacted)
	}
	start := from + 1 - e.base // the first etcd revision the watch reports
	if start < 1 {
		if e.base > 0 {
			return nil, fmt.Errorf("watch from %d, from before this store's history (it migrated at %d): %w", from, e.base, ErrCompacted)
		}
		start = 1
	}
	if from < cur {
		// Ask etcd whether it still has the start revision: a read there fails once it's compacted.
		if _, err := e.cli.Get(ctx, e.metaKey(), clientv3.WithRev(start), clientv3.WithCountOnly()); err != nil {
			if errors.Is(err, rpctypes.ErrCompacted) {
				return nil, fmt.Errorf("watch from %d: %w", from, ErrCompacted)
			}
			return nil, err
		}
	}
	wctx, cancel := context.WithCancel(clientv3.WithRequireLeader(ctx))
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		cancel()
		return nil, ErrClosed
	}
	e.wg.Add(1)
	e.mu.Unlock()
	wch := e.cli.Watch(wctx, p, clientv3.WithPrefix(), clientv3.WithRev(start), clientv3.WithPrevKV())
	out := make(chan Event, watchBuffer)
	go func() {
		defer e.wg.Done()
		defer close(out)
		defer cancel()
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-wctx.Done():
				return
			case resp, ok := <-wch:
				if !ok || resp.Canceled || resp.CompactRevision != 0 || resp.Err() != nil {
					return // compacted under us, leader lost, or ended: the client re-lists
				}
				for _, ev := range resp.Events {
					k, ok := e.parse(ev.Kv.Key)
					if !ok {
						continue
					}
					sev := Event{Type: Modified, Object: e.object(k, ev.Kv)}
					switch {
					case ev.Type == clientv3.EventTypeDelete:
						sev.Type = Deleted
						if ev.PrevKv != nil {
							sev.Object.Data = ev.PrevKv.Value
						}
					case ev.IsCreate():
						sev.Type = Added
					}
					select {
					case out <- sev:
					default:
						return // too far behind: dropped, the client re-lists
					}
				}
			}
		}
	}()
	return out, nil
}

// Close implements Store: open watches end. The client stays open (its owner closes it).
func (e *Etcd) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()
	e.cancel()
	e.wg.Wait()
	return nil
}

var _ Store = (*Etcd)(nil)

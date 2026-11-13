package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	_ "modernc.org/sqlite" // pure Go: no cgo, cross-compiles for every host
)

// SQLite is the Store of a single control plane: one file, with the same semantics as Memory.
// Writes are serialized (one control plane, one writer); watches replay from the events table and
// then go live, under the same lock, so nothing slips between the two.
type SQLite struct {
	db   *sql.DB
	keep int64

	mu     sync.Mutex // serializes writes and watch hand-over
	hub    hub
	closed bool
}

const schema = `
CREATE TABLE IF NOT EXISTS objects (
  kind TEXT NOT NULL, ns TEXT NOT NULL, name TEXT NOT NULL,
  rev INTEGER NOT NULL, data BLOB NOT NULL,
  PRIMARY KEY (kind, ns, name)
);
CREATE TABLE IF NOT EXISTS events (
  rev INTEGER PRIMARY KEY, type TEXT NOT NULL,
  kind TEXT NOT NULL, ns TEXT NOT NULL, name TEXT NOT NULL, data BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
INSERT OR IGNORE INTO meta (k, v) VALUES ('revision', 0), ('compacted', 0);
`

// OpenSQLite opens (or creates) the store at path, keeping the last `keep` events for watches
// (default 10000). Use ":memory:" for a throwaway store.
func OpenSQLite(path string, keep int) (*SQLite, error) {
	if keep <= 0 {
		keep = 10000
	}
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one connection: ":memory:" stays one database, writes stay serialized
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite schema: %w", err)
	}
	return &SQLite{db: db, keep: int64(keep)}, nil
}

func (s *SQLite) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed {
		return ErrClosed
	}
	return nil
}

// Get implements Store.
func (s *SQLite) Get(ctx context.Context, key Key) (Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx); err != nil {
		return Object{}, err
	}
	return getObject(ctx, s.db, key)
}

type querier interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

func getObject(ctx context.Context, q querier, key Key) (Object, error) {
	o := Object{Key: key}
	err := q.QueryRowContext(ctx, `SELECT rev, data FROM objects WHERE kind=? AND ns=? AND name=?`,
		key.Kind, key.Namespace, key.Name).Scan(&o.Revision, &o.Data)
	if errors.Is(err, sql.ErrNoRows) {
		return Object{}, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	return o, err
}

// List implements Store.
func (s *SQLite) List(ctx context.Context, sel Selector) ([]Object, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx); err != nil {
		return nil, 0, err
	}
	q := `SELECT ns, name, rev, data FROM objects WHERE kind=?`
	args := []any{sel.Kind}
	if sel.Namespace != "" {
		q += ` AND ns=?`
		args = append(args, sel.Namespace)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY ns, name`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []Object
	for rows.Next() {
		o := Object{Key: Key{Kind: sel.Kind}}
		if err := rows.Scan(&o.Namespace, &o.Name, &o.Revision, &o.Data); err != nil {
			return nil, 0, err
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	rev, err := s.meta(ctx, s.db, "revision")
	return out, rev, err
}

func (s *SQLite) meta(ctx context.Context, q querier, k string) (int64, error) {
	var v int64
	err := q.QueryRowContext(ctx, `SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	return v, err
}

// Create implements Store.
func (s *SQLite) Create(ctx context.Context, key Key, data []byte) (Object, error) {
	if err := key.Validate(); err != nil {
		return Object{}, err
	}
	return s.write(ctx, key, func(cur Object, exists bool) (EventType, []byte, error) {
		if exists {
			return "", nil, fmt.Errorf("%s: %w", key, ErrExists)
		}
		return Added, data, nil
	})
}

// Update implements Store.
func (s *SQLite) Update(ctx context.Context, key Key, data []byte, expected int64) (Object, error) {
	return s.write(ctx, key, func(cur Object, exists bool) (EventType, []byte, error) {
		if !exists {
			return "", nil, fmt.Errorf("%s: %w", key, ErrNotFound)
		}
		if cur.Revision != expected {
			return "", nil, fmt.Errorf("%s at %d, expected %d: %w", key, cur.Revision, expected, ErrConflict)
		}
		return Modified, data, nil
	})
}

// Delete implements Store.
func (s *SQLite) Delete(ctx context.Context, key Key, expected int64) (Object, error) {
	return s.write(ctx, key, func(cur Object, exists bool) (EventType, []byte, error) {
		if !exists {
			return "", nil, fmt.Errorf("%s: %w", key, ErrNotFound)
		}
		if expected != 0 && cur.Revision != expected {
			return "", nil, fmt.Errorf("%s at %d, expected %d: %w", key, cur.Revision, expected, ErrConflict)
		}
		return Deleted, cur.Data, nil
	})
}

// write runs one change in a transaction: decide from the current object, bump the revision,
// apply, record the event, trim history; then notify watchers.
func (s *SQLite) write(ctx context.Context, key Key, decide func(cur Object, exists bool) (EventType, []byte, error)) (Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx); err != nil {
		return Object{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Object{}, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	cur, err := getObject(ctx, tx, key)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Object{}, err
	}
	typ, data, err := decide(cur, exists)
	if err != nil {
		return Object{}, err
	}
	rev, err := s.meta(ctx, tx, "revision")
	if err != nil {
		return Object{}, err
	}
	rev++
	o := Object{Key: key, Revision: rev, Data: bytes.Clone(data)}
	if o.Data == nil {
		o.Data = []byte{}
	}
	stmts := []struct {
		q    string
		args []any
	}{
		{`UPDATE meta SET v=? WHERE k='revision'`, []any{rev}},
		{`INSERT INTO events (rev, type, kind, ns, name, data) VALUES (?,?,?,?,?,?)`,
			[]any{rev, string(typ), key.Kind, key.Namespace, key.Name, o.Data}},
	}
	if typ == Deleted {
		stmts = append(stmts, struct {
			q    string
			args []any
		}{`DELETE FROM objects WHERE kind=? AND ns=? AND name=?`, []any{key.Kind, key.Namespace, key.Name}})
	} else {
		stmts = append(stmts, struct {
			q    string
			args []any
		}{`INSERT INTO objects (kind, ns, name, rev, data) VALUES (?,?,?,?,?)
		   ON CONFLICT (kind, ns, name) DO UPDATE SET rev=excluded.rev, data=excluded.data`,
			[]any{key.Kind, key.Namespace, key.Name, rev, o.Data}})
	}
	if compacted := rev - s.keep; compacted > 0 {
		stmts = append(stmts,
			struct {
				q    string
				args []any
			}{`DELETE FROM events WHERE rev <= ?`, []any{compacted}},
			struct {
				q    string
				args []any
			}{`UPDATE meta SET v=? WHERE k='compacted'`, []any{compacted}})
	}
	for _, st := range stmts {
		if _, err := tx.ExecContext(ctx, st.q, st.args...); err != nil {
			return Object{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Object{}, err
	}
	s.hub.publish(Event{Type: typ, Object: o})
	return clone(o), nil
}

// Watch implements Store.
func (s *SQLite) Watch(ctx context.Context, sel Selector, from int64) (<-chan Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	compacted, err := s.meta(ctx, s.db, "compacted")
	if err != nil {
		return nil, err
	}
	if from < compacted {
		return nil, fmt.Errorf("watch from %d, history starts after %d: %w", from, compacted, ErrCompacted)
	}
	q := `SELECT rev, type, ns, name, data FROM events WHERE rev > ? AND kind=?`
	args := []any{from, sel.Kind}
	if sel.Namespace != "" {
		q += ` AND ns=?`
		args = append(args, sel.Namespace)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY rev`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var backlog []Event
	for rows.Next() {
		ev := Event{Object: Object{Key: Key{Kind: sel.Kind}}}
		var typ string
		if err := rows.Scan(&ev.Object.Revision, &typ, &ev.Object.Namespace, &ev.Object.Name, &ev.Object.Data); err != nil {
			return nil, err
		}
		ev.Type = EventType(typ)
		backlog = append(backlog, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return s.hub.subscribe(ctx, sel, backlog), nil
}

// Revision implements Store.
func (s *SQLite) Revision(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx); err != nil {
		return 0, err
	}
	return s.meta(ctx, s.db, "revision")
}

// Close implements Store.
func (s *SQLite) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.hub.closeAll()
	return s.db.Close()
}

var _ Store = (*SQLite)(nil)

// Snapshot writes a consistent copy of the store to path (which must not exist), while it keeps
// serving: a backup.
func (s *SQLite) Snapshot(ctx context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("store closed")
	}
	_, err := s.db.ExecContext(ctx, "VACUUM INTO ?", path)
	return err
}

// all returns every object of every kind in key order (kind, namespace, name), and the revision.
func (s *SQLite) all(ctx context.Context) ([]Object, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT kind, ns, name, rev, data FROM objects ORDER BY kind, ns, name`)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []Object
	for rows.Next() {
		var o Object
		if err := rows.Scan(&o.Kind, &o.Namespace, &o.Name, &o.Revision, &o.Data); err != nil {
			return nil, 0, err
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	rev, err := s.meta(ctx, s.db, "revision")
	return out, rev, err
}

package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kevaso.com/core/internal/store"
)

// Starting a cluster is always explicit (brainstorm §0.7, audit K-032). Each system node keeps a
// record next to its PKI, apart from the store's data: the cluster it belongs to and whether that
// cluster was made. The store holds the same identity, plus the history it is in. On start:
//
//   - no record: the node creates nothing. A joining node, or a data dir whose store holds a
//     cluster's identity (a restore from a backup without a record), adopts that identity;
//     anything else refuses.
//   - "new" (kevasod admin create-cluster, which kvoadm init runs, or Config.Create): the first
//     start makes the CA if there is none and writes the identity into the store.
//   - "initialized": the store must hold this cluster's identity. An empty store, or another
//     cluster's, refuses to start and says what to do.
//   - "restored" (kevasod admin restore, MarkRestored): the store must hold this cluster's
//     identity; the start begins a new history (a new History ID, Epoch+1), so workers can tell
//     a deliberate restore from a control plane that is behind (§0.7).

// ClusterRecordFile is the record's name in <data>/pki. It is in the PKI folder on purpose: it
// goes where the CA goes (backups carry it), and not where the store's data is.
const ClusterRecordFile = "cluster.json"

// Record states.
const (
	RecordNew         = "new"         // the next start creates the cluster
	RecordInitialized = "initialized" // the cluster was made: its store must be there
	RecordRestored    = "restored"    // a backup was put here: the next start begins a new history
)

// ClusterRecord is <data>/pki/cluster.json.
type ClusterRecord struct {
	Cluster string    `json:"cluster"` // the cluster's name
	ID      string    `json:"id"`      // the cluster's identity, made once, at creation
	State   string    `json:"state"`
	Created time.Time `json:"created"`
}

// ClusterIdentity is what the store holds about the cluster it is: its identity, and which
// history of it (a restore starts a new one). Every answer of the API carries it (headers.go).
type ClusterIdentity struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	History string    `json:"history"` // made at creation and at each restore; never reused
	Epoch   int64     `json:"epoch"`   // 1 at creation, +1 at each restore
	Created time.Time `json:"created"`
}

// identityKind is the store kind of the cluster's identity (one object, identityKey).
const identityKind = "ClusterIdentity"

var identityKey = store.Key{Kind: identityKind, Name: "cluster"}

// ClusterError is a start refused because of the cluster record: the message says what to do.
type ClusterError struct{ Msg string }

func (e *ClusterError) Error() string { return e.Msg }

func refuseStart(format string, a ...any) error {
	return &ClusterError{Msg: fmt.Sprintf(format, a...)}
}

func recordPath(dataDir string) string { return filepath.Join(dataDir, "pki", ClusterRecordFile) }

// ReadClusterRecord reads the record; nil, nil if there is none.
func ReadClusterRecord(dataDir string) (*ClusterRecord, error) {
	b, err := os.ReadFile(recordPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r ClusterRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", recordPath(dataDir), err)
	}
	if r.ID == "" || r.Cluster == "" {
		return nil, fmt.Errorf("%s: no cluster name or id", recordPath(dataDir))
	}
	switch r.State {
	case RecordNew, RecordInitialized, RecordRestored:
	default:
		return nil, fmt.Errorf("%s: unknown state %q", recordPath(dataDir), r.State)
	}
	return &r, nil
}

// writeRecord writes the record whole or not at all.
func writeRecord(dataDir string, r ClusterRecord) error {
	p := recordPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(p)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand doesn't fail on supported systems
	}
	return hex.EncodeToString(b)
}

// CreateCluster is the explicit create (kevasod admin create-cluster; kvoadm init runs it before
// it installs the unit): it writes a record that makes the next start create the cluster named
// name. On a node that already has a record for that name it changes nothing (kvoadm init run
// again); a record for another name is refused.
func CreateCluster(dataDir, name string, now time.Time) error {
	if name == "" {
		return errors.New("a cluster needs a name")
	}
	r, err := ReadClusterRecord(dataDir)
	if err != nil {
		return err
	}
	if r != nil {
		if r.Cluster != name {
			return refuseStart("this node already belongs to cluster %q (%s): to make a new cluster here, reset the node first (kvoadm reset)", r.Cluster, recordPath(dataDir))
		}
		return nil
	}
	return writeRecord(dataDir, ClusterRecord{Cluster: name, ID: newID(), State: RecordNew, Created: now.UTC()})
}

// MarkRestored marks a data dir a backup was just put into (kevasod admin restore): its next
// start begins a new history of the cluster. The record comes from the backup.
func MarkRestored(dataDir string) error {
	r, err := ReadClusterRecord(dataDir)
	if err != nil {
		return err
	}
	if r == nil {
		return refuseStart("%s has no cluster record (%s): the backup holds none, or the restore didn't finish", dataDir, recordPath(dataDir))
	}
	if r.State == RecordNew {
		return refuseStart("%s: the record is of a cluster never started, not a restored one", recordPath(dataDir))
	}
	r.State = RecordRestored
	return writeRecord(dataDir, *r)
}

// prepareRecord reads the record, and in create mode writes a new one where there is none.
func prepareRecord(cfg Config) (*ClusterRecord, error) {
	if cfg.Create && cfg.Join != nil {
		return nil, errors.New("create mode and joining are exclusive: a joining node takes the cluster it joins")
	}
	r, err := ReadClusterRecord(cfg.DataDir)
	if err != nil || r != nil || !cfg.Create {
		return r, err
	}
	if err := CreateCluster(cfg.DataDir, cfg.ClusterName, cfg.Clock.Now()); err != nil {
		return nil, err
	}
	return ReadClusterRecord(cfg.DataDir)
}

const howToRestore = "restore a backup onto this machine (kvoadm init --restore BACKUP)"

// ExitRefused is kevasod's exit status for a start refused because of what this node is (a
// ClusterError: its data is gone, or another cluster's): starting it again changes nothing, so
// its unit doesn't restart on it (RestartPreventExitStatus, rendered by kvoadm). Any other failure
// exits 1, which the unit restarts.
const ExitRefused = 78 // EX_CONFIG

// ExitCode is the exit status for err from Start (0 for nil).
func ExitCode(err error) int {
	var ce *ClusterError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ce):
		return ExitRefused
	}
	return 1
}

// mayHavePeers: this node is set up as a system node with peers (its unit's flags: store etcd with
// a peer listener), so it may be one of several, and the cluster may run on without it.
func mayHavePeers(cfg Config) bool { return cfg.Store == StoreEtcd && cfg.Etcd.PeerListen != "" }

// howToRecover is the fix for a node that refuses to start because its data is gone, from what is
// left on it: its unit's flags and whether it has a cluster record. A node that may be one of
// several system nodes is told to be taken out and added again (kvoadm init there would make a
// second cluster); only a single system node is told about a restore; making a new cluster is
// offered only to a node with no record of one.
func howToRecover(cfg Config, hasRecord bool) string {
	if mayHavePeers(cfg) {
		return fmt.Sprintf("if the cluster's other system nodes still run, take this one out and add it again: kvoadm host remove %s (from a machine with kvoadm), kvoadm reset (on this machine), then kvoadm host add %s --install control-plane (with the options it was added with). Only if it was the cluster's only system node, %s. Don't run kvoadm init here: it would make a second cluster",
			cfg.HostName, cfg.HostName, howToRestore)
	}
	if hasRecord {
		return howToRestore
	}
	return howToRestore + ", or make a new cluster on purpose (kvoadm reset, then kvoadm init)"
}

// storeOnDisk says whether the configured store has data on this node, before it is opened (an
// open would make an empty one). A joining etcd member gets its data from its peers.
func storeOnDisk(cfg Config) bool {
	exists := func(p string) bool { _, err := os.Stat(filepath.Join(cfg.DataDir, p)); return err == nil }
	switch cfg.Store {
	case StoreEtcd:
		// A store.db next to it is a restore or a SQLite store waiting to move into etcd.
		return exists(filepath.Join("etcd", "data", "member")) || exists("store.db") || cfg.Etcd.Join
	default:
		return exists("store.db")
	}
}

// checkBeforeOpen refuses, before anything is made on disk, a node whose record says its store
// must exist when it doesn't.
func checkBeforeOpen(cfg Config, rec *ClusterRecord) error {
	if storeOnDisk(cfg) {
		return nil
	}
	switch {
	case rec == nil && cfg.Join == nil:
		return refuseStart("this node belongs to no cluster (no %s, no store in %s): %s",
			recordPath(cfg.DataDir), cfg.DataDir, howToRecover(cfg, false))
	case rec != nil && rec.State != RecordNew:
		return refuseStart("this node belongs to cluster %q (%s), but its store is gone from %s: not starting an empty cluster. %s",
			rec.Cluster, recordPath(cfg.DataDir), cfg.DataDir, capital(howToRecover(cfg, true)))
	}
	return nil
}

func readIdentity(ctx context.Context, st store.Store) (ClusterIdentity, int64, bool, error) {
	var id ClusterIdentity
	o, err := st.Get(ctx, identityKey)
	if errors.Is(err, store.ErrNotFound) {
		return id, 0, false, nil
	}
	if err != nil {
		return id, 0, false, err
	}
	if err := json.Unmarshal(o.Data, &id); err != nil {
		return id, 0, false, fmt.Errorf("the store's cluster identity: %w", err)
	}
	return id, o.Revision, true, nil
}

// settleIdentity checks the opened store against the record, writes what create mode or a
// restore make, and returns the identity this node serves.
func settleIdentity(ctx context.Context, st store.Store, cfg Config, rec *ClusterRecord) (ClusterIdentity, error) {
	cur, rev, found, err := readIdentity(ctx, st)
	if err != nil {
		return cur, err
	}
	other := func() error {
		return refuseStart("this node belongs to cluster %q (id %s, %s), but its store is another cluster's (%q, id %s): not starting. %s",
			rec.Cluster, rec.ID, recordPath(cfg.DataDir), cur.Name, cur.ID, capital(howToRecover(cfg, true)))
	}
	done := func(r ClusterRecord) (ClusterIdentity, error) {
		r.State = RecordInitialized
		return cur, writeRecord(cfg.DataDir, r)
	}
	if rec == nil {
		if !found {
			return cur, refuseStart("this node has no cluster record (%s) and its store holds no cluster: not starting one. %s",
				recordPath(cfg.DataDir), capital(howToRecover(cfg, false)))
		}
		cfg.Log("cluster %q (id %s): writing this node's record %s", cur.Name, cur.ID, recordPath(cfg.DataDir))
		return done(ClusterRecord{Cluster: cur.Name, ID: cur.ID, Created: cur.Created})
	}
	if found && cur.ID != rec.ID {
		return cur, other()
	}
	switch rec.State {
	case RecordNew:
		if !found {
			cur = ClusterIdentity{ID: rec.ID, Name: rec.Cluster, History: newID(), Epoch: 1, Created: cfg.Clock.Now().UTC()}
			b, _ := json.Marshal(cur)
			if _, err := st.Create(ctx, identityKey, b); err != nil {
				return cur, fmt.Errorf("writing the cluster identity: %w", err)
			}
			cfg.Log("created cluster %q (id %s)", cur.Name, cur.ID)
		}
		return done(*rec)
	case RecordRestored:
		if !found {
			return cur, refuseStart("the restored store in %s holds no cluster identity: the backup predates it, or isn't this cluster's", cfg.DataDir)
		}
		cur.History, cur.Epoch = newID(), cur.Epoch+1
		b, _ := json.Marshal(cur)
		if _, err := st.Update(ctx, identityKey, b, rev); err != nil {
			return cur, fmt.Errorf("starting the restored history: %w", err)
		}
		cfg.Log("cluster %q restored: history %s, epoch %d (workers take it as a deliberate new start)", cur.Name, cur.History, cur.Epoch)
		return done(*rec)
	default: // RecordInitialized
		if !found {
			return cur, refuseStart("this node belongs to cluster %q (%s), but its store holds no cluster: not starting an empty one. %s",
				rec.Cluster, recordPath(cfg.DataDir), capital(howToRecover(cfg, true)))
		}
		return cur, nil
	}
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

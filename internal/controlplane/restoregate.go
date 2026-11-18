package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// RestoreHostsFile is the operator's statement about hosts the restored store cannot know,
// written by kevasod admin restore and read once when that history begins.
const RestoreHostsFile = "restore-hosts.json"

// RestoreHostsStatement is that file. Exactly one of the two forms is a statement.
type RestoreHostsStatement struct {
	NoHostsAdded bool     `json:"noHostsAdded,omitempty"`
	HostsAdded   []string `json:"hostsAdded,omitempty"`
}

// RestoreHostsPath is <data>/pki/restore-hosts.json, beside the cluster record.
func RestoreHostsPath(dataDir string) string {
	return filepath.Join(dataDir, "pki", RestoreHostsFile)
}

// WriteRestoreHosts records the statement for the next restored start.
func WriteRestoreHosts(dataDir string, noHostsAdded bool, hostsAdded []string) error {
	if err := os.MkdirAll(filepath.Join(dataDir, "pki"), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(RestoreHostsStatement{NoHostsAdded: noHostsAdded, HostsAdded: hostsAdded})
	if err != nil {
		return err
	}
	return os.WriteFile(RestoreHostsPath(dataDir), b, 0o600)
}

func readRestoreHosts(dataDir string) (RestoreHostsStatement, error) {
	b, err := os.ReadFile(RestoreHostsPath(dataDir))
	if os.IsNotExist(err) {
		return RestoreHostsStatement{}, nil
	}
	if err != nil {
		return RestoreHostsStatement{}, err
	}
	var s RestoreHostsStatement
	if err := json.Unmarshal(b, &s); err != nil {
		return RestoreHostsStatement{}, fmt.Errorf("restore hosts statement: %w", err)
	}
	if s.NoHostsAdded && len(s.HostsAdded) > 0 {
		return s, refuseStart("the restore says no host was added and also names hosts that were")
	}
	return s, nil
}

// openRestoreGate writes the account for this history before the identity is published, so a
// worker never sees the new history without it. A gate left by a start that stopped after
// writing it is updated to this attempt's history. The statement file stays until the record
// says the start finished.
func openRestoreGate(ctx context.Context, st store.Store, cfg Config, id ClusterIdentity) error {
	stmt, err := readRestoreHosts(cfg.DataDir)
	if err != nil {
		return err
	}
	hosts, err := restoredHostNames(ctx, st)
	if err != nil {
		return err
	}
	now := cfg.Clock.Now().UTC().Truncate(time.Second)
	spec := v1.RestoreGateSpec{
		History: id.History, Started: now,
		NoHostsAdded: stmt.NoHostsAdded, HostsAdded: stmt.HostsAdded, Required: hosts,
	}
	key := store.Key{Kind: "RestoreGate", Name: v1.RestoreGateName}
	g := &v1.RestoreGate{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RestoreGate"},
		ObjectMeta: meta.ObjectMeta{Name: v1.RestoreGateName, UID: newID(), CreationTimestamp: &now, Generation: 1},
		Spec:       spec,
	}
	b, err := json.Marshal(g)
	if err != nil {
		return err
	}
	if _, err := st.Create(ctx, key, b); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrExists) {
		return fmt.Errorf("the restore gate: %w", err)
	}
	o, err := st.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("the restore gate: %w", err)
	}
	var cur v1.RestoreGate
	if err := json.Unmarshal(o.Data, &cur); err != nil {
		return fmt.Errorf("the restore gate: %w", err)
	}
	cur.Spec.History, cur.Spec.Started = spec.History, spec.Started
	cur.Spec.NoHostsAdded, cur.Spec.HostsAdded, cur.Spec.Required = spec.NoHostsAdded, spec.HostsAdded, spec.Required
	cur.ResourceVersion = ""
	b, err = json.Marshal(&cur)
	if err != nil {
		return err
	}
	if _, err := st.Update(ctx, key, b, o.Revision); err != nil {
		return fmt.Errorf("the restore gate: %w", err)
	}
	return nil
}

func restoredHostNames(ctx context.Context, st store.Store) ([]string, error) {
	objs, _, err := st.List(ctx, store.Selector{Kind: "Host"})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, o := range objs {
		var h v1.Host
		if json.Unmarshal(o.Data, &h) != nil || h.Name == "" {
			continue
		}
		names = append(names, h.Name)
	}
	sort.Strings(names)
	return names, nil
}

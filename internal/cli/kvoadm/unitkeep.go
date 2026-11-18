package kvoadm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/backup"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/sshboot"
	"kevaso.com/core/internal/store"
)

// readInstalledUnit is the machine's kevasod.service, or empty when it has none.
func readInstalledUnit(ctx context.Context, conn *sshboot.Conn) (string, error) {
	out, err := conn.Run(ctx, "if [ -f /etc/systemd/system/kevasod.service ]; then cat /etc/systemd/system/kevasod.service; fi", nil)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// MergeUnit is the kevasod unit init installs. When the machine already has one and this run
// does not pass --replace-unit, a flag this run leaves out stays as the unit has it. A run that
// would drop a worker, a runtime, the storage mode, or an etcd store stops and names the flags.
func MergeUnit(existing string, o InitOptions) (InitOptions, string, error) {
	old := execStart(existing)
	if existing != "" && old == "" && !o.ReplaceUnit {
		return o, "", errors.New("kevasod.service is installed but has no kevasod ExecStart: pass --replace-unit to write it again")
	}
	if old != "" && !o.ReplaceUnit {
		o = keepUnstated(old, o)
	}
	unit := Unit(o)
	dropped := ""
	if old != "" {
		dropped = droppedFlags(old, execStart(unit))
	}
	if !o.ReplaceUnit && dropped != "" { // this run would drop a worker, a runtime, storage, or the etcd store
		return o, "", fmt.Errorf("kevasod.service on this machine has %s, and this init would drop them: repeat those flags, or pass --replace-unit to write the unit from this run only", dropped)
	}
	return o, unit, nil
}

func execStart(unit string) string {
	for _, l := range strings.Split(unit, "\n") {
		if rest, ok := strings.CutPrefix(l, "ExecStart=/usr/local/bin/kevasod "); ok {
			return rest
		}
	}
	return ""
}

type execFlags []string

func parseExec(exec string) execFlags { return strings.Fields(exec) }

func (f execFlags) has(name string) bool {
	for _, a := range f {
		if a == name {
			return true
		}
	}
	return false
}

func (f execFlags) values(name string) []string {
	var out []string
	for i := 0; i < len(f); i++ {
		if f[i] == name && i+1 < len(f) {
			out = append(out, f[i+1])
			i++
		}
	}
	return out
}

func (f execFlags) value(name string) string {
	v := f.values(name)
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

func keepUnstated(exec string, o InitOptions) InitOptions {
	f := parseExec(exec)
	if !o.Worker && f.has("--worker") {
		o.Worker = true // the unit already runs a worker: this init keeps it
	}
	if o.Worker && len(o.Runtimes) == 0 {
		o.Runtimes = append([]string(nil), f.values("--runtime")...)
	}
	if o.Worker && o.LoopStorage == "" && o.StorageDevice == "" {
		if v := f.value("--loop-size"); v != "" {
			o.LoopStorage = v
		}
		if v := f.value("--storage-device"); v != "" {
			o.StorageDevice = v
		}
	}
	if !o.storeGiven && f.value("--store") == "etcd" {
		o.Store = "etcd"
	}
	if o.EgressExtraCA == "" {
		o.EgressExtraCA = f.value("--egress-extra-ca")
	}
	if o.GatewayScope == "" {
		o.GatewayScope = f.value("--openshell-gateway-scope")
	}
	return o
}

func storageMode(f execFlags) string {
	switch {
	case f.has("--storage-device"):
		return "--storage-device"
	case f.has("--loop-storage") || f.has("--loop-size"):
		return "--loop-storage"
	default:
		return ""
	}
}

func droppedFlags(oldExec, newExec string) string {
	old, next := parseExec(oldExec), parseExec(newExec)
	var miss []string
	if old.has("--worker") && !next.has("--worker") {
		miss = append(miss, "--worker")
	}
	for _, r := range old.values("--runtime") {
		found := false
		for _, n := range next.values("--runtime") {
			if n == r {
				found = true
			}
		}
		if !found {
			miss = append(miss, "--runtime "+r)
		}
	}
	if mode := storageMode(old); mode != "" && mode != storageMode(next) {
		miss = append(miss, mode)
	}
	if old.value("--store") == "etcd" && next.value("--store") != "etcd" {
		miss = append(miss, "--store etcd")
	}
	if old.value("--egress-extra-ca") != "" && next.value("--egress-extra-ca") == "" {
		miss = append(miss, "--egress-extra-ca")
	}
	if old.value("--openshell-gateway-scope") != "" && next.value("--openshell-gateway-scope") == "" {
		miss = append(miss, "--openshell-gateway-scope")
	}
	return strings.Join(miss, ", ")
}

// withRestoredHost fills worker, runtimes and the etcd store from the named host in a backup,
// when this run did not state them. Storage (a loop file or a device) is not on the host.
func (o InitOptions) withRestoredHost(restoreJSON []byte) (InitOptions, error) {
	if o.ReplaceUnit {
		return o, nil
	}
	var req client.RestoreRequest
	if err := json.Unmarshal(restoreJSON, &req); err != nil {
		return o, err
	}
	rk, err := kms.ParseRecoveryKey(req.RecoveryKey)
	if err != nil {
		return o, err
	}
	_, files, err := backup.Open(req.Backup, rk)
	if err != nil {
		return o, err
	}
	db := files["store.db"]
	if len(db) == 0 {
		return o, errors.New("the backup has no store to read the host from")
	}
	host, found, err := hostFromStore(db, o.Name)
	if err != nil {
		return o, err
	}
	if !found {
		if o.Worker || o.storeGiven {
			return o, nil
		}
		return o, fmt.Errorf("the backup has no host %q to take the worker and store from: pass --worker and --runtime (and --store, if it is etcd), or --replace-unit", o.Name)
	}
	return fillFromHost(o, host), nil
}

func fillFromHost(o InitOptions, h v1.Host) InitOptions {
	if !o.Worker && h.Spec.Components.Worker != nil {
		o.Worker = true
		if len(o.Runtimes) == 0 {
			for _, rt := range h.Spec.Components.Worker.Runtimes {
				if rt.Name != "" {
					o.Runtimes = append(o.Runtimes, rt.Name)
				}
			}
		}
	}
	if !o.storeGiven && h.Status.ControlPlane != nil && h.Status.ControlPlane.Store == "etcd" {
		o.Store = "etcd"
	}
	return o
}

func hostFromStore(db []byte, name string) (v1.Host, bool, error) {
	dir, err := os.MkdirTemp("", "kevaso-restore-")
	if err != nil {
		return v1.Host{}, false, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "store.db")
	if err := os.WriteFile(path, db, 0o600); err != nil {
		return v1.Host{}, false, err
	}
	st, err := store.OpenSQLite(path, 0)
	if err != nil {
		return v1.Host{}, false, err
	}
	defer func() { _ = st.Close() }()
	objs, _, err := st.List(context.Background(), store.Selector{Kind: "Host"})
	if err != nil {
		return v1.Host{}, false, err
	}
	for _, obj := range objs {
		decoded, _, err := v1.Decode(obj.Data)
		if err != nil {
			return v1.Host{}, false, err
		}
		h, ok := decoded.(*v1.Host)
		if ok && h.Name == name {
			return *h, true, nil
		}
	}
	return v1.Host{}, false, nil
}

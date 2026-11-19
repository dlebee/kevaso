package kvoadm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"

	"kevaso.com/core/internal/backup"
)

func TestReadRecoveryKeyLeavesTheRest(t *testing.T) {
	rk := kms.NewRecoveryKey()
	in := strings.NewReader(rk.String() + "\nnext answer\n")
	got, err := readRecoveryKey(in, io.Discard)
	if err != nil || got.String() != rk.String() {
		t.Fatalf("%v %v", got, err)
	}
	rest, _ := io.ReadAll(in)
	if string(rest) != "next answer\n" {
		t.Fatalf("read past the key: %q left", rest)
	}
	if _, err := readRecoveryKey(strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("no key accepted")
	}
	if _, err := readRecoveryKey(strings.NewReader("KVR1-nope\n"), io.Discard); err == nil {
		t.Fatal("a malformed key accepted")
	}
}

func TestParseInitRestore(t *testing.T) {
	if _, err := parseInit([]string{"root@10.0.0.5", "--ssh-key", "k", "--kevasod", "b", "--restore", "prod.kvb"}); err == nil {
		t.Fatal("a restore without a statement about hosts was accepted")
	}
	if _, err := parseInit([]string{"root@10.0.0.5", "--ssh-key", "k", "--kevasod", "b", "--restore", "prod.kvb", "--no-hosts-added", "--host-added", "hv9"}); err == nil {
		t.Fatal("both statements were accepted")
	}
	o, err := parseInit([]string{"root@10.0.0.5", "--ssh-key", "k", "--kevasod", "b", "--restore", "prod.kvb", "--no-hosts-added"})
	if err != nil || o.Restore != "prod.kvb" || !o.NoHostsAdded || o.nameGiven || o.clusterGiven {
		t.Fatalf("%+v %v", o, err)
	}
	o, err = parseInit([]string{"root@10.0.0.5", "--ssh-key", "k", "--kevasod", "b", "--restore", "x", "--host-added", "hv9", "--host-added", "hv8", "--name", "cp-2", "--cluster", "c"})
	if err != nil || !o.nameGiven || !o.clusterGiven || len(o.HostsAdded) != 2 || o.HostsAdded[0] != "hv9" {
		t.Fatalf("%+v %v", o, err)
	}
}

// prepareRestore checks the key against the file before any machine is touched, and takes the
// cluster and host names from the backup.
func TestPrepareRestore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ca, _ := pki.NewCA("c", time.Now())
	_ = ca.Save(filepath.Join(dir, "pki"))
	st, _ := store.OpenSQLite(filepath.Join(dir, "store.db"), 0)
	defer func() { _ = st.Close() }()
	host, _ := json.Marshal(&v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "cp-1"}})
	if _, err := st.Create(ctx, store.Key{Kind: "Host", Name: "cp-1"}, host); err != nil {
		t.Fatal(err)
	}
	k, _ := kms.OpenLocal(filepath.Join(dir, "kms", "local.json"))
	rk := kms.NewRecoveryKey()
	pub, _ := rk.Public()
	esc, _ := k.EscrowKeys(pub)
	_ = secrets.SaveEscrow(ctx, st, esc)
	ks, _ := k.Status(ctx)
	blob, err := backup.Make(ctx, dir, st.Snapshot, backup.Manifest{Cluster: "prod", Host: "cp-1", Created: time.Now(), KMSKeyID: ks.KeyID}, pub)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "prod.kvb")
	_ = os.WriteFile(file, blob, 0o600)

	o := InitOptions{Restore: file, Cluster: "kevaso", Name: "10-0-0-5", NoHostsAdded: true}
	var out bytes.Buffer
	req, err := prepareRestore(&o, strings.NewReader(rk.String()+"\n"), &out)
	if err != nil {
		t.Fatal(err)
	}
	if o.Cluster != "prod" || o.Name != "cp-1" || !strings.Contains(out.String(), `cluster "prod"`) {
		t.Fatalf("%+v %s", o, out.String())
	}
	var r client.RestoreRequest
	if json.Unmarshal(req, &r) != nil || !bytes.Equal(r.Backup, blob) || r.RecoveryKey != rk.String() || !r.NoHostsAdded {
		t.Fatal("restore request")
	}
	o = InitOptions{Restore: file}
	if _, err := prepareRestore(&o, strings.NewReader(kms.NewRecoveryKey().String()+"\n"), io.Discard); err == nil {
		t.Fatal("a wrong recovery key got past the check")
	}
}

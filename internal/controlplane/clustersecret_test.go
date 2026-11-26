package controlplane

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/operators"
	"kevaso.com/core/internal/plugins"
)

// A system node with no worker still delivers a plugin's controller-side cluster secret.
// The controller side is installed on the system node and records its names in
// cluster-secrets.json; the delivery loop used to start only inside the worker's agent,
// so the credential file was never written here. The component client is not a host
// certificate and is refused for ?for=PLUGIN: this node fetches as itself.
func TestASystemNodeDeliversTheControllerSidesClusterSecret(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "kvcs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	etc := filepath.Join(dir, "plugins")
	const plugin = "linode"
	if err := os.MkdirAll(filepath.Join(etc, plugin), 0o700); err != nil {
		t.Fatal(err)
	}
	rec, err := plugins.EncodeClusterSecrets([]string{"token"})
	if err != nil {
		t.Fatal(err)
	}
	// The controller side's record, not the node side's cluster-secrets-node.json.
	if err := os.WriteFile(plugins.ClusterSecretsPath(etc, plugin, ""), rec, 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var logs []string
	logf := func(f string, a ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(f, a...))
		mu.Unlock()
	}
	r, err := Start(ctx, Config{
		ClusterName: "test", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: filepath.Join(dir, "data"), Listen: "127.0.0.1:0",
		AdminSocket: filepath.Join(dir, "admin.sock"), Heartbeat: time.Second,
		Create: true, Log: logf, PluginsEtc: etc,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = r.Wait() }()

	admin := client.NewUnix(filepath.Join(dir, "admin.sock"))
	const value = "linode-token-bytes"
	if err := admin.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: v1.PluginNamespace}}); err != nil {
		t.Fatal(err)
	}
	sa := operators.ServiceAccountName(plugin)
	if err := admin.Create(ctx, &v1.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Name: sa, Namespace: v1.PluginNamespace}}); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, &v1.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRole"}, ObjectMeta: meta.ObjectMeta{Name: "linode-secrets"},
		Rules: []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"clustersecrets/value"}, ResourceNames: []string{"token"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: "linode-secrets"},
		RoleRef:  v1.RoleRef{Kind: "ClusterRole", Name: "linode-secrets"},
		Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: v1.PluginNamespace}}}); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, &v1.ClusterSecret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterSecret"}, ObjectMeta: meta.ObjectMeta{Name: "token"},
		Spec: v1.ClusterSecretSpec{Data: map[string][]byte{"api-token": []byte(value)}}}); err != nil {
		t.Fatal(err)
	}

	cred := filepath.Join(etc, plugin, "token", "api-token") // a folder: LoadCredential loads it as token_api-token
	deadline := time.Now().Add(20 * time.Second)
	var got []byte
	var rdErr error
wait:
	for time.Now().Before(deadline) {
		got, rdErr = os.ReadFile(cred)
		if rdErr == nil && string(got) == value {
			break
		}
		select {
		case <-ctx.Done():
			break wait
		case <-time.After(50 * time.Millisecond):
		}
	}
	if rdErr != nil || string(got) != value {
		mu.Lock()
		defer mu.Unlock()
		why := "bytes differ"
		if rdErr != nil {
			why = rdErr.Error()
		}
		t.Fatalf("controller-side credential not written: %s\nlog:\n%s", why, strings.Join(logs, "\n"))
	}
	fi, err := os.Stat(cred)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", fi.Mode().Perm())
	}
	for _, l := range func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), logs...) }() {
		if strings.Contains(l, value) {
			t.Fatalf("the value was logged: %s", l)
		}
	}
}

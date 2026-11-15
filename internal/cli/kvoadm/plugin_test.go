package kvoadm

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
)

func TestPluginUnit(t *testing.T) {
	u := mustUnit(t, PluginOptions{Name: "linode", ClusterSecrets: []string{"token"}, Config: "c.json"})
	for _, want := range []string{
		"ExecStart=/usr/local/bin/kevaso-plugin-linode serve --socket /run/kevaso-plugins/linode/plugin.sock --config %d/config",
		"DynamicUser=yes", "RuntimeDirectory=kevaso-plugins/linode\n", "RuntimeDirectoryPreserve=yes",
		"LoadCredential=token:/etc/kevaso/plugins/linode/token", "LoadCredential=config:/etc/kevaso/plugins/linode/config.json",
		"CapabilityBoundingSet=\n", "AmbientCapabilities=\n", "NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateDevices=yes",
		"SystemCallFilter=~@privileged", "UMask=0077",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	// The node side gets its socket's folder too (node.sock), still unprivileged by default.
	n := mustUnit(t, PluginOptions{Name: "linode", Side: "node"})
	for _, want := range []string{"ExecStart=/usr/local/bin/kevaso-plugin-linode node --socket /run/kevaso-plugins/linode/node.sock\n",
		"RuntimeDirectory=kevaso-plugins/linode\n", "DynamicUser=yes", "ProtectSystem=strict"} {
		if !strings.Contains(n, want) {
			t.Errorf("node side unit lacks %q:\n%s", want, n)
		}
	}
	if strings.Contains(n, "LoadCredential") || strings.Contains(n, "KillMode") {
		t.Errorf("node side unit:\n%s", n)
	}
	if _, err := parsePlugin([]string{"root@h", "--name", "linode", "--binary", "b", "--credential", "token=/tmp/token"}, true); err == nil {
		t.Error("--credential is still accepted")
	}
}

// --credential is refused, and --cluster-secret records the names the unit loads. The record
// is names only, at the path kevasod reads, mode 0600.
func TestPluginInstallRecordsClusterSecrets(t *testing.T) {
	if _, err := parsePlugin([]string{"root@h", "--name", "linode", "--binary", "b", "--credential", "token=/tmp/token"}, true); err == nil || !strings.Contains(err.Error(), "--cluster-secret") {
		t.Fatalf("--credential: %v", err)
	}
	for _, bad := range []string{"Token", "token=/tmp/token", "config", "../x", ""} {
		args := []string{"root@h", "--name", "linode", "--binary", "b", "--cluster-secret", bad}
		if bad == "" {
			args = []string{"root@h", "--name", "linode", "--binary", "b", "--cluster-secret"}
		}
		if _, err := parsePlugin(args, true); err == nil {
			t.Errorf("--cluster-secret %q accepted", bad)
		}
	}
	o, err := parsePlugin([]string{"root@h", "--name", "linode", "--binary", "b", "--cluster-secret", "metering", "--cluster-secret", "token", "--cluster-secret", "token"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(o.ClusterSecrets, ",") != "metering,token" {
		t.Fatalf("recorded names %v", o.ClusterSecrets)
	}
	u := mustUnit(t, o)
	for _, want := range []string{
		"LoadCredential=metering:/etc/kevaso/plugins/linode/metering",
		"LoadCredential=token:/etc/kevaso/plugins/linode/token",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	path, data, mode, err := clusterSecretUpload(o)
	if err != nil {
		t.Fatal(err)
	}
	if path != "/etc/kevaso/plugins/linode/cluster-secrets.json" || mode != 0o600 {
		t.Fatalf("record %s mode %o", path, mode)
	}
	var rec struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if strings.Join(rec.Names, ",") != "metering,token" {
		t.Fatalf("record names %v", rec.Names)
	}
	if bytes.Contains(data, []byte("/tmp")) || bytes.Contains(data, []byte("value")) {
		t.Fatalf("the record holds more than names: %s", data)
	}
	node := o
	node.Side = "node"
	npath, _, _, err := clusterSecretUpload(node)
	if err != nil || npath != "/etc/kevaso/plugins/linode/"+plugins.ClusterSecretsNodeFile {
		t.Fatalf("node record %s %v", npath, err)
	}
	rm := PluginRemoveScript("linode", "node")
	if !strings.Contains(rm, "rm -f /etc/systemd/system/'kevaso-plugin-linode-node.service' '/etc/kevaso/plugins/linode/cluster-secrets-node.json'") {
		t.Fatalf("removing the node side leaves its cluster-secret names: %s", rm)
	}
}

// What a JuiceFS-like node side asks for (root, /dev/fuse, the host's mount namespace) is exactly
// what its unit grants, and nothing that would put its mounts in a namespace of its own.
func TestPrivilegedPluginUnit(t *testing.T) {
	node := kplugin.Needs{Root: true, Capabilities: []string{"CAP_SYS_ADMIN"}, Devices: []string{"/dev/fuse"}, HostMounts: true}
	u := mustUnit(t, PluginOptions{Name: "juicefs", Side: "node", Needs: node, Config: "c.json"})
	for _, want := range []string{
		"ExecStart=/usr/local/bin/kevaso-plugin-juicefs node --socket /run/kevaso-plugins/juicefs/node.sock --config %d/config",
		"CapabilityBoundingSet=CAP_SYS_ADMIN\n", "AmbientCapabilities=\n", "NoNewPrivileges=yes",
		"DevicePolicy=closed\n", "DeviceAllow=/dev/fuse rw\n", "SystemCallFilter=@system-service @mount\n",
		"KillMode=process\n", "UMask=0022\n", "RestrictNamespaces=yes", "RuntimeDirectory=kevaso-plugins/juicefs\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	// Anything that makes a mount namespace would hide its mounts from kevasod and the runtimes.
	for _, never := range []string{"DynamicUser", "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "ReadWritePaths",
		"ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups", "ProtectHostname", "ProtectProc",
		"ProcSubset", "PrivateMounts", "~@privileged"} {
		if strings.Contains(u, never) {
			t.Errorf("host-mounts unit has %s:\n%s", never, u)
		}
	}
	// A root side that mounts privately (the JuiceFS controller side) keeps its own namespace.
	ctl := kplugin.Needs{Root: true, Capabilities: []string{"CAP_SYS_ADMIN"}, Devices: []string{"/dev/fuse"}, WritePaths: []string{"/var/lib/kevaso-provider-juicefs"}}
	c := mustUnit(t, PluginOptions{Name: "juicefs", Needs: ctl})
	// …and systemd makes its state folder before the namespace: a writable path that isn't there
	// fails the unit (status 226/NAMESPACE, as on the first real install).
	for _, want := range []string{"ProtectSystem=strict", "ReadWritePaths=/var/lib/kevaso-provider-juicefs\n", "DeviceAllow=/dev/fuse rw", "UMask=0077",
		"StateDirectory=kevaso-provider-juicefs\n", "StateDirectoryMode=0700\n"} {
		if !strings.Contains(c, want) {
			t.Errorf("controller unit lacks %q:\n%s", want, c)
		}
	}
	// …and sees /proc/sys: juicefs panics without /proc/sys/kernel/osrelease (first real install).
	for _, never := range []string{"PrivateDevices", "KillMode", "DynamicUser", "ProcSubset"} {
		if strings.Contains(c, never) {
			t.Errorf("controller unit has %s:\n%s", never, c)
		}
	}
	// Capabilities without root: a dynamic user holding just those.
	d := mustUnit(t, PluginOptions{Name: "bgp", Side: "node", Needs: kplugin.Needs{Capabilities: []string{"CAP_NET_ADMIN"}}})
	if !strings.Contains(d, "DynamicUser=yes") || !strings.Contains(d, "AmbientCapabilities=CAP_NET_ADMIN\n") || !strings.Contains(d, "CapabilityBoundingSet=CAP_NET_ADMIN\n") {
		t.Errorf("dynamic user with a capability:\n%s", d)
	}
}

// The installer reads the manifest, shows the operator what the side gets, and refuses
// privileges unless granted (--yes).
func TestPluginManifestGrant(t *testing.T) {
	dir := t.TempDir()
	mf := filepath.Join(dir, "kevaso-plugin.json")
	_ = os.WriteFile(mf, []byte(`{"name":"juicefs","node":{"root":true,"capabilities":["CAP_SYS_ADMIN"],"devices":["/dev/fuse"],"hostMounts":true}}`), 0o644)
	o, err := parsePlugin([]string{"root@h", "--name", "juicefs", "--binary", "b", "--side", "node", "--manifest", mf}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := readManifest(&o); err != nil || !o.Needs.HostMounts {
		t.Fatalf("%+v %v", o.Needs, err)
	}
	var out bytes.Buffer
	if err := grantNeeds(o, nil, nil, &out); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("privileges without --yes: %v", err)
	}
	for _, want := range []string{"runs as root", "capabilities: CAP_SYS_ADMIN", "devices: /dev/fuse", "the host's mount namespace"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("shown to the operator, lacks %q:\n%s", want, out.String())
		}
	}
	o.Yes = true
	if err := grantNeeds(o, nil, nil, &out); err != nil {
		t.Fatal(err)
	}
	ctl := o
	ctl.Side, ctl.Yes = "", false
	if err := readManifest(&ctl); err != nil || ctl.Needs.Privileged() || grantNeeds(ctl, nil, nil, &out) != nil {
		t.Fatalf("the controller side asks for nothing: %+v %v", ctl.Needs, err)
	}
	other := o
	other.Name = "linode"
	if err := readManifest(&other); err == nil {
		t.Fatal("another plugin's manifest")
	}
	for _, bad := range []string{
		`{"name":"x","node":{"hostMounts":true}}`,                                 // host mounts without root
		`{"name":"x","node":{"devices":["/etc/passwd"]}}`,                         // not a device
		`{"name":"x","node":{"capabilities":["sys_admin"]}}`,                      // not a capability's name
		`{"name":"x","node":{"socket":"other.sock"}}`,                             // kevasod wouldn't find it
		`{"name":"x","node":{"root":true,"hostMounts":true,"writePaths":["/x"]}}`, // nothing is read-only then
		`{"name":"x","node":{"privileged":true}}`,                                 // a need this kvoadm doesn't know
	} {
		if _, err := kplugin.ParseManifest([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// Both sides on one host (a control plane that is also a worker) each get a unit of their own:
// installing the node side used to overwrite the controller side's unit, and removing either side
// took the other's program and credentials with it.
func TestPluginSidesHaveTheirOwnUnits(t *testing.T) {
	c, n := PluginUnitName("hostdir", "controller"), PluginUnitName("hostdir", "node")
	if c == n {
		t.Fatalf("both sides are %s", c)
	}
	if c != "kevaso-plugin-hostdir.service" || n != "kevaso-plugin-hostdir-node.service" {
		t.Errorf("units: %s %s", c, n)
	}
	rm := PluginRemoveScript("hostdir", "node")
	if !strings.Contains(rm, "disable --now 'kevaso-plugin-hostdir-node.service'") || strings.Contains(rm, "disable --now 'kevaso-plugin-hostdir.service'") {
		t.Errorf("removing the node side: %s", rm)
	}
	if !strings.Contains(rm, "if [ ! -e /etc/systemd/system/'kevaso-plugin-hostdir.service' ]; then rm -f /usr/local/bin/'kevaso-plugin-hostdir'") {
		t.Errorf("the program goes while the controller side still runs: %s", rm)
	}
}

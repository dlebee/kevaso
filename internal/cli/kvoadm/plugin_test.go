package kvoadm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kplugin"
)

func TestPluginUnit(t *testing.T) {
	u := PluginUnit(PluginOptions{Name: "linode", Creds: map[string]string{"token": "/x"}, Config: "c.json"})
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
	n := PluginUnit(PluginOptions{Name: "linode", Side: "node"})
	for _, want := range []string{"ExecStart=/usr/local/bin/kevaso-plugin-linode node --socket /run/kevaso-plugins/linode/node.sock\n",
		"RuntimeDirectory=kevaso-plugins/linode\n", "DynamicUser=yes", "ProtectSystem=strict"} {
		if !strings.Contains(n, want) {
			t.Errorf("node side unit lacks %q:\n%s", want, n)
		}
	}
	if strings.Contains(n, "LoadCredential") || strings.Contains(n, "KillMode") {
		t.Errorf("node side unit:\n%s", n)
	}
	if _, err := parsePlugin([]string{"root@h", "--name", "linode", "--binary", "b", "--credential", "token"}, true); err == nil {
		t.Error("a credential without a file")
	}
}

// What a JuiceFS-like node side asks for (root, /dev/fuse, the host's mount namespace) is exactly
// what its unit grants, and nothing that would put its mounts in a namespace of its own.
func TestPrivilegedPluginUnit(t *testing.T) {
	node := kplugin.Needs{Root: true, Capabilities: []string{"CAP_SYS_ADMIN"}, Devices: []string{"/dev/fuse"}, HostMounts: true}
	u := PluginUnit(PluginOptions{Name: "juicefs", Side: "node", Needs: node, Config: "c.json"})
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
	c := PluginUnit(PluginOptions{Name: "juicefs", Needs: ctl})
	for _, want := range []string{"ProtectSystem=strict", "ReadWritePaths=/var/lib/kevaso-provider-juicefs\n", "DeviceAllow=/dev/fuse rw", "UMask=0077"} {
		if !strings.Contains(c, want) {
			t.Errorf("controller unit lacks %q:\n%s", want, c)
		}
	}
	for _, never := range []string{"PrivateDevices", "KillMode", "DynamicUser"} {
		if strings.Contains(c, never) {
			t.Errorf("controller unit has %s:\n%s", never, c)
		}
	}
	// Capabilities without root: a dynamic user holding just those.
	d := PluginUnit(PluginOptions{Name: "bgp", Side: "node", Needs: kplugin.Needs{Capabilities: []string{"CAP_NET_ADMIN"}}})
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
	if err := grantNeeds(o, &out); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("privileges without --yes: %v", err)
	}
	for _, want := range []string{"runs as root", "capabilities: CAP_SYS_ADMIN", "devices: /dev/fuse", "the host's mount namespace"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("shown to the operator, lacks %q:\n%s", want, out.String())
		}
	}
	o.Yes = true
	if err := grantNeeds(o, &out); err != nil {
		t.Fatal(err)
	}
	ctl := o
	ctl.Side, ctl.Yes = "", false
	if err := readManifest(&ctl); err != nil || ctl.Needs.Privileged() || grantNeeds(ctl, &out) != nil {
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

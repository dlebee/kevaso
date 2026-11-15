package kplugin

import (
	"strings"
	"testing"
)

// K-039: a manifest's write paths are folders the plugin is given. Only the plugin's own folder,
// under a root meant for plugin data, may be asked for; anything else (a system folder, Kevaso's
// own state, another plugin's folder, a parent of either, a path that isn't clean) is refused.
func TestWritePathsAreThePluginsOwnFolders(t *testing.T) {
	for _, ok := range []string{
		"/var/lib/kevaso-plugin-x", "/var/cache/kevaso-plugin-x", "/var/log/kevaso-plugin-x",
		"/var/lib/kevaso-provider-x", "/var/cache/kevaso-provider-x", "/var/log/kevaso-provider-x",
		"/srv/x",
	} {
		if err := WritePathProblem("x", ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"/", "/etc", "/etc/kevaso", "/etc/kevaso/plugins/x", "/var", "/var/lib", "/var/lib/kevaso",
		"/var/lib/kevaso/volumes", "/var/lib/kevaso-install", "/var/lib/kevaso-storage.img", "/var/lib/private",
		"/var/lib/kevaso-plugin-y", "/var/lib/kevaso-provider-y", "/srv/y", "/srv", // another plugin's, or the root itself
		"/var/lib/kevaso-plugin-x/sub",       // deeper: the plugin owns the folder above, it could make it a symlink
		"/var/lib/kevaso-plugin-x/../kevaso", // not clean
		"/var/lib/kevaso-plugin-x/",          // not clean
		"/var/lib//kevaso-plugin-x",          // not clean
		"var/lib/kevaso-plugin-x",            // relative
		"/var/lib/kevaso-plugin-x\n",         // a newline in a unit line
		"/var/lib/kevaso-plugin-x /etc",      // two paths in one ReadWritePaths= line
		"/run/kevaso-plugins/x", "/usr/local/bin", "/root", "/home", "/boot", "/dev", "/proc", "/sys", "/tmp",
		"/var/lib/kevaso-plugin-", "/var/lib/kevaso-plugin-x-node", // K-047's shape: another name's folder
	} {
		if err := WritePathProblem("x", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Every hostile manifest is refused when it is read, and a write path counts as a privilege the
// operator must grant (it used to install with nothing asked).
func TestHostileManifests(t *testing.T) {
	for _, bad := range []string{
		`{"name":"x","controller":{"writePaths":["/var/lib/kevaso"]}}`,
		`{"name":"x","controller":{"writePaths":["/etc"]}}`,
		`{"name":"x","node":{"writePaths":["/var/lib"]}}`,
		`{"name":"x","node":{"writePaths":["/var/lib/kevaso-plugin-x","/var/lib/kevaso-plugin-y"]}}`,
		`{"name":"x","node":{"writePaths":["/var/lib/kevaso-plugin-x/../../../etc"]}}`,
		`{"name":"x","node":{"writePaths":["/srv/x/data"]}}`,
		`{"name":"x","node":{"writePaths":["/var/lib/private/kevaso-plugin-x"]}}`,
	} {
		if _, err := ParseManifest([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	m, err := ParseManifest([]byte(`{"name":"x","controller":{"writePaths":["/var/lib/kevaso-plugin-x"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Controller.Privileged() {
		t.Error("a write path is not counted as something to grant")
	}
	if s := strings.Join(m.Controller.Summary(), "\n"); !strings.Contains(s, "/var/lib/kevaso-plugin-x") {
		t.Errorf("the summary does not name the folder:\n%s", s)
	}
	if err := m.Controller.Check("y", "controller"); err == nil {
		t.Error("plugin y's needs accepted plugin x's folder")
	}
}

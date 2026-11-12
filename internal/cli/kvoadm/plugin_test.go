package kvoadm

import (
	"strings"
	"testing"
)

func TestPluginUnit(t *testing.T) {
	u := PluginUnit(PluginOptions{Name: "linode", Creds: map[string]string{"token": "/x"}, Config: "c.json"})
	for _, want := range []string{
		"ExecStart=/usr/local/bin/kevaso-plugin-linode serve --socket /run/kevaso-plugins/linode/plugin.sock --config %d/config",
		"DynamicUser=yes", "RuntimeDirectory=kevaso-plugins/linode",
		"LoadCredential=token:/etc/kevaso/plugins/linode/token", "LoadCredential=config:/etc/kevaso/plugins/linode/config.json",
		"CapabilityBoundingSet=\n", "NoNewPrivileges=yes",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	n := PluginUnit(PluginOptions{Name: "linode", Side: "node"})
	if !strings.Contains(n, "ExecStart=/usr/local/bin/kevaso-plugin-linode node\n") || strings.Contains(n, "RuntimeDirectory") || strings.Contains(n, "LoadCredential") {
		t.Errorf("node side unit:\n%s", n)
	}
	if _, err := parsePlugin([]string{"root@h", "--name", "linode", "--binary", "b", "--credential", "token"}, true); err == nil {
		t.Error("a credential without a file")
	}
}

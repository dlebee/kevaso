package integration

import (
	"testing"

	"kevaso.com/core/internal/admconfig"
)

// adminCluster writes kvoadm's cluster folder the way kvoadm init does (the cluster-admin
// certificate in KVOADM_HOME/clusters/NAME/) and points kvoadm at it.
func adminCluster(t *testing.T, name, server string, ca, cert, key []byte) *admconfig.Config {
	t.Helper()
	root := t.TempDir()
	t.Setenv(admconfig.EnvHome, root)
	t.Setenv(admconfig.EnvCluster, "")
	kc := admconfig.New(root, name)
	kc.Shared.Server = server
	if err := kc.WriteCredentials(ca, cert, key); err != nil {
		t.Fatal(err)
	}
	if err := kc.Save(); err != nil {
		t.Fatal(err)
	}
	return kc
}

package plugins

import (
	"encoding/json"
	"path/filepath"
	"regexp"
)

// ClusterSecretsFile is the root-only record of ClusterSecret names a plugin's controller
// side loads. ClusterSecretsNodeFile is the node side's. kvoadm plugin install writes one,
// kevasod reads it and fills each name at DIR/PLUGIN/NAME (the unit's LoadCredential path).
const (
	ClusterSecretsFile     = "cluster-secrets.json"
	ClusterSecretsNodeFile = "cluster-secrets-node.json"
)

// clusterSecretName is a credential name systemd can load and a path segment kevasod can
// join under the plugin's directory. "config" is the unit's settings file, not a secret.
var clusterSecretName = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// ValidClusterSecretName reports whether name may be recorded for a plugin.
func ValidClusterSecretName(name string) bool {
	return name != "config" && clusterSecretName.MatchString(name)
}

// ClusterSecretsPath is where side's names are recorded (side "node", or the controller side).
func ClusterSecretsPath(root, plugin, side string) string {
	file := ClusterSecretsFile
	if side == "node" {
		file = ClusterSecretsNodeFile
	}
	return filepath.Join(root, plugin, file)
}

type clusterSecretRecord struct {
	Names []string `json:"names"`
}

// EncodeClusterSecrets is the on-disk record: the names only, never a value.
func EncodeClusterSecrets(names []string) ([]byte, error) {
	b, err := json.Marshal(clusterSecretRecord{Names: names})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeClusterSecrets reads a record from EncodeClusterSecrets.
func DecodeClusterSecrets(b []byte) ([]string, error) {
	var r clusterSecretRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return r.Names, nil
}

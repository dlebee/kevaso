package kvoadm

import (
	"os"
	"testing"
)

// K-045: internal/operators refuses a package whose roles write a built-in kind's status unless
// the operator names exactly those (operators.InstallOptions.StatusWrites); kvoadm plugin install
// --package has no flag to name them yet. That flag is operator.go's (host lane): parseOperator
// takes `--allow-status silos/status,ips/status` (comma-separated), and operatorCmd passes it as
// InstallOptions.StatusWrites. Until then such a package can't be installed (the refusal names
// the flag). Drop the skip when the flag lands (KEVASO_K045=1 runs it now).
func TestOperatorInstallTakesAllowStatus(t *testing.T) {
	if os.Getenv("KEVASO_K045") == "" {
		t.Skip("K-045: --allow-status is operator.go's (host lane); see the comment")
	}
	if _, err := parseOperator([]string{"--package", "dir", "--allow-status", "silos/status,ips/status", "root@cp1"}); err != nil {
		t.Fatalf("--allow-status: %v", err)
	}
}

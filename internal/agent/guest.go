package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// The guest helper (design §8.2: "helpers inside the VM are clients, never trusted"): kvo-guest
// talks to the broker over vsock for the silo's programs and writes file and env deliveries. It
// can't raise what the silo may have: every decision stays on the host and the control plane.

const guestUnit = `[Unit]
Description=Kevaso guest helper: secrets from the host's broker into files, kept up to date
After=local-fs.target

[Service]
ExecStart=/usr/local/bin/kvo-guest sync
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`

// prepareScript installs the helper (from stdin) and its unit, writes the deliveries once (so
// init steps have them), then keeps them up to date in the background.
const prepareScript = `set -e
mkdir -p /usr/local/bin /var/lib/kevaso-guest
cat > /usr/local/bin/kvo-guest.new
chmod 0755 /usr/local/bin/kvo-guest.new
mv /usr/local/bin/kvo-guest.new /usr/local/bin/kvo-guest
printf '%s' "$2" > /etc/systemd/system/kvo-guest.service
systemctl daemon-reload
systemctl enable kvo-guest.service >/dev/null 2>&1
if [ -n "$3" ]; then
  mkdir -p /usr/local/share/ca-certificates
  printf '%s' "$3" > /usr/local/share/ca-certificates/kevaso-egress.crt
  update-ca-certificates >/dev/null 2>&1 || true
  grep -q '^NODE_EXTRA_CA_CERTS=' /etc/environment 2>/dev/null || printf 'NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/kevaso-egress.crt\nREQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\nSSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\n' >> /etc/environment
fi
/usr/local/bin/kvo-guest sync --once
systemctl restart kvo-guest.service
printf '%s' "$1" > /var/lib/kevaso-guest/version
`

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// prepareGuest puts the helper in the silo once per agent run (and again after the binary changed).
func (a *Agent) prepareGuest(ctx context.Context, rt kri.Runtime, s *v1.Silo) error {
	if a.GuestHelper == "" {
		return nil
	}
	if _, ok := a.prepared.Load(s.UID); ok {
		return nil
	}
	version, err := hashFile(a.GuestHelper)
	if err != nil {
		return fmt.Errorf("guest helper: %w", err)
	}
	if len(a.GuestCA) > 0 { // a new egress CA re-runs the setup too
		sum := sha256.Sum256(a.GuestCA)
		version += "-" + hex.EncodeToString(sum[:4])
	}
	var out bytes.Buffer
	if code, err := rt.Exec(ctx, idOf(s), kri.ExecRequest{Command: []string{"cat", "/var/lib/kevaso-guest/version"}, Stdout: &out}); err == nil && code == 0 &&
		strings.TrimSpace(out.String()) == version && a.guestServiceActive(ctx, rt, s) {
		a.prepared.Store(s.UID, struct{}{})
		return nil
	}
	f, err := os.Open(a.GuestHelper)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	out.Reset()
	code, err := rt.Exec(ctx, idOf(s), kri.ExecRequest{Command: []string{"sh", "-c", prepareScript, "sh", version, guestUnit, string(a.GuestCA)}, Stdin: f, Stdout: &out, Stderr: &out})
	if err != nil {
		return fmt.Errorf("installing the guest helper: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("installing the guest helper: exit %d: %s", code, tail(out.String(), 300))
	}
	a.log("guest helper %s in %s/%s", version, s.Namespace, s.Name)
	a.prepared.Store(s.UID, struct{}{})
	return nil
}

func (a *Agent) guestServiceActive(ctx context.Context, rt kri.Runtime, s *v1.Silo) bool {
	code, err := rt.Exec(ctx, idOf(s), kri.ExecRequest{Command: []string{"systemctl", "is-active", "--quiet", "kvo-guest.service"}})
	return err == nil && code == 0
}

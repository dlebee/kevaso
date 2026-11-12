package kvoadm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"kevaso.com/core/api/client"
)

// kmsCmd: the master key for secrets, on a control-plane host, over SSH (the KMS is managed only
// through the host's root-only admin socket, never over the API):
//
//	kvoadm kms rotate [USER@]ADDRESS [--ssh-key PATH] [--ssh-port N] [--host-key SHA256:…] [--new-recovery-key]
//
// rotate makes a new master key, re-wraps every secret's data key (values aren't re-encrypted) and
// retires the old key; the recovery key stays the same. --new-recovery-key also replaces the
// recovery key, for when it leaked: the new master key is escrowed only to the new one, so the
// leaked key opens nothing backed up from then on.
func kmsCmd(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	usage := errors.New("usage: kvoadm kms rotate [USER@]ADDRESS [--ssh-key PATH] [--ssh-port N] [--host-key SHA256:…] [--new-recovery-key]")
	if len(args) < 2 || args[0] != "rotate" {
		return usage
	}
	o := InitOptions{SSHPort: 22}
	newRK := false
	var target string
	for i := 1; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "--ssh-key":
			o.SSHKey, err = next()
		case "--host-key":
			o.HostKey, err = next()
		case "--ssh-port":
			var v string
			if v, err = next(); err == nil {
				o.SSHPort, err = strconv.Atoi(v)
			}
		case "--new-recovery-key":
			newRK = true
		default:
			if strings.HasPrefix(a, "-") || target != "" {
				return usage
			}
			target = a
		}
		if err != nil {
			return err
		}
	}
	if target == "" {
		return usage
	}
	o.User, o.Address = "root", target
	if u, a, ok := strings.Cut(target, "@"); ok {
		o.User, o.Address = u, a
	}
	if o.SSHKey == "" { // the key kvoadm installed when it set the host up
		if h, err := os.UserHomeDir(); err == nil {
			if p := filepath.Join(h, ".kevaso", "ssh", "id_ed25519"); fileExists(p) {
				o.SSHKey = p
			}
		}
	}
	conn, _, err := dialHost(ctx, o, bufio.NewReader(stdin), stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	cmd := "kevasod admin kms-rotate"
	if newRK {
		cmd += " --new-recovery-key"
	}
	resp, err := conn.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	var r client.KMSRotation
	if err := json.Unmarshal(lastLine(resp), &r); err != nil {
		return fmt.Errorf("kms-rotate answer: %w", err)
	}
	_, _ = fmt.Fprintf(out, "→ new master key %s; %d secrets re-wrapped, the old key retired\n", r.KeyID, r.Rewrapped)
	if !newRK {
		_, _ = fmt.Fprintln(out, "→ the recovery key is unchanged")
		return nil
	}
	_, _ = fmt.Fprintf(out, `
New recovery key for secrets (shown only now, keep it offline; the old one no longer opens
anything backed up from now on):

    %s

Backups taken before this still open with the old key, and hold the secret values of then:
  1. take a fresh backup and destroy the older ones;
  2. rotate the secrets that matter (kvo secret set NAME --from-file -).
`, r.RecoveryKey)
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

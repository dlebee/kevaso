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
	"time"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/backup"
	"kevaso.com/core/internal/kms"
)

// backupCmd: a backup of a control plane, over SSH, to a file here:
//
//	kvoadm backup [USER@]ADDRESS --output FILE [--ssh-key PATH] [--ssh-port N] [--host-key SHA256:…]
//
// The file is sealed to the recovery key: it opens nothing without it, so it can sit in ordinary
// storage. kvoadm init --restore FILE puts it on a fresh machine.
func backupCmd(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	o, output, err := parseBackup(args)
	if err != nil {
		return err
	}
	conn, _, err := dialHost(ctx, o, bufio.NewReader(stdin), stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	resp, err := conn.Run(ctx, "kevasod admin backup", nil)
	if err != nil {
		return err
	}
	var b client.Backup
	if err := json.Unmarshal(lastLine(resp), &b); err != nil || len(b.Backup) == 0 {
		return fmt.Errorf("backup answer: %v", err)
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b.Backup); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "→ backup written to %s (%d KiB), sealed to your recovery key\n", output, (len(b.Backup)+1023)/1024)
	return nil
}

// readRecoveryKey asks for the recovery key: hidden, in a terminal; else the first line of stdin
// (read byte by byte, so later answers on stdin are left for the next question).
func readRecoveryKey(stdin io.Reader, out io.Writer) (kms.RecoveryKey, error) {
	var s string
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		in := huh.NewInput().Title("Recovery key").Description("The KVR1-… key kvoadm init printed. It opens the backup.").
			EchoMode(huh.EchoModePassword).Value(&s)
		if err := huh.NewForm(huh.NewGroup(in)).WithInput(f).WithOutput(out).Run(); err != nil {
			return nil, err
		}
	} else {
		var b [1]byte
		var line []byte
		for {
			n, err := stdin.Read(b[:])
			if n == 1 && b[0] != '\n' {
				line = append(line, b[0])
				continue
			}
			if n == 1 || err != nil {
				if len(line) == 0 && err != nil {
					return nil, errors.New("the recovery key: none on stdin")
				}
				break
			}
		}
		s = string(line)
	}
	return kms.ParseRecoveryKey(strings.TrimSpace(s))
}

// prepareRestore opens the backup here, before touching the machine: a wrong key or a damaged file
// stops kvoadm init --restore before anything changes. The cluster and host name come from it
// unless given.
func prepareRestore(o *InitOptions, stdin io.Reader, out io.Writer) ([]byte, error) {
	blob, err := os.ReadFile(o.Restore)
	if err != nil {
		return nil, err
	}
	rk, err := readRecoveryKey(stdin, out)
	if err != nil {
		return nil, err
	}
	m, _, err := backup.Open(blob, rk)
	if err != nil {
		return nil, err
	}
	if !o.clusterGiven {
		o.Cluster = m.Cluster
	}
	if !o.nameGiven {
		o.Name = m.Host
	}
	_, _ = fmt.Fprintf(out, "→ backup of cluster %q (control plane %s), taken %s: the recovery key opens it\n",
		m.Cluster, m.Host, m.Created.Local().Format(time.DateTime))
	return json.Marshal(client.RestoreRequest{Backup: blob, RecoveryKey: rk.String()})
}

// parseBackup reads kvoadm backup's arguments: the target (its login, root by default), the
// output file (which must not exist) and the SSH options.
func parseBackup(args []string) (InitOptions, string, error) {
	usage := errors.New("usage: kvoadm backup [USER@]ADDRESS --output FILE [--ssh-key PATH] [--ssh-port N] [--host-key SHA256:…]")
	o := InitOptions{SSHPort: 22}
	var target, output string
	for i := 0; i < len(args); i++ {
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
		case "--output", "-o":
			output, err = next()
		case "--ssh-key":
			o.SSHKey, err = next()
		case "--host-key":
			o.HostKey, err = next()
		case "--ssh-port":
			var v string
			if v, err = next(); err == nil {
				o.SSHPort, err = strconv.Atoi(v)
			}
		case "--accept-host-key-on-first-use":
			o.HostKeyFirstUse = true
		default:
			if strings.HasPrefix(a, "-") || target != "" {
				return o, "", usage
			}
			target = a
		}
		if err != nil {
			return o, "", err
		}
	}
	if target == "" || output == "" {
		return o, "", usage
	}
	if _, err := os.Stat(output); err == nil {
		return o, "", fmt.Errorf("%s exists: give a new file name (backups are never overwritten)", output)
	}
	o.User, o.Address = splitTarget(target)
	if o.SSHKey == "" {
		if h, err := os.UserHomeDir(); err == nil {
			if p := filepath.Join(h, ".kevaso", "ssh", "id_ed25519"); fileExists(p) {
				o.SSHKey = p
			}
		}
	}
	return o, output, nil
}

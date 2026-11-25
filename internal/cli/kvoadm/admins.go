package kvoadm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/internal/admconfig"
	"kevaso.com/core/internal/sshboot"
)

// The cluster's administrators, kept in the shared cluster.yaml with their SSH public keys, and put
// on every host's authorized_keys (for the user kvoadm logs in as there) inside a block kvoadm owns:
//
//	kvoadm admins                                  who they are
//	kvoadm admins add NAME KEY.pub|"ssh-ed25519 …"…  add one, or replace their keys
//	kvoadm admins remove NAME
//	kvoadm admins sync [--dry-run]                 every host's block made to match the file
//
// Adding an admin is a commit of cluster.yaml and one sync. A sync never removes the key it is
// connected with (it refuses: you'd lock yourself out), and lines outside its block are left alone.

const (
	adminsBegin = "# kevaso-admins begin: managed by kvoadm admins sync (edit the cluster's cluster.yaml instead)"
	adminsEnd   = "# kevaso-admins end"
)

func adminsCmd(ctx context.Context, args []string, stdin io.Reader, out io.Writer) error {
	rest, cluster, err := takeCluster(args)
	if err != nil {
		return err
	}
	kc, err := loadCluster(cluster)
	if err != nil {
		return err
	}
	if len(rest) == 0 || rest[0] == "list" {
		return listAdmins(kc, out)
	}
	switch rest[0] {
	case "add":
		if len(rest) < 3 {
			return errors.New("admins add NAME KEY.pub|\"ssh-ed25519 AAAA…\"…")
		}
		var keys []string
		for _, k := range rest[2:] {
			line, err := readPublicKey(k)
			if err != nil {
				return err
			}
			keys = append(keys, line)
		}
		if err := kc.Update(func(c *admconfig.Config) error { return c.SetAdmin(rest[1], keys...) }); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "→ admin %s: %d key(s) in %s. Commit it, then: kvoadm admins sync\n", rest[1], len(keys), kc.SharedPath())
		return nil
	case "remove":
		if len(rest) != 2 {
			return errors.New("admins remove NAME")
		}
		if err := kc.Update(func(c *admconfig.Config) error {
			if !c.RemoveAdmin(rest[1]) {
				return fmt.Errorf("no admin %s in %s", rest[1], c.SharedPath())
			}
			return nil
		}); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "→ admin %s removed from %s. Commit it, then: kvoadm admins sync (it takes their keys off the hosts)\n", rest[1], kc.SharedPath())
		return nil
	case "sync":
		dry := slices.Contains(rest[1:], "--dry-run")
		return syncAdmins(ctx, kc, dry, stdin, out)
	}
	return fmt.Errorf("unknown admins command %q (list, add, remove, sync)", rest[0])
}

func listAdmins(kc *admconfig.Config, out io.Writer) error {
	if len(kc.Shared.Admins) == 0 {
		_, _ = fmt.Fprintf(out, "no admins in %s (kvoadm admins add NAME KEY.pub)\n", kc.SharedPath())
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ADMIN\tKEYS\tYOU")
	for _, a := range kc.Shared.Admins {
		var fps []string
		for _, k := range a.SSHKeys {
			if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err == nil {
				fps = append(fps, ssh.FingerprintSHA256(pk))
			}
		}
		you := ""
		if a.Name == kc.Local.Admin {
			you = "*"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", a.Name, strings.Join(fps, ", "), you)
	}
	return tw.Flush()
}

// syncAdmins makes every host's kvoadm block match the shared file.
func syncAdmins(ctx context.Context, kc *admconfig.Config, dry bool, stdin io.Reader, out io.Writer) error {
	c, err := kc.Client()
	if err != nil {
		return err
	}
	hosts, err := listHosts(ctx, c)
	if err != nil {
		return err
	}
	block := AdminsBlock(kc.Shared.Admins)
	var failed []string
	for i := range hosts {
		h := &hosts[i]
		conn, o, err := dialHostAt(ctx, kc, h, InitOptions{}, stdin, out)
		if err != nil {
			failed = append(failed, h.Name+": "+firstLine(err.Error()))
			continue
		}
		changed, err := syncAdminsOn(ctx, conn, o, block, dry)
		_ = conn.Close()
		switch {
		case err != nil:
			failed = append(failed, h.Name+": "+firstLine(err.Error()))
		case dry && changed:
			_, _ = fmt.Fprintf(out, "→ %s: would update %s's authorized_keys\n", h.Name, o.User)
		case changed:
			_, _ = fmt.Fprintf(out, "→ %s: %s's authorized_keys updated (%d admin key(s))\n", h.Name, o.User, keyCount(kc.Shared.Admins))
		default:
			_, _ = fmt.Fprintf(out, "→ %s: up to date\n", h.Name)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d hosts not synced:\n  %s", len(failed), len(hosts), strings.Join(failed, "\n  "))
	}
	return nil
}

// syncAdminsOn puts block on the host's authorized_keys for the login user, unless that would drop
// the key kvoadm is connected with. It reports whether the file changes.
func syncAdminsOn(ctx context.Context, conn *sshboot.Conn, o InitOptions, block string, dry bool) (bool, error) {
	return syncAdminsWith(ctx, conn, o, block, dry)
}

func syncAdminsWith(ctx context.Context, conn hostRunner, o InitOptions, block string, dry bool) (bool, error) {
	user := o.User
	if user == "" {
		user = "root"
	}
	cur, err := conn.Run(ctx, AuthorizedKeysRead(user), nil)
	if err != nil {
		return false, err
	}
	next := ReplaceAdminsBlock(string(cur), block)
	if next == string(cur) {
		return false, nil
	}
	if own := publicKeyOf(o.SSHKey); own != "" && !authorizes(next, own) {
		return false, fmt.Errorf("refusing: the new authorized_keys for %s wouldn't hold the key kvoadm logs in with (%s): add yourself to the admins first", user, o.SSHKey)
	}
	if dry {
		return true, nil
	}
	if _, err := conn.Run(ctx, AuthorizedKeysWrite(user), []byte(next)); err != nil {
		return false, err
	}
	return true, nil
}

// AdminsBlock is the block of authorized_keys lines for the admins, each key tagged with its
// admin's name. Pure.
func AdminsBlock(admins []admconfig.Admin) string {
	var b strings.Builder
	b.WriteString(adminsBegin + "\n")
	for _, a := range admins {
		for _, k := range a.SSHKeys {
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k))
			if err != nil {
				continue
			}
			line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
			b.WriteString(line + " kevaso-admin:" + a.Name + "\n")
		}
	}
	b.WriteString(adminsEnd + "\n")
	return b.String()
}

// ReplaceAdminsBlock swaps kvoadm's block in an authorized_keys file for block, or appends it.
// Every other line stays as it was. Pure.
func ReplaceAdminsBlock(file, block string) string {
	lines := strings.SplitAfter(file, "\n")
	var out strings.Builder
	in, placed := false, false
	for _, l := range lines {
		t := strings.TrimRight(l, "\n")
		switch {
		case t == adminsBegin:
			in = true
			if !placed {
				out.WriteString(block)
				placed = true
			}
		case t == adminsEnd && in:
			in = false
		case !in:
			out.WriteString(l)
		}
	}
	s := out.String()
	if !placed {
		if s != "" && !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		s += block
	}
	return s
}

// authorizes reports whether an authorized_keys text holds the public key (an authorized_keys
// line). Pure.
func authorizes(file, pub string) bool {
	want, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	if err != nil {
		return false
	}
	for _, l := range strings.Split(file, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err == nil && bytes.Equal(pk.Marshal(), want.Marshal()) {
			return true
		}
	}
	return false
}

// AuthorizedKeysRead prints the login user's authorized_keys (nothing when there is none). It
// runs as root (kvoadm's connection uses sudo for another login).
func AuthorizedKeysRead(user string) string {
	return homeOf(user) + "[ -n \"$h\" ] || exit 3; cat \"$h/.ssh/authorized_keys\" 2>/dev/null; true"
}

// homeOf sets $h to user's home folder: getent on Linux, the directory service on a Mac (macOS
// has no getent).
func homeOf(user string) string {
	u := sshboot.Quote(user)
	return "h=$(getent passwd " + u + " 2>/dev/null | cut -d: -f6); " +
		"[ -n \"$h\" ] || h=$(dscl . -read /Users/" + u + " NFSHomeDirectory 2>/dev/null | awk '{print $2}'); "
}

// AuthorizedKeysWrite replaces the login user's authorized_keys with stdin, atomically, owned by
// the user, mode 0600.
func AuthorizedKeysWrite(user string) string {
	u := sshboot.Quote(user)
	return "set -e; " + homeOf(user) + "[ -n \"$h\" ]; g=$(id -g " + u + "); " +
		"install -d -m 0700 -o " + u + " -g \"$g\" \"$h/.ssh\"; t=\"$h/.ssh/authorized_keys.kevaso\"; cat > \"$t\"; " +
		"chown " + u + ":\"$g\" \"$t\"; chmod 0600 \"$t\"; mv \"$t\" \"$h/.ssh/authorized_keys\""
}

func keyCount(admins []admconfig.Admin) int {
	n := 0
	for _, a := range admins {
		n += len(a.SSHKeys)
	}
	return n
}

// readPublicKey is a public key given as a file (KEY.pub) or as the authorized_keys line itself.
func readPublicKey(arg string) (string, error) {
	line := arg
	if !strings.HasPrefix(arg, "ssh-") && !strings.HasPrefix(arg, "ecdsa-") && !strings.HasPrefix(arg, "sk-") {
		b, err := os.ReadFile(arg)
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(string(b))
	}
	if strings.Contains(line, "PRIVATE KEY") {
		return "", fmt.Errorf("%s is a private key: give the public one (.pub)", arg)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
		return "", fmt.Errorf("%s: not an SSH public key", arg)
	}
	return line, nil
}

// publicKeyOf is the authorized_keys line for a private key file: its .pub beside it, else the key
// itself when it has no passphrase. "" when neither works.
func publicKeyOf(privPath string) string {
	if privPath == "" {
		return ""
	}
	if b, err := os.ReadFile(privPath + ".pub"); err == nil {
		if pk, _, _, _, err := ssh.ParseAuthorizedKey(b); err == nil {
			return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
		}
	}
	if b, err := os.ReadFile(privPath); err == nil {
		if s, err := ssh.ParsePrivateKey(b); err == nil {
			return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
		}
	}
	return ""
}

func adminListed(kc *admconfig.Config, name string) bool {
	return slices.ContainsFunc(kc.Shared.Admins, func(a admconfig.Admin) bool { return a.Name == name })
}

// syncAdminsTo puts the admins' keys on one host kvoadm just set up (host add, init), best effort.
func syncAdminsTo(ctx context.Context, kc *admconfig.Config, conn *sshboot.Conn, o InitOptions, say func(string, ...any)) {
	if kc == nil || len(kc.Shared.Admins) == 0 {
		return
	}
	if changed, err := syncAdminsOn(ctx, conn, o, AdminsBlock(kc.Shared.Admins), false); err != nil {
		say("admins' keys not put on %s (%v): kvoadm admins sync", o.Address, firstLine(err.Error()))
	} else if changed {
		say("admins' keys on %s's authorized_keys (%d key(s), from %s)", o.User, keyCount(kc.Shared.Admins), kc.SharedPath())
	}
}

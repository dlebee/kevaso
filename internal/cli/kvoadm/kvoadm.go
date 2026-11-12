// Package kvoadm is the operator CLI: `kvoadm init` sets up a fresh machine over SSH, installs the
// control plane on it, and gives you working `kvo` credentials; `kvoadm users` invites people
// (one-time codes for `kvo login`), lists and disables them.
//
//	kvoadm init [USER@]ADDRESS [--name NAME] [--ssh-port 22] [--ssh-key PATH] [--host-key SHA256:…]
//	            [--kevasod PATH] [--api-server URL] [--cluster NAME] [--user NAME]
//	            [--worker [--loop-storage SIZE]]   also run silos on this host (one-host cluster)
//
// Without --ssh-key, the password is asked for once, after the host key is trusted, used for one
// connection, then the machine is switched to key-only and its root password rotated (research
// E016–E017). kevasod is installed only after its signature verifies on the host (E018).
//
//	kvoadm kms rotate [USER@]ADDRESS [--new-recovery-key]
//
// rotates the master key for secrets over SSH (and, with --new-recovery-key, replaces a leaked
// recovery key).
package kvoadm

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"debug/elf"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/sshboot"
)

// Run runs one kvoadm command and returns its exit code.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "host" {
		if err := hostCmd(ctx, args[1:], stdin, stdout); err != nil {
			_, _ = fmt.Fprintln(stderr, "kvoadm:", err)
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "kms" {
		if err := kmsCmd(ctx, args[1:], stdin, stdout); err != nil {
			_, _ = fmt.Fprintln(stderr, "kvoadm:", err)
			return 1
		}
		return 0
	}
	if len(args) > 0 && args[0] == "users" {
		if err := usersCmd(ctx, args[1:], stdout); err != nil {
			_, _ = fmt.Fprintln(stderr, "kvoadm:", err)
			return 1
		}
		return 0
	}
	if len(args) == 0 || args[0] != "init" {
		_, _ = fmt.Fprintln(stderr, "usage: kvoadm init [USER@]ADDRESS [--ssh-key PATH] [--host-key SHA256:…] [--kevasod PATH]\n       kvoadm users invite NAME [--namespace NS [--role editor]] [--group G]… | list | disable NAME\n       kvoadm kms rotate [USER@]ADDRESS [--new-recovery-key]")
		return 2
	}
	o, err := parseInit(args[1:])
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "kvoadm:", err)
		return 2
	}
	if err := initCluster(ctx, o, stdin, stdout); err != nil {
		_, _ = fmt.Fprintln(stderr, "kvoadm:", err)
		return 1
	}
	return 0
}

// InitOptions are kvoadm init's flags.
type InitOptions struct {
	User, Address, Name, SSHKey, HostKey, Kevasod, APIServer, Cluster, UserName, Home string
	SSHPort                                                                           int
	HostKeyFirstUse                                                                   bool   // trust the host key without asking (tests only)
	Worker                                                                            bool   // also install the worker component (one-host cluster)
	LoopStorage                                                                       string // development: back silo disks with a loop file of this size
	Advertise                                                                         string // the address other hosts reach this one at, if not the SSH one
	EgressExtraCA                                                                     string // a PEM file on the host the egress gate also trusts upstream
}

func parseInit(args []string) (InitOptions, error) {
	o := InitOptions{SSHPort: 22, Cluster: "kevaso"}
	var target string
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
		case "--name":
			o.Name, err = next()
		case "--ssh-key":
			o.SSHKey, err = next()
		case "--host-key":
			o.HostKey, err = next()
		case "--kevasod":
			o.Kevasod, err = next()
		case "--api-server":
			o.APIServer, err = next()
		case "--cluster":
			o.Cluster, err = next()
		case "--user":
			o.UserName, err = next()
		case "--ssh-port":
			var v string
			if v, err = next(); err == nil {
				o.SSHPort, err = strconv.Atoi(v)
			}
		case "--accept-host-key-on-first-use":
			o.HostKeyFirstUse = true
		case "--worker":
			o.Worker = true
		case "--loop-storage":
			o.LoopStorage, err = next()
		case "--address":
			o.Advertise, err = next()
		case "--egress-extra-ca":
			o.EgressExtraCA, err = next()
		default:
			if strings.HasPrefix(a, "-") {
				return o, fmt.Errorf("unknown flag %s", a)
			}
			if target != "" {
				return o, fmt.Errorf("one target only (got %q and %q)", target, a)
			}
			target = a
		}
		if err != nil {
			return o, err
		}
	}
	if target == "" {
		return o, errors.New("init needs a target: [USER@]ADDRESS")
	}
	o.User, o.Address = "root", target
	if u, a, ok := strings.Cut(target, "@"); ok {
		o.User, o.Address = u, a
	}
	if o.Name == "" {
		o.Name = strings.ReplaceAll(o.Address, ".", "-")
	}
	if o.UserName == "" {
		if u, err := user.Current(); err == nil {
			o.UserName = strings.ToLower(u.Username)
		}
	}
	if o.Kevasod == "" {
		return o, errors.New("--kevasod PATH is required: a kevasod binary for the host's OS and CPU (release downloads come later)")
	}
	return o, nil
}

// ElfArch maps a Linux binary's machine type to `uname -m` names.
func ElfArch(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s: not a Linux binary: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	switch f.Machine {
	case elf.EM_X86_64:
		return "x86_64", nil
	case elf.EM_AARCH64:
		return "aarch64", nil
	}
	return "", fmt.Errorf("%s: unsupported machine %v", path, f.Machine)
}

// SigningKey loads (or creates) the ed25519 key kvoadm signs binaries with, and its public key as
// PEM for the host to pin. Release binaries will be signed by the project's key instead.
func SigningKey(dir string) (ed25519.PrivateKey, []byte, error) {
	path := filepath.Join(dir, "signing.key")
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, nil, fmt.Errorf("%s: not PEM", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("%s: not an ed25519 key", path)
		}
		return priv, pubPEM(priv), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, nil, err
	}
	return priv, pubPEM(priv), nil
}

func pubPEM(priv ed25519.PrivateKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(priv.Public())
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// SSHKey loads (or creates) kvoadm's own SSH key, which it installs on hosts it sets up.
func SSHKey(dir string) (ssh.Signer, []byte, error) {
	path := filepath.Join(dir, "id_ed25519")
	if b, err := os.ReadFile(path); err == nil {
		s, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, nil, err
		}
		return s, ssh.MarshalAuthorizedKey(s.PublicKey()), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "kvoadm")
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, nil, err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return s, ssh.MarshalAuthorizedKey(s.PublicKey()), nil
}

// Unit is the control plane's systemd unit.
func Unit(o InitOptions) string {
	addr := o.Address
	if o.Advertise != "" {
		addr = o.Advertise
	}
	args := []string{"control-plane", "--name", o.Name, "--address", addr, "--cluster", o.Cluster}
	if o.Advertise != "" && o.Advertise != o.Address {
		args = append(args, "--extra-name", o.Address)
	}
	if o.Worker {
		args = append(args, "--worker", "--runtime", "cloud-hypervisor")
		if o.LoopStorage != "" {
			args = append(args, "--loop-storage", "/var/lib/kevaso-storage.img", "--loop-size", o.LoopStorage)
		}
		if o.EgressExtraCA != "" {
			args = append(args, "--egress-extra-ca", o.EgressExtraCA)
		}
	}
	return `[Unit]
Description=Kevaso control plane (kevasod)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/kevasod ` + strings.Join(args, " ") + `
Restart=always
RestartSec=2
RuntimeDirectory=kevaso
RuntimeDirectoryMode=0700
StateDirectory=kevaso
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`
}

func readLine(r *bufio.Reader) (string, error) {
	s, err := r.ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func initCluster(ctx context.Context, o InitOptions, stdin io.Reader, out io.Writer) error {
	home := o.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		home = filepath.Join(h, ".kevaso")
	}
	say := func(f string, a ...any) { _, _ = fmt.Fprintf(out, "→ "+f+"\n", a...) }
	conn, err := bootstrap(ctx, o, home, stdin, out, say)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.InstallUnit(ctx, "kevasod.service", []byte(Unit(o))); err != nil {
		return err
	}
	say("control plane started (kevasod.service)")

	// 5. Your credentials: the key is made here, only the CSR goes to the host.
	keyPEM, csrPEM, err := client.NewKeyAndCSR(o.UserName)
	if err != nil {
		return err
	}
	resp, err := conn.Run(ctx, "kevasod admin sign-user --name "+sshboot.Quote(o.UserName), csrPEM)
	if err != nil {
		return err
	}
	var cred struct{ Certificate, CA string }
	if err := json.Unmarshal(lastLine(resp), &cred); err != nil {
		return fmt.Errorf("sign-user answer: %w", err)
	}
	server := o.APIServer
	if server == "" {
		server = "https://" + net.JoinHostPort(o.Address, "6443")
	}
	cfgPath := filepath.Join(home, "config.yaml")
	if p := os.Getenv("KVO_CONFIG"); p != "" && o.Home == "" {
		cfgPath = p
	}
	if err := kvoconfig.AddContext(cfgPath, o.Cluster, server, []byte(cred.CA), []byte(cred.Certificate), keyPEM); err != nil {
		return err
	}
	say("kvo context %q written to %s (server %s)", o.Cluster, cfgPath, server)

	// 6. Check it from here, over TLS, the way kvo will.
	c, err := client.NewTLS(server, []byte(cred.CA), []byte(cred.Certificate), keyPEM)
	if err != nil {
		return err
	}
	if err := waitHostReady(ctx, c, o.Name, 2*time.Minute); err != nil {
		return err
	}
	say("host %s is Ready. Try: kvo get hosts", o.Name)

	// 7. The recovery key for secrets: made on the host, shown once, here, and never again.
	if rk, err := conn.Run(ctx, "kevasod admin recovery-key", nil); err == nil {
		var r client.RecoveryKey
		if json.Unmarshal(lastLine(rk), &r) == nil && r.RecoveryKey != "" {
			_, _ = fmt.Fprintf(out, "\nRecovery key for secrets (needed to restore a backup; shown only now, keep it offline):\n\n    %s\n\n", r.RecoveryKey)
		}
	} else if !strings.Contains(err.Error(), "AlreadyExists") {
		return fmt.Errorf("recovery key: %w", err)
	}
	return nil
}

// bootstrap is what every host gets from kvoadm, over one SSH session (design §3.1): the host key
// checked, the machine checked, keys instead of the password (rotated), and a signed kevasod
// verified on the host. It returns the connection, for installing a component.
func bootstrap(ctx context.Context, o InitOptions, home string, stdin io.Reader, out io.Writer, say func(string, ...any)) (*sshboot.Conn, error) {
	in := bufio.NewReader(stdin)

	binArch, err := ElfArch(o.Kevasod)
	if err != nil {
		return nil, err
	}
	bin, err := os.ReadFile(o.Kevasod)
	if err != nil {
		return nil, err
	}
	signKey, signPub, err := SigningKey(home)
	if err != nil {
		return nil, err
	}
	_, ownPub, err := SSHKey(filepath.Join(home, "ssh"))
	if err != nil {
		return nil, err
	}

	// 1. Connect: host key first, then a key or the password (asked once).
	conn, usedPassword, err := dialHost(ctx, o, in, stdin, out)
	if err != nil {
		return nil, err
	}
	say("connected to %s (host key %s)", net.JoinHostPort(o.Address, strconv.Itoa(o.SSHPort)), conn.Fingerprint)

	// 2. Check the machine.
	uname, err := conn.Run(ctx, "uname -m", nil)
	if err != nil {
		return nil, err
	}
	if got := strings.TrimSpace(string(uname)); got != binArch {
		return nil, fmt.Errorf("the host is %s but --kevasod is built for %s", got, binArch)
	}
	if _, err := conn.Run(ctx, "command -v openssl >/dev/null && command -v systemctl >/dev/null", nil); err != nil {
		return nil, errors.New("the host needs openssl and systemd")
	}

	// 3. If a password got us in, switch to keys and rotate it.
	if usedPassword {
		if err := conn.Harden(ctx, ownPub); err != nil {
			return nil, err
		}
		say("installed kvoadm's SSH key (%s), sshd is key-only, root password rotated", filepath.Join(home, "ssh", "id_ed25519"))
	}

	// 4. Install kevasod, signature checked on the host, and start the control plane.
	if err := conn.PinSigningKey(ctx, signPub); err != nil {
		return nil, err
	}
	if err := conn.InstallBinary(ctx, "kevasod", bin, ed25519.Sign(signKey, bin)); err != nil {
		return nil, err
	}
	say("kevasod installed (signature verified on the host)")
	return conn, nil
}

func lastLine(b []byte) []byte {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return []byte(lines[len(lines)-1])
}

func waitHostReady(ctx context.Context, c *client.Client, name string, d time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var last error
	for {
		var h v1.Host
		err := c.Get(ctx, "Host", "", name, &h)
		if err == nil && meta.IsTrue(h.Status.Conditions, "Ready") {
			return nil
		}
		if err != nil {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("host %s not Ready in %v (last error: %v)", name, d, last)
		case <-time.After(time.Second):
		}
	}
}

// dialHost connects to a host the way kvoadm does: the host key pinned or confirmed first, then a
// key or the password (asked once).
func dialHost(ctx context.Context, o InitOptions, in *bufio.Reader, stdin io.Reader, out io.Writer) (*sshboot.Conn, bool, error) {
	policy := sshboot.HostKeyPolicy{Pin: o.HostKey}
	if o.HostKey == "" {
		policy.Confirm = func(typ, fp string) bool {
			if o.HostKeyFirstUse {
				return true
			}
			_, _ = fmt.Fprintf(out, "host key of %s is %s %s. Trust it? Type yes: ", o.Address, typ, fp)
			line, _ := readLine(in)
			return strings.TrimSpace(line) == "yes"
		}
	}
	var auth sshboot.Auth
	usedPassword := false
	if o.SSHKey != "" {
		b, err := os.ReadFile(o.SSHKey)
		if err != nil {
			return nil, false, err
		}
		if auth.Signer, err = ssh.ParsePrivateKey(b); err != nil {
			return nil, false, fmt.Errorf("%s: %w", o.SSHKey, err)
		}
	} else {
		usedPassword = true
		auth.Password = func() (string, error) {
			_, _ = fmt.Fprintf(out, "password for %s@%s: ", o.User, o.Address)
			if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
				pw, err := term.ReadPassword(int(f.Fd()))
				_, _ = fmt.Fprintln(out)
				return string(pw), err
			}
			return readLine(in)
		}
	}
	addr := net.JoinHostPort(o.Address, strconv.Itoa(o.SSHPort))
	conn, err := sshboot.Connect(ctx, sshboot.Target{Addr: addr, User: o.User}, policy, auth)
	if err != nil {
		return nil, false, err
	}
	conn.Sudo = o.User != "root"
	return conn, usedPassword, nil
}

package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"kevaso.com/core/internal/sshboot"
)

// checkScript prints what kvoadm needs to know about a machine, one KEY=VALUE per line. It only
// reads.
const checkScript = `. /etc/os-release 2>/dev/null; echo "os=$PRETTY_NAME"
echo "arch=$(uname -m)"
echo "kernel=$(uname -r)"
echo "uid=$(id -u)"
command -v systemctl >/dev/null && echo systemd=yes || echo systemd=no
command -v openssl >/dev/null && echo openssl=yes || echo openssl=no
command -v apt-get >/dev/null && echo apt=yes || echo apt=no
[ -c /dev/kvm ] && echo kvm=yes || echo kvm=no
echo "cpus=$(nproc)"
echo "memory_mib=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)"
echo "disk_free_gib=$(df -P -BG /var/lib 2>/dev/null | awk 'NR==2 {gsub("G","",$4); print $4}')"
echo "password_login=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/ {print $2}')"
systemctl is-active --quiet kevasod 2>/dev/null && echo kevasod=running || echo kevasod=absent
(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -q ':6443$') && echo port_6443=taken || echo port_6443=free
`

// CheckResult is one line of what kvoadm found on a machine.
type CheckResult struct {
	What, Found, Note string
	Level             string // ok | warn | fail
}

// Assess turns the machine's facts into findings. Pure.
func Assess(facts map[string]string) []CheckResult {
	var out []CheckResult
	add := func(level, what, found, note string) {
		out = append(out, CheckResult{What: what, Found: found, Note: note, Level: level})
	}
	os := facts["os"]
	if strings.Contains(os, "Ubuntu 24.04") || strings.Contains(os, "Debian GNU/Linux 12") {
		add("ok", "operating system", os, "")
	} else {
		add("warn", "operating system", os, "tested on Ubuntu 24.04; others may work")
	}
	switch facts["arch"] {
	case "x86_64", "aarch64":
		add("ok", "CPU", facts["arch"], "build kevasod with GOARCH="+map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[facts["arch"]])
	default:
		add("fail", "CPU", facts["arch"], "kevasod runs on x86_64 and aarch64")
	}
	if facts["uid"] == "0" {
		add("ok", "account", "root", "")
	} else {
		add("ok", "account", "uid "+facts["uid"]+" (sudo)", "kvoadm runs every change with sudo -n")
	}
	for _, k := range []string{"systemd", "openssl"} {
		if facts[k] == "yes" {
			add("ok", k, "yes", "")
		} else {
			add("fail", k, "missing", "kevasod runs as a systemd service; kvoadm checks kevasod's signature with openssl")
		}
	}
	if facts["apt"] != "yes" {
		add("warn", "packages", "no apt-get", "runtimes install their packages with apt; install them yourself")
	}
	if facts["kvm"] == "yes" {
		add("ok", "KVM", "/dev/kvm", "microVM silos (cloud-hypervisor, openshell) can run here")
	} else {
		add("warn", "KVM", "none", "no microVMs on this machine: container silos only (docker, podman, openshell-container)")
	}
	cpus, _ := strconv.Atoi(facts["cpus"])
	mem, _ := strconv.Atoi(facts["memory_mib"])
	disk, _ := strconv.Atoi(facts["disk_free_gib"])
	level := "ok"
	if cpus < 2 || mem < 2048 {
		level = "warn"
	}
	add(level, "size", fmt.Sprintf("%d CPUs, %d MiB memory, %d GiB free", cpus, mem, disk), "a control plane alone needs ~1 CPU and 1 GiB; silos need their own")
	switch facts["password_login"] {
	case "no":
		add("ok", "SSH password login", "off", "")
	case "yes":
		add("warn", "SSH password login", "on", "anyone can try passwords: set PasswordAuthentication no once your key works")
	default:
		add("warn", "SSH password login", "unknown", "couldn't read sshd's settings")
	}
	if facts["kevasod"] == "running" {
		add("warn", "kevasod", "already running", "init again reinstalls it and restarts the service (the CA and store are kept)")
	}
	if facts["port_6443"] == "taken" && facts["kevasod"] != "running" {
		add("fail", "port 6443", "taken", "the API listens on 6443: something else already does")
	}
	return out
}

// ErrDryRun stops a command after it looked at the machine (--dry-run): nothing was changed.
var ErrDryRun = errors.New("dry run: nothing was changed")

// inspectMachine reads the machine (changing nothing), prints what it found, and reports whether
// it's fit (no ✗). Every command that sets a machine up does this first.
func inspectMachine(ctx context.Context, conn *sshboot.Conn, out io.Writer) (map[string]string, bool, error) {
	raw, err := conn.Run(ctx, "sh -c "+shQuote(checkScript), nil)
	if err != nil {
		return nil, false, fmt.Errorf("reading the machine: %w", err)
	}
	facts := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			facts[k] = v
		}
	}
	if facts["arch"] == "" {
		return facts, false, errors.New("the machine answered nothing kvoadm understands")
	}
	_, _ = fmt.Fprintln(out, "\nWhat's on this machine:")
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	ok := true
	for _, r := range Assess(facts) {
		mark := map[string]string{"ok": "✓", "warn": "!", "fail": "✗"}[r.Level]
		if r.Level == "fail" {
			ok = false
		}
		note := ""
		if r.Note != "" {
			note = "  " + r.Note
		}
		_, _ = fmt.Fprintf(tw, "  %s %s\t%s\t%s\n", mark, r.What, r.Found, note)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintln(out)
	return facts, ok, nil
}

// lookFirst logs in and reads the machine before anything is created for it (host add declares the
// Host and makes a join token before installing): a dry run or an unfit machine leaves nothing behind.
func lookFirst(ctx context.Context, o InitOptions, stdin io.Reader, out io.Writer) error {
	conn, _, err := dialHost(ctx, o, bufio.NewReader(stdin), stdin, out)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, fit, err := inspectMachine(ctx, conn, out)
	switch {
	case err != nil:
		return err
	case !fit:
		return errors.New("fix the ✗ lines first: nothing was changed")
	case o.DryRun:
		return ErrDryRun
	}
	return nil
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

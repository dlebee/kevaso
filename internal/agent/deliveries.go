package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// File and env deliveries, written by the host (design §8.2, §8.5, ADR 0009): the agent writes a
// silo's file and env secrets into it through its runtime's exec, before its init steps and again
// whenever what it receives changes, and removes what's no longer delivered. Nothing is installed
// in the silo: the scripts are POSIX sh, and the values travel on exec's stdin (never argv, never a
// file on the host). A secret is only ever written onto tmpfs (or ramfs): every silo container
// gets --tmpfs /run, and a microVM's /run is a tmpfs.

// Where env deliveries go and what was written, inside the silo.
const (
	EnvFile       = "/run/kevaso/secrets.env"
	DeliveredFile = "/run/kevaso/delivered"
	EnvProfile    = "/etc/profile.d/kevaso-secrets.sh"
)

// The scripts run as root in the silo. R and M only exist for tests (a folder standing in for the
// silo's root, and its mount table); in a silo they're empty and /proc/mounts.
const scriptEnv = `R=${KEVASO_TEST_ROOT:-}; M=${KEVASO_TEST_MOUNTS:-/proc/mounts}
`

// fsTypeFn prints the filesystem type of the folder $1 (from the mount table: the longest mount
// point above it).
const fsTypeFn = `fstype() {
  best=; t=
  while read -r _ mp ty _; do
    case "$1/" in
      "$mp"/*) [ ${#mp} -gt ${#best} ] && { best=$mp; t=$ty; } ;;
    esac
    [ "$mp" = / ] && [ -z "$best" ] && t=$ty
  done < "$M"
  printf '%s' "$t"
}
`

// writeScript writes stdin to $1 with mode $2, atomically; $3 = secret refuses anything but
// tmpfs (and anything outside /run).
const writeScript = scriptEnv + fsTypeFn + `set -e
p=$1; d=${p%/*}
if [ "$3" = secret ]; then
  case "$p" in /run/*) ;; *) echo "kevaso: $p isn't under /run" >&2; exit 3 ;; esac
  (umask 027; mkdir -p "$R$d")
  t=$(fstype "$d")
  case "$t" in tmpfs|ramfs) ;; *) echo "kevaso: $d is on ${t:-an unknown filesystem}, not tmpfs: no secret is written there" >&2; exit 4 ;; esac
else
  (umask 022; mkdir -p "$R$d")
fi
umask 077
cat > "$R$p.kvo-tmp"
chmod "$2" "$R$p.kvo-tmp"
mv -f "$R$p.kvo-tmp" "$R$p"
`

// cleanScript removes what an earlier pass wrote and this one didn't ($@: what it wrote), then
// records the new list. Only paths under /run are ever removed; without env deliveries, the
// profile script goes too.
const cleanScript = scriptEnv + `set -e
list=$R` + DeliveredFile + `
if [ -f "$list" ]; then
  while IFS= read -r p; do
    keep=0
    for n in "$@"; do [ "$p" = "$n" ] && keep=1; done
    case "$p" in /run/*) [ $keep = 1 ] || rm -f -- "$R$p" ;; esac
  done < "$list"
fi
env=0
for n in "$@"; do [ "$n" = ` + EnvFile + ` ] && env=1; done
[ $env = 1 ] || rm -f "$R` + EnvProfile + `"
mkdir -p "${list%/*}"
: > "$list.kvo-tmp"
for n in "$@"; do printf '%s\n' "$n" >> "$list.kvo-tmp"; done
chmod 0600 "$list.kvo-tmp"
mv -f "$list.kvo-tmp" "$list"
`

// caScript trusts the egress CA ($1, PEM; $2 its hash) in a VM, once per CA. It prints
// "env-only" when the image has no trust-store tooling: only the environment variables point at it.
const caScript = scriptEnv + `set -e
m=$R/etc/kevaso/egress-ca.sha256
[ "$(cat "$m" 2>/dev/null)" = "$2" ] && exit 0
mkdir -p "$R/etc/kevaso"
printf '%s' "$1" > "$R/etc/kevaso/egress-ca.crt"
how=store
if command -v update-ca-certificates >/dev/null 2>&1; then
  mkdir -p "$R/usr/local/share/ca-certificates"
  cp "$R/etc/kevaso/egress-ca.crt" "$R/usr/local/share/ca-certificates/kevaso-egress.crt"
  update-ca-certificates >/dev/null 2>&1
  bundle=/etc/ssl/certs/ca-certificates.crt
elif command -v update-ca-trust >/dev/null 2>&1; then
  mkdir -p "$R/etc/pki/ca-trust/source/anchors"
  cp "$R/etc/kevaso/egress-ca.crt" "$R/etc/pki/ca-trust/source/anchors/kevaso-egress.crt"
  update-ca-trust extract
  bundle=/etc/pki/tls/certs/ca-bundle.crt
else
  how=env-only
  bundle=/etc/kevaso/ca-bundle.crt
  : > "$R$bundle.kvo-tmp"
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    [ -f "$R$f" ] && { cat "$R$f" >> "$R$bundle.kvo-tmp"; echo >> "$R$bundle.kvo-tmp"; break; }
  done
  cat "$R/etc/kevaso/egress-ca.crt" >> "$R$bundle.kvo-tmp"
  mv -f "$R$bundle.kvo-tmp" "$R$bundle"
fi
e=$R/etc/environment
touch "$e"
grep -v -e '^NODE_EXTRA_CA_CERTS=' -e '^REQUESTS_CA_BUNDLE=' -e '^SSL_CERT_FILE=' -e '^CURL_CA_BUNDLE=' "$e" > "$e.kvo-tmp" || true
printf 'NODE_EXTRA_CA_CERTS=/etc/kevaso/egress-ca.crt\nREQUESTS_CA_BUNDLE=%s\nSSL_CERT_FILE=%s\nCURL_CA_BUNDLE=%s\n' "$bundle" "$bundle" "$bundle" >> "$e.kvo-tmp"
mv -f "$e.kvo-tmp" "$e"
printf '%s' "$2" > "$m"
[ "$how" = store ] || echo env-only
`

// delivered is what the agent last wrote into a silo (this run): its deliveries' key.
type delivered struct {
	key  string
	note string // what the condition said
}

// deliveriesKey names a set of deliveries (names, modes, places, versions) and the CA.
func deliveriesKey(ds []client.Delivery, ca string) string {
	h := sha256.New()
	for _, d := range ds {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%d\x00", d.Name, d.Mode, d.Path, d.Env, d.Version)
	}
	h.Write([]byte(ca))
	return hex.EncodeToString(h.Sum(nil))
}

// envFileText is the env file: KEY='value' lines, sorted, shell-quoted.
func envFileText(env map[string][]byte) []byte {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		b.WriteString(k + "='" + strings.ReplaceAll(string(env[k]), "'", `'\''`) + "'\n")
	}
	return b.Bytes()
}

const envProfileText = "# Kevaso: secrets delivered as environment variables (root only)\n[ -r " + EnvFile + " ] && { set -a; . " + EnvFile + "; set +a; }\n"

// execIn runs a script in the silo, with stdin, and says what went wrong.
func execIn(ctx context.Context, rt kri.Runtime, id kri.ID, stdin []byte, script string, args ...string) (string, error) {
	var out bytes.Buffer
	code, err := rt.Exec(ctx, id, kri.ExecRequest{Command: append([]string{"sh", "-c", script, "sh"}, args...),
		Stdin: bytes.NewReader(stdin), Stdout: &out, Stderr: &out})
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("exit %d: %s", code, strings.TrimSpace(tail(out.String(), 300)))
	}
	return strings.TrimSpace(out.String()), nil
}

// trustsCA reports whether the agent puts the egress CA in this silo itself: VMs whose grants
// inject (containers get the runtime's read-only bundle; runtimes that inject themselves bring
// their own).
func (a *Agent) trustsCA(rt kri.Runtime, s *v1.Silo, grants []*v1.Grant) bool {
	_, policied := rt.(kri.Policied)
	return len(a.EgressCA) > 0 && !policied && rt.Info().Capabilities.Isolation == "vm" && v1.Injects(s, grants)
}

// deliver writes the silo's file and env deliveries (and, for a VM that needs it, the egress CA)
// when they changed since this agent last wrote them, and says how it went in SecretsDelivered.
func (a *Agent) deliver(ctx context.Context, rt kri.Runtime, s *v1.Silo) error {
	grants := a.grantList()
	wantsCA := a.trustsCA(rt, s, grants)
	last, had := a.delivered.Load(s.UID)
	if !v1.HostWrites(s, grants) && !wantsCA && !had {
		return nil
	}
	id := idOf(s)
	ask := func(op string) (client.BrokerResponse, error) {
		var resp client.BrokerResponse
		if err := a.Client.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
			Namespace: s.Namespace, Name: s.Name, UID: s.UID, Host: a.HostName, Request: client.BrokerRequest{Op: op}}, &resp); err != nil {
			return resp, err
		}
		if resp.Error != "" {
			return resp, fmt.Errorf("%s", resp.Error)
		}
		return resp, nil
	}
	list, err := ask(client.OpDeliveries)
	if err != nil {
		return fmt.Errorf("deliveries: %w", err)
	}
	ca := ""
	if wantsCA {
		sum := sha256.Sum256(a.EgressCA)
		ca = hex.EncodeToString(sum[:])
	}
	key := deliveriesKey(list.Deliveries, ca)
	if had && last.(delivered).key == key {
		// Unchanged, unless the silo rebooted behind our back (/run is a tmpfs: it'd be empty).
		if code, err := rt.Exec(ctx, id, kri.ExecRequest{Command: []string{"test", "-f", DeliveredFile}}); err != nil || code == 0 {
			return err
		}
		a.log("silo %s/%s lost its secrets (rebooted?): writing them again", s.Namespace, s.Name)
	}
	note, werr := a.writeDeliveries(ctx, rt, id, list.Deliveries, ask, ca)
	cond, reason, msg := meta.ConditionTrue, "Delivered", note
	if werr != nil {
		cond, reason, msg = meta.ConditionFalse, "DeliveryFailed", werr.Error()
	}
	if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		setCond(st, "SecretsDelivered", cond, reason, msg, s.Generation, a.now())
	}); err != nil {
		return err
	}
	if werr != nil {
		return werr
	}
	a.delivered.Store(s.UID, delivered{key: key, note: note})
	return nil
}

// writeDeliveries does the writing; note is the condition's message.
func (a *Agent) writeDeliveries(ctx context.Context, rt kri.Runtime, id kri.ID, ds []client.Delivery, ask func(string) (client.BrokerResponse, error), ca string) (string, error) {
	var written []string
	files, envs := 0, 0
	if len(ds) > 0 {
		vals, err := ask(client.OpDeliveryValues)
		if err != nil {
			return "", fmt.Errorf("deliveries: %w", err)
		}
		defer func() {
			for _, d := range vals.Deliveries {
				clear(d.Value)
			}
		}()
		env := map[string][]byte{}
		for _, d := range vals.Deliveries {
			switch d.Mode {
			case v1.DeliverFile:
				p := path.Clean(d.Path)
				if !strings.HasPrefix(p, "/run/") {
					return "", fmt.Errorf("secret %s: %s isn't under /run (tmpfs)", d.Name, d.Path)
				}
				if _, err := execIn(ctx, rt, id, d.Value, writeScript, p, "0400", "secret"); err != nil {
					return "", fmt.Errorf("secret %s to %s: %w", d.Name, p, err)
				}
				written = append(written, p)
				files++
			case v1.DeliverEnv:
				env[d.Env] = d.Value
				envs++
			}
		}
		if len(env) > 0 {
			text := envFileText(env)
			_, err := execIn(ctx, rt, id, text, writeScript, EnvFile, "0400", "secret")
			clear(text)
			if err != nil {
				return "", fmt.Errorf("env secrets: %w", err)
			}
			written = append(written, EnvFile)
			if _, err := execIn(ctx, rt, id, []byte(envProfileText), writeScript, EnvProfile, "0644", "plain"); err != nil {
				return "", fmt.Errorf("env secrets' profile script: %w", err)
			}
		}
	}
	if _, err := execIn(ctx, rt, id, nil, cleanScript, written...); err != nil {
		return "", fmt.Errorf("removing secrets no longer delivered: %w", err)
	}
	note := fmt.Sprintf("%d files, %d environment variables (tmpfs)", files, envs)
	if ca != "" {
		out, err := execIn(ctx, rt, id, nil, caScript, string(a.EgressCA), ca)
		if err != nil {
			return "", fmt.Errorf("trusting the egress CA: %w", err)
		}
		if out == "env-only" {
			note += "; egress CA trusted through environment variables only (no update-ca-certificates or update-ca-trust in the image)"
		} else {
			note += "; egress CA trusted"
		}
	}
	return note, nil
}

func (a *Agent) grantList() []*v1.Grant {
	if a.grants == nil {
		return nil
	}
	var out []*v1.Grant
	for _, o := range a.grants.List() {
		out = append(out, o.(*v1.Grant))
	}
	return out
}

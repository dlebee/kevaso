// Package openshell is the `openshell` and `openshell-container` runtimes (design §6): each silo is
// an NVIDIA OpenShell sandbox, on its VM driver (a microVM with no network card: egress only through
// OpenShell's policy, research E004, E007) or its Docker driver (no KVM needed, E035). Kevaso owns
// placement, namespaces and the API; OpenShell owns the sandbox, its policy engine and credential
// injection (E026). A silo's grants become an OpenShell policy and providers (E037).
//
// OpenShell's gateway runs under a dedicated user in a locked-down unit (E028), one per host,
// namespace or silo (gatewayScope): sandboxes of one gateway share its user, so the scope is how far
// an escape reaches.
//
// Everything goes through the openshell CLI (`-o json`), via the Runner interface, so command
// sequences are unit-tested anywhere.
package openshell

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"kevaso.com/core/sdk/kri"
)

// Version is the OpenShell release this runtime is tested with (pre-1.0: pinned, conformance per
// release).
const Version = "v0.1.8"

// Debs are the release packages and their SHA-256 (from the release's checksum file).
var Debs = map[string]struct{ File, SHA256 string }{
	"x86_64":  {"openshell_0.1.8-1_amd64.deb", "b3339527085d9b44afc0d5e4f835c2d34e44e33d0b67d6a4cac9d96f25a656b1"},
	"aarch64": {"openshell_0.1.8-1_arm64.deb", "3d53db93dc2f130ae570a838c2dd48fda626bd1ab964ea1de895e13a21a667a9"},
}

// DebURL is where a package is downloaded from.
func DebURL(file string) string {
	return "https://github.com/NVIDIA/OpenShell/releases/download/" + Version + "/" + file
}

// Drivers.
const (
	DriverVM     = "vm"     // runtime openshell
	DriverDocker = "docker" // runtime openshell-container
)

// Gateway scopes (design §3.1): how many gateways, so how many sandboxes share one user.
const (
	ScopeHost      = "host"
	ScopeNamespace = "namespace" // the default
	ScopeSilo      = "silo"
)

// Paths.
const (
	StateDir  = "/var/lib/kevaso-openshell"
	BasePort  = 17700
	unitStart = "kevaso-openshell-"
)

func hash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:5])
}

// Short is a silo's stable name part.
func Short(id kri.ID) string { return hash(id.Namespace, id.Name, id.UID) }

// SandboxName is the silo's sandbox in OpenShell.
func SandboxName(id kri.ID) string { return "kv-" + Short(id) }

// GatewayKey is which gateway a silo goes to under scope (driver included: each driver has its own).
func GatewayKey(driver, scope string, id kri.ID) string {
	switch scope {
	case ScopeHost:
		return driver + "-host"
	case ScopeSilo:
		return driver + "-s" + Short(id)
	default:
		return driver + "-n" + hash(id.Namespace)
	}
}

// Gateway is one OpenShell gateway on this host.
type Gateway struct {
	Key    string `json:"key"`
	Port   int    `json:"port"`
	Driver string `json:"driver"`
}

// User is the gateway's own system user.
func (g Gateway) User() string { return "kvos-" + hash(g.Key)[:8] }

// Dir is its home: config, state, sandbox disks.
func (g Gateway) Dir() string { return StateDir + "/gw/" + g.Key }

// Unit is its systemd unit.
func (g Gateway) Unit() string { return unitStart + g.Key + ".service" }

// Name is how the CLI knows it.
func (g Gateway) Name() string { return "kv-" + g.Key }

// Endpoint is where it listens (loopback only).
func (g Gateway) Endpoint() string { return "https://127.0.0.1:" + strconv.Itoa(g.Port) }

// Env is the environment the CLI runs with to reach it: the gateway's own config and state dirs,
// where its client certificate is.
func (g Gateway) Env() []string {
	d := g.Dir()
	return []string{"HOME=" + d, "XDG_CONFIG_HOME=" + d + "/.config", "XDG_STATE_HOME=" + d + "/.local/state",
		"XDG_DATA_HOME=" + d + "/.local/share", "OPENSHELL_GATEWAY=" + g.Name(), "NO_COLOR=1"}
}

// EnvFile is the gateway's settings: driver, loopback, its port and name (E004: the driver must be
// set, auto-detection finds none).
func (g Gateway) EnvFile() string {
	return fmt.Sprintf("OPENSHELL_COMPUTE_DRIVER=%s\nOPENSHELL_BIND_ADDRESS=127.0.0.1\nOPENSHELL_SERVER_PORT=%d\nOPENSHELL_GATEWAY_NAME=%s\nOPENSHELL_GATEWAY_CONFIG=%s/.config/openshell/gateway.toml\n",
		g.Driver, g.Port, g.Name(), g.Dir())
}

// TOML is the gateway's config file: the driver, and extra CAs its proxy trusts upstream.
func (g Gateway) TOML(extraCA string) string {
	s := "[openshell]\nversion = 2\n\n[openshell.gateway]\ncompute_driver = \"" + g.Driver + "\"\n"
	if extraCA != "" {
		s += "\n[openshell.supervisor.network]\nadditional_ca_bundle = \"" + extraCA + "\"\n"
	}
	return s
}

// Unit is the gateway's locked-down systemd unit (E028): its own user, no capabilities, a system
// call filter, only /dev/kvm (VM driver) or the Docker socket (container driver).
func (g Gateway) UnitFile() string {
	d := g.Dir()
	devices := "PrivateDevices=yes\nBindPaths=/dev/kvm\nDevicePolicy=closed\nDeviceAllow=/dev/kvm rw\n"
	groups := "SupplementaryGroups=kvm\n"
	if g.Driver == DriverDocker {
		devices = "PrivateDevices=yes\n"
		groups = "SupplementaryGroups=docker\n"
	}
	return `[Unit]
Description=Kevaso OpenShell gateway ` + g.Key + ` (` + Version + `, ` + g.Driver + ` driver)
After=network-online.target

[Service]
Type=simple
User=` + g.User() + `
Group=` + g.User() + `
` + groups + `Environment=HOME=` + d + `
Environment=XDG_CONFIG_HOME=` + d + `/.config
Environment=XDG_STATE_HOME=` + d + `/.local/state
Environment=XDG_DATA_HOME=` + d + `/.local/share
Environment=XDG_RUNTIME_DIR=/run/` + strings.TrimSuffix(g.Unit(), ".service") + `
RuntimeDirectory=` + strings.TrimSuffix(g.Unit(), ".service") + `
RuntimeDirectoryMode=0700
Environment=OPENSHELL_LOCAL_TLS_DIR=` + d + `/.local/state/openshell/tls
EnvironmentFile=` + d + `/.config/openshell/gateway.env
ExecStartPre=/usr/bin/openshell-gateway config preflight
ExecStartPre=/usr/bin/openshell-gateway generate-certs --output-dir ${OPENSHELL_LOCAL_TLS_DIR} --server-san host.openshell.internal
ExecStart=/usr/bin/openshell-gateway
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=` + d + `
ProtectHome=yes
PrivateTmp=yes
` + devices + `ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
`
}

// ── policy and providers (E037) ──────────────────────────────────────────────

// basePolicy is OpenShell's default filesystem policy (what `policy get --full` shows).
const basePolicy = `version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/bin, /usr, /lib, /proc, /dev/urandom, /etc, /var/log]
  read_write: [/tmp, /dev/null]
landlock:
  compatibility: best_effort
`

// PolicyYAML is a silo's OpenShell policy: no network_policies means nothing outside; each endpoint
// is a rule for any program (`/**`: a rule without binaries allows nothing, E037). Hosts that get a
// credential are inspected (rest), so the proxy can swap the placeholder.
func PolicyYAML(p kri.Policy) string {
	if len(p.Egress) == 0 {
		return basePolicy
	}
	rest := map[string]bool{}
	for _, c := range p.Credentials {
		rest[strings.ToLower(c.Host)] = true
	}
	eps := append([]kri.Endpoint(nil), p.Egress...)
	sort.Slice(eps, func(i, j int) bool {
		return eps[i].Host < eps[j].Host || (eps[i].Host == eps[j].Host && eps[i].Port < eps[j].Port)
	})
	var b strings.Builder
	b.WriteString(basePolicy + "network_policies:\n")
	for i, e := range eps {
		name := fmt.Sprintf("kv_%d", i)
		fmt.Fprintf(&b, "  %s:\n    name: %s\n    endpoints:\n      - host: %q\n        port: %d\n", name, name, e.Host, e.Port)
		if rest[strings.ToLower(e.Host)] && e.Port == 443 {
			b.WriteString("        protocol: rest\n        access: read-write\n")
		}
		b.WriteString("    binaries:\n      - path: \"/**\"\n")
	}
	return b.String()
}

// ProfileID is the provider profile (and provider) for one injected credential of a silo.
func ProfileID(id kri.ID, c kri.Credential) string {
	return "kv" + Short(id) + hash(c.Name, c.Host, c.Header, c.Env)
}

// ProfileYAML is the provider profile for a credential: what OpenShell swaps the placeholder in $Env
// for, in which header, for which host (E026, E037).
func ProfileYAML(id kri.ID, c kri.Credential) string {
	style := "header\n    header_name: " + strings.ToLower(c.Header)
	if c.Bearer {
		style = "bearer\n    header_name: authorization"
	}
	return `id: ` + ProfileID(id, c) + `
display_name: Kevaso ` + c.Name + `
description: Kevaso secret ` + c.Name + ` for ` + id.Namespace + `/` + id.Name + `
category: other
credentials:
  - name: value
    description: Kevaso secret ` + c.Name + `
    env_vars: [` + c.Env + `]
    required: true
    auth_style: ` + style + `
endpoints:
  - host: ` + c.Host + `
    port: 443
    path: /**
    protocol: rest
    access: read-write
    enforcement: enforce
binaries: ["/**"]
`
}

// PolicyHash identifies a policy for "nothing changed" (credential versions, never values).
func PolicyHash(p kri.Policy) string {
	parts := []string{PolicyYAML(p)}
	for _, c := range p.Credentials {
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%s|%v|%d", c.Name, c.Host, c.Header, c.Env, c.Bearer, c.Version))
	}
	return hash(parts...)
}

// Phase maps a sandbox phase to a KRI state.
func Phase(phase string) kri.State {
	switch strings.ToLower(phase) {
	case "ready":
		return kri.Running
	case "stopped", "suspended":
		return kri.Stopped
	case "error", "failed":
		return kri.Failed
	}
	return kri.Running // provisioning, starting: on its way (Exec waits for Ready)
}

// Memory is OpenShell's form of a byte count (Mi).
func Memory(bytes int64) string { return strconv.FormatInt(bytes>>20, 10) + "Mi" }

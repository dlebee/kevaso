package openshell

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"kevaso.com/core/sdk/kri"
)

func newRuntime(f *fake, scope string) *Runtime {
	return &Runtime{Host: f, Name: "openshell", Driver: DriverVM, Scope: scope, Arch: "aarch64", Wait: time.Second, Sleep: func(time.Duration) {}}
}

var silo = kri.ID{Namespace: "dev", Name: "agent", UID: "u1"}

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04", CPU: 2, Memory: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	g := Gateway{Key: GatewayKey(DriverVM, ScopeNamespace, silo), Port: BasePort, Driver: DriverVM}
	if f.ran("useradd --system --home-dir "+g.Dir()) != 1 || f.ran("systemctl start") != 0 || f.ran("systemctl enable") != 0 {
		t.Fatalf("gateway setup (readied, not started):\n%s", strings.Join(f.cmds, "\n"))
	}
	if st, _ := r.Status(ctx, silo); st.State != kri.Created {
		t.Fatalf("after create: %v", st.State)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if f.ran("systemctl start "+g.Unit()) != 1 || f.ran("gateway add https://127.0.0.1:17700 --local --name "+g.Name()) != 1 {
		t.Fatalf("gateway start:\n%s", strings.Join(f.cmds, "\n"))
	}
	create := f.cmds[len(f.cmds)-1]
	for _, want := range []string{"sandbox create --name " + SandboxName(silo), "--detach", "--cpu 2", "--memory 1024Mi", "--label kevaso.com/uid=u1", "--policy " + policyPath(silo)} {
		if !strings.Contains(create, want) {
			t.Errorf("create %q missing %q", create, want)
		}
	}
	if strings.Contains(create, "--from") {
		t.Error("ubuntu-24.04 is OpenShell's default image: no --from")
	}
	if st, _ := r.Status(ctx, silo); st.State != kri.Running {
		t.Fatalf("after start: %v", st.State)
	}
	// Exec passes stdin through and returns the exit code.
	f.execCode = 7
	var out strings.Builder
	code, err := r.Exec(ctx, silo, kri.ExecRequest{Command: []string{"sh", "-c", "cat; exit 7"}, Stdin: strings.NewReader("hi"), Stdout: &out})
	if err != nil || code != 7 || out.String() != "hi" || !strings.Contains(f.cmds[len(f.cmds)-1], "sandbox exec -n "+SandboxName(silo)+" --no-tty -- sh -c ") ||
		!strings.HasSuffix(f.cmds[len(f.cmds)-1], " sh -c cat; exit 7") {
		t.Fatalf("exec: %d %q %v %s", code, out.String(), err, f.cmds[len(f.cmds)-1])
	}
	if err := r.Stop(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.Status(ctx, silo); st.State != kri.Stopped {
		t.Fatalf("after stop: %v", st.State)
	}
	if _, err := r.Exec(ctx, silo, kri.ExecRequest{Command: []string{"true"}}); err == nil {
		t.Fatal("exec in a stopped sandbox")
	}
	if err := r.Start(ctx, silo); err != nil || f.ran("sandbox start "+SandboxName(silo)) != 1 {
		t.Fatalf("restart: %v", err)
	}
	ids, _ := r.List(ctx)
	if len(ids) != 1 || ids[0] != silo {
		t.Fatalf("list %v", ids)
	}
	if err := r.Delete(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.Status(ctx, silo); st.State != kri.Absent || len(f.sandboxes) != 0 {
		t.Fatalf("after delete: %v %v", st.State, f.sandboxes)
	}
	if f.ran("userdel") != 0 {
		t.Error("a namespace's gateway was removed with one silo")
	}
}

func TestPolicyAndCredentials(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, ScopeHost)
	_ = r.Create(ctx, kri.Spec{ID: silo})
	cred := kri.Credential{Name: "anthropic-key", Env: "ANTHROPIC_API_KEY", Host: "api.anthropic.com", Header: "x-api-key", Value: []byte("sk-secret-1"), Version: 1}
	p := kri.Policy{Egress: []kri.Endpoint{{Host: "api.github.com", Port: 443}, {Host: "api.anthropic.com", Port: 443}}, Credentials: []kri.Credential{cred}}
	// Before the sandbox exists: providers made, policy file written; create attaches them.
	if err := r.SetPolicy(ctx, silo, p); err != nil {
		t.Fatal(err)
	}
	name := ProfileID(silo, cred)
	if f.ran("profile import -f") != 1 || f.ran("provider create --name "+name+" --type "+name+" --credential ANTHROPIC_API_KEY") != 1 {
		t.Fatalf("providers:\n%s", strings.Join(f.cmds, "\n"))
	}
	if err := r.Start(ctx, silo); err != nil || !strings.Contains(f.cmds[len(f.cmds)-1], "--provider "+name) {
		t.Fatalf("create without the provider: %v %s", err, f.cmds[len(f.cmds)-1])
	}
	pol := string(f.files[policyPath(silo)])
	for _, want := range []string{"network_policies:", `host: "api.github.com"`, `host: "api.anthropic.com"`, "protocol: rest", `path: "/**"`} {
		if !strings.Contains(pol, want) {
			t.Errorf("policy missing %q:\n%s", want, pol)
		}
	}
	// Unchanged: nothing runs.
	n := len(f.cmds)
	if err := r.SetPolicy(ctx, silo, p); err != nil || len(f.cmds) != n {
		t.Fatalf("unchanged policy ran %d commands", len(f.cmds)-n)
	}
	// Rotation: provider update, the value through the environment.
	p.Credentials[0].Value, p.Credentials[0].Version = []byte("sk-secret-2"), 2
	if err := r.SetPolicy(ctx, silo, p); err != nil {
		t.Fatal(err)
	}
	if f.ran("provider update "+name+" --credential ANTHROPIC_API_KEY --wait") != 1 || f.ran("policy set "+SandboxName(silo)) != 1 {
		t.Fatalf("rotation:\n%s", strings.Join(f.cmds[n:], "\n"))
	}
	if !strings.Contains(f.envs[len(f.envs)-2], "ANTHROPIC_API_KEY=sk-secret-2") {
		t.Errorf("the new value didn't go through the environment: %s", f.envs[len(f.envs)-2])
	}
	// The credential goes away: detached, deleted.
	if err := r.SetPolicy(ctx, silo, kri.Policy{Egress: []kri.Endpoint{{Host: "api.github.com", Port: 443}}}); err != nil {
		t.Fatal(err)
	}
	if f.ran("sandbox provider detach "+SandboxName(silo)+" "+name) != 1 || f.ran("provider delete "+name) != 1 {
		t.Fatalf("removal:\n%s", strings.Join(f.cmds, "\n"))
	}
	// No value ever on a command line.
	for _, c := range f.cmds {
		if strings.Contains(c, "sk-secret") {
			t.Fatalf("a secret on a command line: %s", c)
		}
	}
}

func TestGatewayScopes(t *testing.T) {
	a := kri.ID{Namespace: "dev", Name: "a", UID: "1"}
	b := kri.ID{Namespace: "dev", Name: "b", UID: "2"}
	c := kri.ID{Namespace: "ops", Name: "c", UID: "3"}
	for _, tc := range []struct {
		scope          string
		sameAB, sameAC bool
	}{
		{ScopeHost, true, true},
		{ScopeNamespace, true, false},
		{"", true, false},
		{ScopeSilo, false, false},
	} {
		r := &Runtime{Scope: tc.scope}
		ka, kb, kc := GatewayKey(DriverVM, r.scope(), a), GatewayKey(DriverVM, r.scope(), b), GatewayKey(DriverVM, r.scope(), c)
		if (ka == kb) != tc.sameAB || (ka == kc) != tc.sameAC {
			t.Errorf("scope %q: %s %s %s", tc.scope, ka, kb, kc)
		}
	}
	if GatewayKey(DriverVM, ScopeHost, a) == GatewayKey(DriverDocker, ScopeHost, a) {
		t.Error("the two drivers share a gateway")
	}
	// Two namespaces: two gateways, two ports, two users.
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, ScopeNamespace)
	_ = r.Create(ctx, kri.Spec{ID: a})
	_ = r.Create(ctx, kri.Spec{ID: c})
	_ = r.Create(ctx, kri.Spec{ID: b})
	if f.ran("useradd") != 2 || len(f.files[Gateway{Key: GatewayKey(DriverVM, ScopeNamespace, a), Port: 17700}.Dir()+"/.config/openshell/gateway.env"]) == 0 ||
		!strings.Contains(string(f.files[Gateway{Key: GatewayKey(DriverVM, ScopeNamespace, c)}.Dir()+"/.config/openshell/gateway.env"]), "OPENSHELL_SERVER_PORT=17701") {
		t.Fatalf("namespace gateways:\n%s", strings.Join(f.cmds, "\n"))
	}
}

func TestUnitAndProfile(t *testing.T) {
	g := Gateway{Key: "vm-host", Port: 17700, Driver: DriverVM}
	u := g.UnitFile()
	for _, want := range []string{"User=" + g.User(), "NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "SystemCallFilter=@system-service",
		"PrivateDevices=yes\nBindPaths=/dev/kvm", "DeviceAllow=/dev/kvm rw", "ReadWritePaths=" + g.Dir(), "SupplementaryGroups=kvm"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q", want)
		}
	}
	d := Gateway{Key: "docker-host", Port: 17701, Driver: DriverDocker}.UnitFile()
	if strings.Contains(d, "/dev/kvm") || !strings.Contains(d, "SupplementaryGroups=docker") {
		t.Error("docker gateway unit")
	}
	if !strings.Contains(g.EnvFile(), "OPENSHELL_COMPUTE_DRIVER=vm") || !strings.Contains(g.EnvFile(), "OPENSHELL_BIND_ADDRESS=127.0.0.1") {
		t.Error("env file")
	}
	if !strings.Contains(g.TOML("/etc/kevaso/ca.pem"), `additional_ca_bundle = "/etc/kevaso/ca.pem"`) || strings.Contains(g.TOML(""), "supervisor") {
		t.Error("toml")
	}
	bearer := ProfileYAML(silo, kri.Credential{Name: "gh", Env: "GH_TOKEN", Host: "api.github.com", Header: "Authorization", Bearer: true})
	header := ProfileYAML(silo, kri.Credential{Name: "a", Env: "K", Host: "api.anthropic.com", Header: "X-Api-Key"})
	for _, doc := range []string{bearer, header, PolicyYAML(kri.Policy{Egress: []kri.Endpoint{{Host: "api.anthropic.com", Port: 443}}, Credentials: []kri.Credential{{Host: "api.anthropic.com"}}})} {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("not YAML: %v\n%s", err, doc)
		}
	}
	var prof struct {
		Credentials []struct {
			AuthStyle  string   `yaml:"auth_style"`
			HeaderName string   `yaml:"header_name"`
			EnvVars    []string `yaml:"env_vars"`
		}
		Endpoints []struct{ Host string }
		Binaries  []string
	}
	_ = yaml.Unmarshal([]byte(header), &prof)
	if len(prof.Credentials) != 1 || prof.Credentials[0].AuthStyle != "header" || prof.Credentials[0].HeaderName != "x-api-key" ||
		prof.Credentials[0].EnvVars[0] != "K" || prof.Endpoints[0].Host != "api.anthropic.com" || prof.Binaries[0] != "/**" {
		t.Errorf("header profile parsed as %+v", prof)
	}
	_ = yaml.Unmarshal([]byte(bearer), &prof)
	if prof.Credentials[0].AuthStyle != "bearer" || prof.Credentials[0].HeaderName != "authorization" {
		t.Errorf("bearer profile parsed as %+v", prof)
	}
	if PolicyYAML(kri.Policy{}) != basePolicy || strings.Contains(PolicyYAML(kri.Policy{}), "network_policies") {
		t.Error("no grants must mean no network")
	}
	for in, want := range map[string]kri.State{"Ready": kri.Running, "Stopped": kri.Stopped, "Provisioning": kri.Running, "Error": kri.Failed} {
		if Phase(in) != want {
			t.Errorf("Phase(%s)", in)
		}
	}
}

// A caller that never closes stdin doesn't keep Exec waiting once the command is done.
func TestLocalRunDoesNotWaitForStdin(t *testing.T) {
	r, w := io.Pipe()
	defer func() { _ = w.Close() }()
	done := make(chan int, 1)
	go func() {
		code, _ := Local{}.Run(context.Background(), Cmd{Name: "sh", Args: []string{"-c", "exit 3"}, Stdin: r})
		done <- code
	}()
	select {
	case code := <-done:
		if code != 3 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run waited for stdin after the command exited")
	}
}

// Found on the machine (TestMetalOpenShell): a gateway stopped behind Kevaso's back. Status
// failed on every look ("connect error"), so the agent never got to Start, which is what sets the
// gateway up again: the silo never came back. A gateway that doesn't answer is a stopped silo,
// started again with its gateway.
func TestAStoppedGatewayIsStartedAgainWithTheSilo(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	g := Gateway{Key: GatewayKey(DriverVM, ScopeNamespace, silo), Port: BasePort, Driver: DriverVM}
	f.units[g.Unit()] = "inactive" // systemctl stop, behind Kevaso's back
	st, err := r.Status(ctx, silo)
	if err != nil || st.State != kri.Stopped || !strings.Contains(st.Message, g.Name()) {
		t.Fatalf("its gateway down: %v %q %v, want Stopped, saying why", st.State, st.Message, err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.Status(ctx, silo); st.State != kri.Running || !f.answers(g.Name()) {
		t.Fatalf("started again: %v, gateway up %v", st.State, f.answers(g.Name()))
	}
}

// K-066: a credential's env name, header and host reach a root command's environment, its
// arguments and a profile's text: checked where they're used, whatever admission said. LD_PRELOAD
// or HOME would steer the CLI that kevasod runs as root; a newline would write keys of its own
// into the profile.
func TestACredentialIsCheckedWhereItIsUsed(t *testing.T) {
	ctx := context.Background()
	for _, bad := range []kri.Credential{
		{Name: "k", Env: "LD_PRELOAD", Host: "api.example.com", Header: "Authorization"},
		{Name: "k", Env: "HOME", Host: "api.example.com", Header: "Authorization"},
		{Name: "k", Env: "OPENSHELL_GATEWAY_ENDPOINT", Host: "api.example.com", Header: "Authorization"},
		{Name: "k", Env: "KEY\nendpoints:", Host: "api.example.com", Header: "Authorization"},
		{Name: "k", Env: "lower", Host: "api.example.com", Header: "Authorization"},
		{Name: "k", Env: "KEY", Host: "api.example.com\n  - host: evil", Header: "Authorization"},
		{Name: "k", Env: "KEY", Host: "api.example.com", Header: "X-Key\nfoo: bar"},
		{Name: "k\nx", Env: "KEY", Host: "api.example.com", Header: "Authorization"},
	} {
		f := newFake()
		r := newRuntime(f, "")
		if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
			t.Fatal(err)
		}
		bad.Value, bad.Version = []byte("v"), 1
		if err := r.SetPolicy(ctx, silo, kri.Policy{Credentials: []kri.Credential{bad}}); err == nil {
			t.Errorf("%q accepted", fmt.Sprintf("%+v", bad))
		}
		if f.ran("provider create") != 0 || f.ran("profile import") != 0 {
			t.Errorf("%+v: the CLI ran with it", bad)
		}
	}
	ok := kri.Credential{Name: "api-key", Env: "API_KEY", Host: "api.example.com", Header: "Authorization", Bearer: true, Value: []byte("v"), Version: 1}
	if err := CheckCredential(ok); err != nil {
		t.Fatalf("a good one refused: %v", err)
	}
}

// Found on machine 2 (TestMetalOpenShell, the VM driver): a gateway stopped and started again
// brings its sandbox's VM back by itself, then marks the sandbox Error ("Failed to start sandbox
// during gateway startup: VM sandbox is already running"), and refuses sandbox start in that
// state. A stop clears it: Start stops a sandbox in Error before it starts it.
func TestASandboxInErrorIsStoppedThenStarted(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	f.sandboxes[SandboxName(silo)].phase = "Error"
	if st, _ := r.Status(ctx, silo); st.State != kri.Failed {
		t.Fatalf("a sandbox in Error: %v", st.State)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatalf("Start of a sandbox in Error: %v", err)
	}
	if st, _ := r.Status(ctx, silo); st.State != kri.Running || f.ran("sandbox stop "+SandboxName(silo)) != 1 {
		t.Fatalf("after Start: %v (stops: %d)", st.State, f.ran("sandbox stop "+SandboxName(silo)))
	}
}

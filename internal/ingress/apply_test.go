package ingress_test

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kic/kong"
	"kevaso.com/core/builtin/kic/nginx"
	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/internal/ingress/ingresstest"
	"kevaso.com/core/sdk/kic"
	"kevaso.com/core/sdk/kic/kictest"
)

func execOn(p *ingresstest.Proxy) ingress.Exec {
	return func(_ context.Context, argv []string, stdin []byte) (int, string, error) {
		out, code := p.Handle(argv, stdin)
		return code, out, nil
	}
}

func render(t *testing.T, s kic.State) kic.Plan {
	t.Helper()
	p, err := nginx.Driver{}.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyFiles(t *testing.T) {
	ctx := context.Background()
	px := ingresstest.New()
	p := render(t, kictest.Sample(nil))
	r, err := ingress.Apply(ctx, execOn(px), nil, nginx.Driver{}, p, "")
	if err != nil || !r.Changed || r.Hash != p.Hash() || r.Rejected != "" {
		t.Fatalf("first: %+v %v", r, err)
	}
	files, writes, reloads := px.Snapshot()
	if reloads != 1 || string(files[nginx.ConfigPath]) != string(p.Config.Data) || string(files[p.Files[0].Path]) != string(p.Files[0].Data) {
		t.Fatalf("reloads %d, files %v", reloads, writes)
	}
	ran := px.Commands()
	check := slices.IndexFunc(ran, func(c string) bool { return strings.HasPrefix(c, "nginx -t -q -c "+nginx.ConfigPath+".next") })
	reload := slices.Index(ran, "nginx -s reload")
	mv := slices.Index(ran, "mv -f "+nginx.ConfigPath+".next "+nginx.ConfigPath)
	if check < 0 || mv < check || reload < mv {
		t.Fatalf("check, move, reload, in that order: %v", ran)
	}
	for _, c := range ran {
		if strings.Contains(c, "PRIVATE KEY") {
			t.Fatal("a key in a command's arguments")
		}
	}

	// Unchanged: nothing at all is run.
	before := len(px.Commands())
	if r, err := ingress.Apply(ctx, execOn(px), nil, nginx.Driver{}, p, r.Hash); err != nil || r.Changed || len(px.Commands()) != before {
		t.Fatalf("unchanged: %+v %v %v", r, err, px.Commands()[before:])
	}
	// An agent that restarted (knows nothing): it reads the config, sees it's the same, stops.
	if r, err := ingress.Apply(ctx, execOn(px), nil, nginx.Driver{}, p, ""); err != nil || r.Changed || r.Hash != p.Hash() ||
		!slices.Equal(px.Commands()[before:], []string{"cat " + nginx.ConfigPath}) {
		t.Fatalf("after a restart: %+v %v %v", r, err, px.Commands()[before:])
	}

	// The proxy refuses the next one: nothing of it stays, the running config is untouched.
	s := kictest.Sample(nil)
	s.Certificates[0].Chain = []byte(strings.Replace(kictest.Chain, "MIIB", "MIIC", 1))
	bad := render(t, s)
	px.Check = func(cfg []byte, _ map[string][]byte) string {
		return "nginx: [emerg] cannot load certificate in " + nginx.ConfigPath + ".next:" + lineOf(cfg, "ssl_certificate ") + "\nnginx: configuration file " + nginx.ConfigPath + ".next test failed"
	}
	r2, err := ingress.Apply(ctx, execOn(px), nil, nginx.Driver{}, bad, r.Hash)
	if err != nil || r2.Changed || r2.Hash != r.Hash || !strings.Contains(r2.Rejected, "cannot load certificate in "+nginx.ConfigPath+":") ||
		!slices.Equal(r2.Blamed, []string{"payments/api"}) {
		t.Fatalf("refused: %+v %v", r2, err)
	}
	after, _, reloads := px.Snapshot()
	if reloads != 1 || len(after) != len(files) || string(after[nginx.ConfigPath]) != string(p.Config.Data) {
		t.Fatalf("a refused config left something: reloads %d, files %d → %d", reloads, len(files), len(after))
	}

	// Accepted (a renewal): the new certificate in, the old one out, one reload.
	px.Check = nil
	r3, err := ingress.Apply(ctx, execOn(px), nil, nginx.Driver{}, bad, r.Hash)
	after, _, reloads = px.Snapshot()
	if err != nil || !r3.Changed || reloads != 2 {
		t.Fatalf("renewal: %+v %v", r3, err)
	}
	if _, ok := after[p.Files[0].Path]; ok {
		t.Fatal("the old certificate's key is still there")
	}
	if _, ok := after[bad.Files[0].Path]; !ok {
		t.Fatal("the new certificate isn't there")
	}

	// A reload that fails is an error (try again), not a success.
	failing := &ingresstest.Proxy{Files: after, CheckCmd: px.CheckCmd, ReloadCmd: []string{"unused"}}
	exec := func(ctx context.Context, argv []string, stdin []byte) (int, string, error) {
		if slices.Equal(argv, []string{"nginx", "-s", "reload"}) {
			return 1, "nginx: [error] invalid PID number", nil
		}
		return execOn(failing)(ctx, argv, stdin)
	}
	if _, err := ingress.Apply(ctx, exec, nil, nginx.Driver{}, p, r3.Hash); err == nil || !strings.Contains(err.Error(), "reload") {
		t.Fatalf("a failed reload: %v", err)
	}
}

func lineOf(cfg []byte, s string) string {
	for i, l := range strings.Split(string(cfg), "\n") {
		if strings.Contains(l, s) {
			return strconv.Itoa(i + 1)
		}
	}
	return "0"
}

// An admin-API driver: the call is the check and the reload; refused, Kong keeps what it had.
func TestApplyCall(t *testing.T) {
	ctx := context.Background()
	p, err := kong.Driver{}.Render(kictest.Sample(nil))
	if err != nil {
		t.Fatal(err)
	}
	var calls []kic.Call
	status, body := 201, ""
	call := func(_ context.Context, c kic.Call) (int, string, error) {
		calls = append(calls, c)
		return status, body, nil
	}
	noExec := func(context.Context, []string, []byte) (int, string, error) {
		t.Fatal("an admin-API driver ran a command in the silo")
		return 0, "", nil
	}
	r, err := ingress.Apply(ctx, noExec, call, kong.Driver{}, p, "")
	if err != nil || !r.Changed || len(calls) != 1 || calls[0].Path != "/config" {
		t.Fatalf("first: %+v %v %v", r, err, calls)
	}
	if r, err := ingress.Apply(ctx, noExec, call, kong.Driver{}, p, r.Hash); err != nil || r.Changed || len(calls) != 1 {
		t.Fatalf("unchanged: %+v %v", r, err)
	}
	status, body = 400, `{"name":"invalid declarative configuration","flattened_errors":[{"entity_name":"shop.plain.3"}]}`
	s := kictest.Sample(nil)
	s.Routes = s.Routes[:3]
	p2, _ := kong.Driver{}.Render(s)
	s.Routes = kictest.Sample(nil).Routes
	p3, _ := kong.Driver{}.Render(s)
	if r, err := ingress.Apply(ctx, noExec, call, kong.Driver{}, p2, p3.Hash()); err != nil || r.Changed || !strings.HasPrefix(r.Rejected, "400:") {
		t.Fatalf("refused: %+v %v", r, err)
	}
	if r, err := ingress.Apply(ctx, noExec, nil, kong.Driver{}, p2, ""); err == nil {
		t.Fatalf("no way to reach the admin API: %+v", r)
	}
}

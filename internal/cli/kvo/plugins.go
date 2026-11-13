package kvo

// kvo plugins (design §10, ADR 0008): client-side programs installed per user from a signed index
// and run as `kvo NAME …`. A built-in command always wins: a plugin can't take one's name.
//
//	kvo plugin search [TERM]                 every index's plugins (and whether this OS has a build)
//	kvo plugin install NAME[@VERSION]        the build for this OS and CPU, verified, in your own folder
//	kvo plugin list                          what's installed, and from where
//	kvo plugin upgrade [NAME]                to the newest release (all of them without NAME)
//	kvo plugin remove NAME
//	kvo plugin index add URL --key ed25519:… [--name N]   trust another publisher's index (N/foo)
//	kvo plugin index list | kvo plugin index remove N
//	kvo plugin token [--context NAME]        for plugins: a short-lived access token, as JSON
//	kvo NAME [ARGS…]                         run an installed plugin in the current context

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/kvoplugin"
)

// builtinCommands are kvo's own commands and the names kept for later; a plugin never shadows one.
// TestBuiltinsCoverRun checks every command Run knows is here.
var builtinCommands = map[string]bool{
	"login": true, "logout": true, "ctx": true, "ns": true, "auth": true, "apply": true, "get": true,
	"describe": true, "create": true, "secret": true, "move": true, "pane": true, "approve": true,
	"deny": true, "open": true, "close": true, "delete": true, "watch": true, "scale": true,
	"reset": true, "protect": true, "exec": true, "ssh": true, "cp": true, "ui": true, "plugin": true,
	// kept: kvo will want these, and a plugin by that name would confuse people
	"help": true, "version": true, "completion": true, "config": true, "kvo": true, "edit": true,
	"logs": true, "run": true, "ip": true, "ips": true, "image": true, "images": true,
}

// Builtin reports whether name is one of kvo's own commands (or kept for one).
func Builtin(name string) bool { return builtinCommands[name] }

// Executable is kvo's own path, handed to plugins so they can run `kvo plugin token` (tests point
// it at a built kvo).
var Executable = os.Executable

// newPluginManager is the plugin manager for this user (tests replace it).
var newPluginManager = func() (*kvoplugin.Manager, error) {
	m, err := kvoplugin.New()
	if err != nil {
		return nil, err
	}
	m.Reserved = Builtin
	return m, nil
}

// pluginDispatch runs `kvo plugin …` and installed plugins; ok is false for anything else, which
// Run handles as before.
func pluginDispatch(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, bool) {
	if args[0] == "plugin" {
		if err := pluginCommand(ctx, args[1:], stdout, stderr); err != nil {
			_, _ = fmt.Fprintln(stderr, "kvo:", err)
			if errors.Is(err, errUsage) {
				return 2, true
			}
			return 1, true
		}
		return 0, true
	}
	if Builtin(args[0]) || strings.HasPrefix(args[0], "-") {
		return 0, false
	}
	if _, _, err := kvoplugin.ParseRef(args[0]); err != nil {
		return 0, false
	}
	m, err := newPluginManager()
	if err != nil {
		return 0, false
	}
	p, ok, err := m.Installed(args[0])
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "kvo:", err)
		return 1, true
	}
	if !ok {
		return 0, false
	}
	return runPlugin(p, args[1:], stdin, stdout, stderr), true
}

// pluginSession is the current context as a plugin sees it: where the cluster is, the CA to pin,
// the default namespace. No credentials.
func pluginSession() (kvoplugin.Session, error) {
	var s kvoplugin.Session
	exe, err := Executable()
	if err != nil {
		return s, err
	}
	s.Kvo = exe
	s.Namespace = "default"
	if srv := os.Getenv("KVO_SERVER"); srv != "" {
		s.Server = srv
		if strings.HasPrefix(srv, "https://") {
			s.CAFile = os.Getenv("KVO_CA_FILE")
		}
		return s, nil
	}
	path, err := kvoconfig.Path()
	if err != nil {
		return s, err
	}
	cfg, err := kvoconfig.Load(path)
	if err != nil {
		return s, err
	}
	if len(cfg.Contexts) == 0 {
		s.Server = DefaultServer
		return s, nil
	}
	name, kc, err := cfg.Resolve("")
	if err != nil {
		return s, err
	}
	s.Context, s.CAFile = name, kc.CA
	if servers := client.SplitServers(kc.Server); len(servers) > 0 {
		s.Server = servers[0]
	}
	if kc.Namespace != "" {
		s.Namespace = kc.Namespace
	}
	return s, nil
}

func runPlugin(p kvoplugin.Manifest, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	s, err := pluginSession()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "kvo:", err)
		return 1
	}
	cmd := p.Command(s, args, os.Environ())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return exit.ExitCode()
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "kvo: %s: %v (kvo plugin install %s again?)\n", p.Ref(), err, p.Ref())
		return 1
	}
	return 0
}

var errUsage = errors.New("usage: kvo plugin search|install|list|upgrade|remove|index|token")

// pluginFlags reads the few flags kvo plugin takes; the rest are positional.
func pluginFlags(args []string, names ...string) (map[string]string, []string, error) {
	flags := map[string]string{}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			pos = append(pos, a)
			continue
		}
		k, v, hasV := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		known := false
		for _, n := range names {
			known = known || n == k
		}
		if !known {
			return nil, nil, fmt.Errorf("unknown flag %s", a)
		}
		if !hasV {
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("%s needs a value", a)
			}
			i++
			v = args[i]
		}
		flags[k] = v
	}
	return flags, pos, nil
}

func pluginCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	if args[0] == "token" { // run by plugins; needs no plugin folder
		return pluginToken(ctx, args[1:], stdout)
	}
	m, err := newPluginManager()
	if err != nil {
		return err
	}
	flags, pos, err := pluginFlags(args[1:], "key", "name")
	if err != nil {
		return err
	}
	one := func(what string) (string, error) {
		if len(pos) != 1 {
			return "", fmt.Errorf("kvo plugin %s needs one %s", args[0], what)
		}
		return pos[0], nil
	}
	switch args[0] {
	case "search":
		return pluginSearch(ctx, m, strings.Join(pos, " "), stdout, stderr)
	case "list":
		return pluginList(m, stdout)
	case "install":
		ref, err := one("NAME[@VERSION]")
		if err != nil {
			return err
		}
		ref, version, _ := strings.Cut(ref, "@")
		p, err := m.Install(ctx, ref, version)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "installed %s %s for %s/%s (sha256 %s… verified)\nrun it with: kvo %s\n",
			p.Ref(), p.Version, p.OS, p.Arch, p.SHA256[:12], p.Ref())
		return nil
	case "upgrade":
		if len(pos) > 1 {
			return errors.New("kvo plugin upgrade takes at most one NAME")
		}
		ref := ""
		if len(pos) == 1 {
			ref = pos[0]
		}
		ups, err := m.Upgrade(ctx, ref)
		for _, u := range ups {
			if u.From == u.To {
				_, _ = fmt.Fprintf(stdout, "%s %s is the newest\n", u.Ref, u.To)
			} else {
				_, _ = fmt.Fprintf(stdout, "upgraded %s %s → %s\n", u.Ref, u.From, u.To)
			}
		}
		return err
	case "remove", "uninstall":
		ref, err := one("NAME")
		if err != nil {
			return err
		}
		p, err := m.Remove(ref)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "removed %s %s\n", p.Ref(), p.Version)
		return nil
	case "index":
		return pluginIndex(ctx, m, pos, flags, stdout)
	}
	return errUsage
}

func pluginSearch(ctx context.Context, m *kvoplugin.Manager, term string, stdout, stderr io.Writer) error {
	found, errs := m.Search(ctx, term)
	for _, err := range errs {
		_, _ = fmt.Fprintln(stderr, "kvo:", err)
	}
	if len(found) == 0 {
		if len(errs) > 0 {
			return errors.New("no index could be read")
		}
		_, _ = fmt.Fprintln(stdout, "no plugins found")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tVERSION\tINSTALLED\tDESCRIPTION")
	for _, f := range found {
		v := f.Latest
		if !f.Available {
			v = "no build for " + m.Platform.String()
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Ref, v, dash(f.Installed), f.Description)
	}
	return tw.Flush()
}

func pluginList(m *kvoplugin.Manager, stdout io.Writer) error {
	ps, err := m.List()
	if err != nil {
		return err
	}
	if len(ps) == 0 {
		_, _ = fmt.Fprintln(stdout, "no plugins installed (kvo plugin search)")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tVERSION\tPLATFORM\tINDEX\tINSTALLED")
	for _, p := range ps {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s/%s\t%s\t%s\n", p.Ref(), p.Version, p.OS, p.Arch, p.Index, p.InstalledAt.Format("2006-01-02"))
	}
	return tw.Flush()
}

func pluginIndex(ctx context.Context, m *kvoplugin.Manager, pos []string, flags map[string]string, stdout io.Writer) error {
	if len(pos) == 0 {
		return errors.New("kvo plugin index add|list|remove")
	}
	switch pos[0] {
	case "list":
		ixs, err := m.Indexes()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "NAME\tURL\tKEY")
		for _, ix := range ixs {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", ix.Name, ix.URL, dash(ix.Key))
		}
		return tw.Flush()
	case "add":
		if len(pos) != 2 || flags["key"] == "" {
			return errors.New("kvo plugin index add URL --key ed25519:… [--name NAME]")
		}
		ref, err := m.AddIndex(ctx, pos[1], flags["key"], flags["name"])
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "added index %s (signature verified); its plugins are %s/NAME\n", ref.Name, ref.Name)
		return nil
	case "remove":
		if len(pos) != 2 {
			return errors.New("kvo plugin index remove NAME")
		}
		if err := m.RemoveIndex(pos[1]); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "removed index %s\n", pos[1])
		return nil
	}
	return errors.New("kvo plugin index add|list|remove")
}

// pluginToken prints a short-lived access token for the plugin's context ($KVO_PLUGIN_CONTEXT, so
// switching contexts meanwhile doesn't move a running plugin; else --context or the current one),
// as JSON. The refresh token stays in kvo's token store.
func pluginToken(ctx context.Context, args []string, stdout io.Writer) error {
	flags, pos, err := pluginFlags(args, "context")
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return errors.New("kvo plugin token [--context NAME]")
	}
	var t kvoplugin.Token
	name, set := flags["context"], true
	if name == "" {
		name, set = os.LookupEnv(kvoplugin.EnvContext)
	}
	switch {
	case os.Getenv("KVO_TOKEN") != "":
		t.Token = os.Getenv("KVO_TOKEN") // the caller's own token for CI: it's already in their environment
	case set && name == "", !set && os.Getenv("KVO_SERVER") != "":
		// a dev server (kevasod dev) without sign-in: no token
	default:
		path, err := kvoconfig.Path()
		if err != nil {
			return err
		}
		cfg, err := kvoconfig.Load(path)
		if err != nil {
			return err
		}
		if t.Token, t.ExpiresAt, err = cfg.AccessToken(ctx, path, name); err != nil {
			return err
		}
	}
	return json.NewEncoder(stdout).Encode(t)
}

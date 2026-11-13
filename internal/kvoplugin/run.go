package kvoplugin

import (
	"os/exec"
	"strings"
	"time"
)

// What kvo hands a plugin, as environment variables (ADR 0008). Nothing here is a credential: the
// plugin asks `"$KVO_PLUGIN_KVO" plugin token` for a short-lived access token when it needs one.
const (
	EnvName      = "KVO_PLUGIN_NAME"      // "panes", or "acme/foo"
	EnvVersion   = "KVO_PLUGIN_VERSION"   // the installed version
	EnvDir       = "KVO_PLUGIN_DIR"       // the plugin's own folder (read-only by convention)
	EnvKvo       = "KVO_PLUGIN_KVO"       // kvo's own path, to run `plugin token`
	EnvContext   = "KVO_PLUGIN_CONTEXT"   // the kvo context it runs in ("" for a dev server)
	EnvServer    = "KVO_PLUGIN_SERVER"    // the control plane's URL
	EnvCAFile    = "KVO_PLUGIN_CA_FILE"   // the cluster CA to pin (PEM); "" for a plain-http dev server
	EnvNamespace = "KVO_PLUGIN_NAMESPACE" // the context's default namespace
)

// Session is the context a plugin runs in.
type Session struct {
	Context, Server, CAFile, Namespace string
	Kvo                                string // kvo's own executable
}

// Token is what `kvo plugin token` prints, as JSON: an access token and when it expires (zero
// when kvo doesn't know, an empty token when the cluster takes none).
type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
}

// Env is environ with the plugin's variables set (any KVO_PLUGIN_* already there is replaced, so
// a parent can't pass a plugin a context it didn't pick).
func Env(environ []string, p Manifest, s Session) []string {
	var out []string
	for _, kv := range environ {
		if !strings.HasPrefix(kv, "KVO_PLUGIN_") {
			out = append(out, kv)
		}
	}
	for _, kv := range [][2]string{
		{EnvName, p.Ref()}, {EnvVersion, p.Version}, {EnvDir, p.Dir}, {EnvKvo, s.Kvo},
		{EnvContext, s.Context}, {EnvServer, s.Server}, {EnvCAFile, s.CAFile}, {EnvNamespace, s.Namespace},
	} {
		out = append(out, kv[0]+"="+kv[1])
	}
	return out
}

// Command is the plugin's program with args and the session in its environment. It isn't tied to
// a context: the plugin shares kvo's terminal and gets its signals (Ctrl-C) itself.
func (p Manifest) Command(s Session, args, environ []string) *exec.Cmd {
	cmd := exec.Command(p.Program(), args...)
	cmd.Env = Env(environ, p, s)
	return cmd
}

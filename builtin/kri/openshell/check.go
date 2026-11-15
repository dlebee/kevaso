package openshell

import (
	"fmt"
	"regexp"
	"strings"

	"kevaso.com/core/sdk/kri"
)

// K-066: a credential's names reach a command kevasod runs as root (its env name is set in the
// CLI's environment and named in its arguments) and the text of a provider profile (its name,
// env, header and host). They are checked where they're used, whatever admission said.
var (
	envName    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	headerName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	hostName   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}$`)
	secretName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// reservedEnv are variables the CLI (or anything it loads) acts on.
var reservedEnv = []string{"HOME", "PATH", "SHELL", "USER", "TMPDIR", "IFS", "ENV", "BASH_ENV"}

// CheckEnvName refuses an env name that isn't a plain variable name, or one the CLI, the dynamic
// linker or the shell acts on.
func CheckEnvName(env string) error {
	if !envName.MatchString(env) {
		return fmt.Errorf("env %q: a variable name is A-Z, 0-9 and _, at most 64", env)
	}
	for _, p := range []string{"LD_", "OPENSHELL_", "XDG_", "GCONV_", "MALLOC_"} {
		if strings.HasPrefix(env, p) {
			return fmt.Errorf("env %q: %s* variables steer the programs that receive them", env, p)
		}
	}
	for _, r := range reservedEnv {
		if env == r {
			return fmt.Errorf("env %q: a variable the programs that receive it act on", env)
		}
	}
	return nil
}

// CheckCredential checks every name of c that a command or a profile takes.
func CheckCredential(c kri.Credential) error {
	if err := CheckEnvName(c.Env); err != nil {
		return fmt.Errorf("secret %s: %w", c.Name, err)
	}
	switch {
	case !secretName.MatchString(c.Name):
		return fmt.Errorf("secret %q: not a name", c.Name)
	case !headerName.MatchString(c.Header):
		return fmt.Errorf("secret %s: header %q: not a header name", c.Name, c.Header)
	case !hostName.MatchString(c.Host):
		return fmt.Errorf("secret %s: host %q: not a host name", c.Name, c.Host)
	}
	return nil
}

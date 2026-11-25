package kvoadm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/admconfig"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/pki"
)

// userRole is a kvo user's certificate role: no power of its own, only what RBAC binds to the name.
const userRole = "user"

// kvoUserRole is the built-in role kvoadm init binds kvo's user to, in every namespace.
const kvoUserRole = "editor"

// kvoUser sets up daily kvo for name: a namespace to start in (default), a ClusterRoleBinding of
// the editor role to the name, a user certificate (role user) signed over conn, and the kvo
// context that uses it. kvo never holds the admin certificate.
// target is how kvoadm reaches the system node again (its name in the cluster folder), for the
// renewal hint: the server's address with root@ is wrong where root can't log in over SSH.
func kvoUser(ctx context.Context, c *client.Client, run runner, name, cluster, server, target string, ca []byte, cfgPath string, say func(string, ...any)) error {
	ns := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "default"}}
	if err := c.Create(ctx, ns); err != nil && !client.IsAlreadyExists(err) {
		return err
	}
	b := &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "kvo-user-" + name},
		RoleRef:    v1.RoleRef{Kind: "ClusterRole", Name: kvoUserRole},
		Subjects:   []v1.Subject{{Kind: "User", Name: name}}}
	if err := c.Create(ctx, b); err != nil && !client.IsAlreadyExists(err) {
		return err
	}
	keyPEM, certPEM, _, err := signUserOverSSHAs(ctx, run, name, userRole)
	if err != nil {
		return err
	}
	if err := kvoconfig.AddContext(cfgPath, cluster, server, ca, certPEM, keyPEM); err != nil {
		return err
	}
	say("kvo context %q written to %s: user %s, %s in every namespace (namespace default to start in)", cluster, cfgPath, name, kvoUserRole)
	if cert, err := pki.ParseCertificatePEM(certPEM); err == nil {
		say("kvo's certificate is valid until %s. After that, run: %s", cert.NotAfter.UTC().Format("2006-01-02"), KvoRenewHint(target, name, server))
	}
	return nil
}

// adminKvoConfig writes the cluster folder's kvo-admin.yaml, a kvo config whose one context is
// the admin certificate in the folder (with the CA beside it), and returns its path. It is local:
// the folder's .gitignore keeps it out.
func adminKvoConfig(kc *admconfig.Config) (string, error) {
	if kc.Local.Certificate == "" || kc.Local.Key == "" {
		return "", fmt.Errorf("cluster %s: no admin credential on this machine (%s)", kc.Cluster(), kc.LocalPath())
	}
	ca := filepath.Join(kc.Folder(), "ca.crt")
	if err := os.WriteFile(ca, kc.CAPEM(), 0o644); err != nil {
		return "", err
	}
	ctx := kc.Context()
	ctx.CA = ca
	path := filepath.Join(kc.Folder(), "kvo-admin.yaml")
	cfg := kvoconfig.Config{CurrentContext: kc.Cluster(), Contexts: map[string]kvoconfig.Context{kc.Cluster(): ctx}}
	if err := cfg.Save(path); err != nil {
		return "", err
	}
	return path, nil
}

// kvoAsAdmin: kvoadm kvo [--cluster NAME] ARGS… runs kvo as the cluster's admin, with the
// credential in the cluster folder (namespaces, hosts, cluster secrets: what kvo's user can't).
func kvoAsAdmin(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	rest, cluster, err := takeClusterLeading(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return errors.New("kvoadm kvo [--cluster NAME] ARGS… (any kvo command, as the cluster's admin)")
	}
	kc, err := loadCluster(cluster)
	if err != nil {
		return err
	}
	path, err := adminKvoConfig(kc)
	if err != nil {
		return err
	}
	old, had := os.LookupEnv("KVO_CONFIG")
	_ = os.Setenv("KVO_CONFIG", path)
	defer func() {
		if had {
			_ = os.Setenv("KVO_CONFIG", old)
		} else {
			_ = os.Unsetenv("KVO_CONFIG")
		}
	}()
	if code := kvo.Run(ctx, rest, stdin, stdout, stderr); code != 0 {
		return exitCode(code)
	}
	return nil
}

// takeClusterLeading takes --cluster NAME only before the kvo command, so kvo's own flags pass.
func takeClusterLeading(args []string) ([]string, string, error) {
	if len(args) >= 1 && args[0] == "--cluster" {
		if len(args) < 2 {
			return nil, "", errors.New("--cluster needs a value")
		}
		return args[2:], args[1], nil
	}
	return args, "", nil
}

// exitCode is a command's exit code passed up as an error (kvo has printed its own message).
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

// KvoRenewHint is the command that renews kvo's certificate, as kvoadm prints it (pure): by the
// system node's name when kvoadm has one, else what kvo itself would say.
func KvoRenewHint(target, user, server string) string {
	if target == "" {
		return kvoconfig.CertRecovery(user, server)
	}
	return "kvoadm users resign " + target + " --name " + user + " --kvo"
}

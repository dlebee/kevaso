package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/kvoconfig"
)

// usersCmd runs kvoadm users invite|list|disable, as a cluster-admin of the current kvo context.
//
//	kvoadm users invite NAME [--group G]… [--namespace NS [--role editor]] [--ttl 15m] [--context C]
//	kvoadm users list
//	kvoadm users disable NAME
//	kvoadm users resign [USER@]ADDRESS --name USER [--context C] [--ssh-key PATH]
func usersCmd(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("users needs invite, list, disable or resign")
	}
	if args[0] == "resign" {
		return usersResign(ctx, args[1:], stdin, stdout)
	}
	var groups, rest []string
	var namespace, role, ttl, kctx string
	for i := 1; i < len(args); i++ {
		a := args[i]
		val := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		var v string
		switch a {
		case "--group":
			v, err = val()
			groups = append(groups, v)
		case "--namespace", "-n":
			namespace, err = val()
		case "--role":
			role, err = val()
		case "--ttl":
			ttl, err = val()
		case "--context":
			kctx, err = val()
		default:
			if strings.HasPrefix(a, "-") {
				return fmt.Errorf("unknown flag %s", a)
			}
			rest = append(rest, a)
		}
		if err != nil {
			return err
		}
	}
	path, err := kvoconfig.Path()
	if err != nil {
		return err
	}
	cfg, err := kvoconfig.Load(path)
	if err != nil {
		return err
	}
	c, name, err := cfg.Client(path, kctx)
	if err != nil {
		return err
	}
	switch args[0] {
	case "invite":
		if len(rest) != 1 {
			return errors.New("users invite needs NAME")
		}
		user := rest[0]
		if role != "" && namespace == "" {
			return errors.New("--role needs --namespace")
		}
		var inv client.InviteResponse
		if err := c.Call(ctx, http.MethodPost, "/admin/invites", client.InviteRequest{User: user, Groups: groups, TTL: ttl}, &inv); err != nil {
			return err
		}
		if namespace != "" {
			if role == "" {
				role = "editor"
			}
			rb := &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
				ObjectMeta: meta.ObjectMeta{Name: user + "-" + role, Namespace: namespace},
				RoleRef:    v1.RoleRef{Kind: "ClusterRole", Name: role}, Subjects: []v1.Subject{{Kind: "User", Name: user}}}
			if err := c.Create(ctx, rb); err != nil && !client.IsAlreadyExists(err) {
				return fmt.Errorf("binding %s as %s in %s: %w", user, role, namespace, err)
			}
			_, _ = fmt.Fprintf(stdout, "→ %s is %s in namespace %s\n", user, role, namespace)
		}
		_, _ = fmt.Fprintf(stdout, "→ invite for %s, valid until %s. Send them both lines:\n\n", user, inv.Expires.Local().Format("15:04 MST"))
		_, _ = fmt.Fprintf(stdout, "    kvo login %s --ca %s\n", cfg.Contexts[name].Server, inv.CAFingerprint)
		_, _ = fmt.Fprintf(stdout, "    invite code: %s\n\n", inv.Code)
		_, _ = fmt.Fprintln(stdout, "The code works once; the browser asks for it.")
		return nil
	case "list":
		var out struct{ Items []client.User }
		if err := c.Call(ctx, http.MethodGet, "/admin/users", nil, &out); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 3, ' ', 0)
		_, _ = fmt.Fprintln(tw, "NAME\tGROUPS\tSTATUS\tCREATED")
		for _, u := range out.Items {
			st := "active"
			if u.Disabled {
				st = "disabled"
			}
			g := strings.Join(u.Groups, ",")
			if g == "" {
				g = "-"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", u.Name, g, st, u.Created.Local().Format("2006-01-02"))
		}
		return tw.Flush()
	case "disable":
		if len(rest) != 1 {
			return errors.New("users disable needs NAME")
		}
		if err := c.Call(ctx, http.MethodPost, "/admin/users/"+rest[0]+"/disable", nil, nil); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "→ %s is disabled; their sessions ended\n", rest[0])
		return nil
	}
	return fmt.Errorf("unknown users command %q", args[0])
}

// usersResign signs a new client certificate over SSH and stores it on the named context.
// The key is made here. The control plane only sees the request.
func usersResign(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	var name, kctx string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 >= len(args) {
				return errors.New("--name needs a value")
			}
			i++
			name = args[i]
		case "--context":
			if i+1 >= len(args) {
				return errors.New("--context needs a value")
			}
			i++
			kctx = args[i]
		default:
			rest = append(rest, args[i])
		}
	}
	if name == "" {
		return errors.New("users resign needs --name USER")
	}
	o, err := parseTarget(rest)
	if err != nil {
		return err
	}
	defaultSSHKey(&o)
	if err := needCredential(o); err != nil {
		return err
	}
	path := os.Getenv("KVO_CONFIG")
	if path == "" {
		path, err = kvoconfig.Path()
		if err != nil {
			return err
		}
	}
	cfg, err := kvoconfig.Load(path)
	if err != nil {
		return err
	}
	n, c, err := cfg.Resolve(kctx)
	if err != nil {
		return err
	}
	if c.Certificate == "" || c.Key == "" {
		return fmt.Errorf("context %s has no certificate to replace", n)
	}
	conn, _, err := dialHost(ctx, o, bufio.NewReader(stdin), stdin, stdout)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	keyPEM, certPEM, _, err := signUserOverSSH(ctx, conn, name)
	if err != nil {
		return err
	}
	if err := installResignedCert(c.Key, c.Certificate, keyPEM, certPEM); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "certificate for %s written to context %s\n", name, n)
	return nil
}

// installResignedCert writes the new key and certificate where the context reads them.
func installResignedCert(keyPath, certPath string, keyPEM, certPEM []byte) error {
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, certPEM, 0o644)
}

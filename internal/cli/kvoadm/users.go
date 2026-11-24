package kvoadm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/admconfig"
	"kevaso.com/core/internal/kvoconfig"
)

// usersCmd runs kvoadm users invite|list|disable, as the cluster-admin of a cluster folder (--cluster).
//
//	kvoadm users invite NAME [--group G]… [--namespace NS [--role editor]] [--ttl 15m] [--cluster NAME]
//	kvoadm users list
//	kvoadm users disable NAME
//	kvoadm users resign [USER@]ADDRESS --name USER [--kvo] [--cluster NAME] [--ssh-key PATH]
//	  (the admin certificate in the cluster folder; --kvo: kvo's plain user certificate)
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
		case "--cluster":
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
	c, kc, err := adminClient(kctx)
	if err != nil {
		return err
	}
	_ = kc
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
		_, _ = fmt.Fprintf(stdout, "    kvo login %s --ca %s\n", kc.Server(), inv.CAFingerprint)
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
	var forKvo bool
	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--kvo":
			forKvo = true
		case "--name":
			if i+1 >= len(args) {
				return errors.New("--name needs a value")
			}
			i++
			name = args[i]
		case "--cluster":
			if i+1 >= len(args) {
				return errors.New("--cluster needs a value")
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
	kc, err := loadCluster(kctx)
	if err != nil {
		return err
	}
	prepareTarget(kc, &o)
	if err := needCredential(o); err != nil {
		return err
	}
	conn, _, err := dialHost(ctx, o, bufio.NewReader(stdin), stdin, stdout)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if forKvo { // kvo's plain user certificate, into kvo's context of the cluster's name
		keyPEM, certPEM, _, err := signUserOverSSHAs(ctx, conn, name, userRole)
		if err != nil {
			return err
		}
		path, err := kvoconfig.Path()
		if err != nil {
			return err
		}
		cfg, err := kvoconfig.Load(path)
		if err != nil {
			return err
		}
		c, ok := cfg.Contexts[kc.Cluster()]
		if !ok || c.Certificate == "" || c.Key == "" {
			return fmt.Errorf("kvo has no certificate context %s in %s", kc.Cluster(), path)
		}
		if err := installResignedCert(c.Key, c.Certificate, keyPEM, certPEM); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "kvo certificate for %s written to context %s\n", name, kc.Cluster())
		return nil
	}
	keyPEM, certPEM, _, err := signUserOverSSH(ctx, conn, name)
	if err != nil {
		return err
	}
	if err := kc.Update(func(c *admconfig.Config) error {
		if c.Local.Certificate == "" || c.Local.Key == "" {
			c.Local.Certificate, c.Local.Key = "admin.crt", "admin.key"
		}
		if c.Local.Admin == "" {
			c.Local.Admin = name
		}
		// A new admin's first run on this machine: their key, and the host key they just checked.
		if c.Local.SSHKey == "" && o.SSHKey != "" {
			if abs, err := filepath.Abs(o.SSHKey); err == nil {
				c.Local.SSHKey = abs
			}
		}
		if c.HasHost(o.Address) {
			c.RecordHost(o.Address, "", conn.Fingerprint)
		}
		return installResignedCert(c.File(c.Local.Key), c.File(c.Local.Certificate), keyPEM, certPEM)
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "certificate for %s written to cluster %s (%s)\n", name, kc.Cluster(), kc.Folder())
	return nil
}

// installResignedCert writes the new key and certificate where the context reads them.
func installResignedCert(keyPath, certPath string, keyPEM, certPEM []byte) error {
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, certPEM, 0o644)
}

package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Secrets from the command line (design §8.4): values come from a file or stdin, never from
// argv (which other users of the machine and shell history can see); --from-literal needs --i-know.
//
//	kvo create secret NAME (--from-file F | --from-file - | --generate) [--type opaque|ed25519|ecdsa-p256]
//	        [--write-only] [--allow broker,inject,…] [-l KEY=VALUE]…
//	kvo secret set NAME --from-file F|-       a new value (rotation): every silo using it gets it
//	kvo get secret NAME --reveal              print the value (needs read-value; never write-only)
type secretOpts struct {
	fromFile, fromLiteral, typ string
	literalSet, iKnow          bool
	generate, writeOnly        bool
	reveal                     bool
	allow, labels              []string
}

func (o secretOpts) value(stdin io.Reader) ([]byte, error) {
	switch {
	case o.literalSet && !o.iKnow:
		return nil, errors.New("--from-literal puts the value on the command line (shell history, ps): use --from-file FILE or --from-file - (stdin), or add --i-know")
	case o.literalSet:
		return []byte(o.fromLiteral), nil
	case o.fromFile == "-":
		b, err := io.ReadAll(io.LimitReader(stdin, 64<<10+1))
		return trimNewline(b), err
	case o.fromFile != "":
		b, err := os.ReadFile(o.fromFile)
		return trimNewline(b), err
	}
	return nil, nil
}

// trimNewline drops one trailing newline (echo and editors add it; tokens never mean it).
func trimNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

func createSecret(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("create secret needs a NAME: kvo create secret NAME --from-file FILE|-")
	}
	value, err := o.secret.value(stdin)
	if err != nil {
		return err
	}
	if value == nil && !o.secret.generate {
		return errors.New("a secret needs a value: --from-file FILE, --from-file - (stdin) or --generate")
	}
	s := &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: o.args[1], Namespace: defaultNS(o)},
		Spec:       v1.SecretSpec{Type: o.secret.typ, Generate: o.secret.generate, Value: value, AllowedDelivery: o.secret.allow}}
	if o.secret.writeOnly {
		f := false
		s.Spec.ValueReadable = &f
	}
	for _, l := range o.secret.labels {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			return fmt.Errorf("label %q: want KEY=VALUE", l)
		}
		if s.Labels == nil {
			s.Labels = map[string]string{}
		}
		s.Labels[k] = v
	}
	if err := c.Create(ctx, s); err != nil {
		return err
	}
	clear(value)
	msg := fmt.Sprintf("secret/%s created (version %d", s.Name, s.Status.Version)
	if s.Status.PublicKey != "" {
		msg += ", public key " + s.Status.PublicKey
	}
	_, _ = fmt.Fprintln(stdout, msg+")")
	return nil
}

func secretCommand(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	if len(o.args) != 2 || o.args[0] != "set" {
		return errors.New("usage: kvo secret set NAME --from-file FILE|-")
	}
	value, err := o.secret.value(stdin)
	if err != nil {
		return err
	}
	if value == nil {
		return errors.New("secret set needs the new value: --from-file FILE or --from-file - (stdin)")
	}
	defer clear(value)
	for attempt := 0; ; attempt++ {
		var s v1.Secret
		if err := c.Get(ctx, "Secret", defaultNS(o), o.args[1], &s); err != nil {
			return err
		}
		s.Spec.Value = value
		err := c.Update(ctx, &s)
		if client.IsConflict(err) && attempt < 3 {
			continue
		}
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "secret/%s: version %d\n", s.Name, s.Status.Version)
		return nil
	}
}

func revealSecret(ctx context.Context, c *client.Client, ns, name string, stdout io.Writer) error {
	p, err := client.Path("Secret", ns, name)
	if err != nil {
		return err
	}
	var v client.SecretValue
	if err := c.Call(ctx, http.MethodGet, p+"/value", nil, &v); err != nil {
		return err
	}
	defer clear(v.Value)
	_, err = stdout.Write(v.Value)
	return err
}

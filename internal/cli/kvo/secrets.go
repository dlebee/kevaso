package kvo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Secrets from the command line (design §8.4, hack/design/secret-keys.md): values come from a file
// or stdin, never from argv (which other users of the machine and shell history can see);
// --from-literal needs --i-know.
//
//	kvo create secret NAME (--from-file F | --from-file - | --from-file KEY=F… | --generate) [--type opaque|ed25519|ecdsa-p256]
//	        [--write-only] [--allow broker,inject,…] [-l KEY=VALUE]…
//	kvo create secret NAME --type registry --server HOST --username U --from-file - [--default-pull]
//	kvo secret set NAME --from-file F|-       a new value, the key value only (rotation): every silo using it gets it
//	kvo secret set NAME --from-file KEY=F…    set these keys, keep the others
//	kvo secret set NAME --remove-key KEY…     remove keys
//	kvo get secret NAME --reveal [--key KEY]  print the value (needs read-value; never write-only)
type secretOpts struct {
	fromFiles, fromLiterals []string
	removeKeys              []string
	key                     string // --reveal: one key
	typ                     string
	iKnow                   bool
	generate, writeOnly     bool
	reveal                  bool
	allow, labels           []string
	server, username        string // type registry
	defaultPull             bool   // type registry: the namespace's default for its server
}

// literalSet reports whether any value is to come from the command line.
func (o secretOpts) literalSet() bool { return len(o.fromLiterals) > 0 }

// splitKey splits KEY=REST when KEY is a key's name; ok false: the whole is a path.
func splitKey(s string) (key, rest string, ok bool) {
	k, r, found := strings.Cut(s, "=")
	if !found || !v1.ValidKey(k) {
		return "", s, false
	}
	return k, r, true
}

// keys reads what the flags give: value (a bare --from-file F|-, the key value) or data (KEY=F
// and KEY=VALUE literals). Neither: nil, nil.
func (o secretOpts) keys(stdin io.Reader) (value []byte, data map[string][]byte, err error) {
	if o.literalSet() && !o.iKnow {
		return nil, nil, errors.New("--from-literal puts the value on the command line (shell history, ps): use --from-file FILE or --from-file - (stdin), or add --i-know")
	}
	stdinUsed := false
	read := func(f string) ([]byte, error) {
		if f == "-" {
			if stdinUsed {
				return nil, errors.New("--from-file -: stdin can give one value")
			}
			stdinUsed = true
			b, err := io.ReadAll(io.LimitReader(stdin, 64<<10+1))
			return trimNewline(b), err
		}
		b, err := os.ReadFile(f)
		return trimNewline(b), err
	}
	defer func() {
		if err != nil {
			clear(value)
			for _, b := range data {
				clear(b)
			}
			value, data = nil, nil
		}
	}()
	set := func(k string, b []byte) error {
		if data == nil {
			data = map[string][]byte{}
		}
		if _, dup := data[k]; dup {
			return fmt.Errorf("key %s is given twice", k)
		}
		data[k] = b
		return nil
	}
	for _, f := range o.fromFiles {
		k, path, keyed := splitKey(f)
		if !keyed {
			if value != nil || len(o.fromFiles) > 1 {
				return nil, nil, fmt.Errorf("--from-file %s: with several --from-file, each is KEY=FILE", f)
			}
			if value, err = read(path); err != nil {
				return nil, nil, err
			}
			continue
		}
		b, rerr := read(path)
		if rerr != nil {
			return nil, nil, rerr
		}
		if err = set(k, b); err != nil {
			return nil, nil, err
		}
	}
	for _, l := range o.fromLiterals {
		k, v, keyed := splitKey(l)
		if !keyed {
			return nil, nil, fmt.Errorf("--from-literal: KEY=VALUE (the key value for a single value: --from-literal value=…)")
		}
		if err = set(k, []byte(v)); err != nil {
			return nil, nil, err
		}
	}
	if value != nil && data != nil {
		return nil, nil, errors.New("--from-file FILE (the one value) and KEY=… can't be mixed: name every key")
	}
	return value, data, nil
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

// keysNote is ", keys a, b" for a secret holding named keys ("" for the one value).
func keysNote(keys []string) string {
	if len(keys) == 0 || v1.SingleValue(keys) {
		return ""
	}
	return ", keys " + strings.Join(keys, ", ")
}

func clearData(d map[string][]byte) {
	for _, b := range d {
		clear(b)
	}
}

func createSecret(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("create secret needs a NAME: kvo create secret NAME --from-file FILE|-")
	}
	if len(o.secret.removeKeys) > 0 {
		return errors.New("--remove-key is for kvo secret set")
	}
	value, data, err := o.secret.keys(stdin)
	if err != nil {
		return err
	}
	defer clear(value)
	defer clearData(data)
	if value == nil && data == nil && !o.secret.generate {
		return errors.New("a secret needs a value: --from-file FILE, --from-file - (stdin), --from-file KEY=FILE (repeatable) or --generate")
	}
	s := &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: o.args[1], Namespace: defaultNS(o)},
		Spec:       v1.SecretSpec{Type: o.secret.typ, Generate: o.secret.generate, Value: value, Data: data, AllowedDelivery: o.secret.allow}}
	if o.secret.writeOnly {
		f := false
		s.Spec.ValueReadable = &f
	}
	if err := registrySecret(s, o.secret); err != nil {
		return err
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
	msg := fmt.Sprintf("secret/%s created (version %d%s", s.Name, s.Status.Version, keysNote(s.Status.Keys))
	if s.Status.PublicKey != "" {
		msg += ", public key " + s.Status.PublicKey
	}
	_, _ = fmt.Fprintln(stdout, msg+")")
	return nil
}

func secretCommand(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	if len(o.args) != 2 || o.args[0] != "set" {
		return errors.New("usage: kvo secret set NAME (--from-file FILE|- | --from-file KEY=FILE… | --remove-key KEY…)")
	}
	value, data, err := o.secret.keys(stdin)
	if err != nil {
		return err
	}
	defer clear(value)
	defer clearData(data)
	if value != nil && len(o.secret.removeKeys) > 0 {
		return errors.New("--from-file FILE replaces every key already: --remove-key goes with KEY=FILE, or alone")
	}
	if value == nil && data == nil && len(o.secret.removeKeys) == 0 {
		return errors.New("secret set needs the new value: --from-file FILE, --from-file - (stdin), --from-file KEY=FILE (repeatable) or --remove-key KEY")
	}
	var s v1.Secret
	if err := retryUpdate(func() error {
		if err := c.Get(ctx, "Secret", defaultNS(o), o.args[1], &s); err != nil {
			return err
		}
		s.Spec.Value, s.Spec.SetData, s.Spec.RemoveKeys = value, data, o.secret.removeKeys
		return c.Update(ctx, &s)
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "secret/%s: version %d%s\n", s.Name, s.Status.Version, keysNote(s.Status.Keys))
	return nil
}

// revealValue prints a secret's (or a cluster secret's) value: one key's bytes with key, the
// shorthand's value as it is, otherwise every key as KEY: VALUE lines.
func revealValue(ctx context.Context, c *client.Client, kind, ns, name, key string, stdout io.Writer) error {
	p, err := client.Path(kind, ns, name)
	if err != nil {
		return err
	}
	p += "/value"
	if key != "" {
		p += "?key=" + url.QueryEscape(key)
	}
	var v client.SecretValue
	if err := c.Call(ctx, http.MethodGet, p, nil, &v); err != nil {
		return err
	}
	defer clear(v.Value)
	defer clearData(v.Data)
	if key != "" {
		_, err = stdout.Write(v.Value)
		return err
	}
	if b, ok := v.Data[v1.ValueKey]; ok && len(v.Data) == 1 {
		_, err = stdout.Write(b)
		return err
	}
	keys := make([]string, 0, len(v.Data))
	for k, b := range v.Data {
		if !utf8.Valid(b) || bytes.ContainsAny(b, "\r\n") {
			return fmt.Errorf("key %s isn't one line of text: print it alone with --key %s", k, k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out bytes.Buffer
	for _, k := range keys {
		out.WriteString(k + ": ")
		out.Write(v.Data[k])
		out.WriteByte('\n')
	}
	_, err = stdout.Write(out.Bytes())
	clear(out.Bytes())
	return err
}

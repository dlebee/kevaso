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
// --from-literal needs --i-know. Every key is named: nothing is implied.
//
//	kvo create secret NAME (--from-file KEY=F|KEY=-… | --generate KEY) [--type opaque|ed25519|ecdsa-p256]
//	        [--write-only] [--allow broker,inject,…] [-l KEY=VALUE]…
//	kvo create secret NAME --type registry --server HOST --username U --from-file password=- [--default-pull]
//	kvo secret set NAME --from-file KEY=F|KEY=-…  set these keys, keep the others (rotation): every silo using it gets them
//	kvo secret set NAME --remove-key KEY…         remove keys
//	kvo get secret NAME --reveal --key KEY|"*"    print one key, or every key (needs read-value; never write-only)
type secretOpts struct {
	fromFiles, fromLiterals []string
	removeKeys              []string
	key                     string // --reveal: one key, or "*"
	typ                     string
	generate                string // the key to make
	iKnow                   bool
	writeOnly               bool
	reveal                  bool
	allow, labels           []string
	server, username        string // type registry
	defaultPull             bool   // type registry: the namespace's default for its server
}

// literalSet reports whether any value is to come from the command line.
func (o secretOpts) literalSet() bool { return len(o.fromLiterals) > 0 }

// splitKey splits KEY=REST when KEY is a key's name; ok false: no key named.
func splitKey(s string) (key, rest string, ok bool) {
	k, r, found := strings.Cut(s, "=")
	if !found || !v1.ValidKey(k) {
		return "", s, false
	}
	return k, r, true
}

// errFromFileForm is the answer to a --from-file that names no key.
func errFromFileForm(f string) error {
	return fmt.Errorf("--from-file %s: name the key: --from-file KEY=FILE, or --from-file KEY=- for stdin (e.g. --from-file token=%s)", f, f)
}

// keys reads what the flags give: data, every key named (KEY=FILE, KEY=- and KEY=VALUE literals).
// None: nil.
func (o secretOpts) keys(stdin io.Reader) (data map[string][]byte, err error) {
	if o.literalSet() && !o.iKnow {
		return nil, errors.New("--from-literal puts the value on the command line (shell history, ps): use --from-file KEY=FILE or --from-file KEY=- (stdin), or add --i-know")
	}
	stdinUsed := false
	read := func(f string) ([]byte, error) {
		if f == "-" {
			if stdinUsed {
				return nil, errors.New("--from-file KEY=-: stdin can give one key")
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
			clearData(data)
			data = nil
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
		if !keyed || path == "" {
			return nil, errFromFileForm(f)
		}
		b, rerr := read(path)
		if rerr != nil {
			return nil, rerr
		}
		if err = set(k, b); err != nil {
			return nil, err
		}
	}
	for _, l := range o.fromLiterals {
		k, v, keyed := splitKey(l)
		if !keyed {
			return nil, fmt.Errorf("--from-literal %s: KEY=VALUE", strings.SplitN(l, "=", 2)[0])
		}
		if err = set(k, []byte(v)); err != nil {
			return nil, err
		}
	}
	return data, nil
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

// keysNote is ", keys a, b" (", key a" for one) for a secret's keys.
func keysNote(keys []string) string {
	switch len(keys) {
	case 0:
		return ""
	case 1:
		return ", key " + keys[0]
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
		return errors.New("create secret needs a NAME: kvo create secret NAME --from-file KEY=FILE")
	}
	if len(o.secret.removeKeys) > 0 {
		return errors.New("--remove-key is for kvo secret set")
	}
	data, err := o.secret.keys(stdin)
	if err != nil {
		return err
	}
	defer clearData(data)
	if data != nil && o.secret.generate != "" {
		return errors.New("--generate KEY makes the value: no --from-file with it")
	}
	if data == nil && o.secret.generate == "" {
		return errors.New("a secret needs at least one key: --from-file KEY=FILE, --from-file KEY=- (stdin; repeatable with other files), or --generate KEY")
	}
	s := &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: o.args[1], Namespace: defaultNS(o)},
		Spec:       v1.SecretSpec{Type: o.secret.typ, Generate: o.secret.generate, Data: data, AllowedDelivery: o.secret.allow}}
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
		return errors.New("usage: kvo secret set NAME (--from-file KEY=FILE|KEY=-… | --remove-key KEY…)")
	}
	data, err := o.secret.keys(stdin)
	if err != nil {
		return err
	}
	defer clearData(data)
	if data == nil && len(o.secret.removeKeys) == 0 {
		return errors.New("secret set needs the keys to change: --from-file KEY=FILE, --from-file KEY=- (stdin; repeatable) or --remove-key KEY")
	}
	var s v1.Secret
	if err := retryUpdate(func() error {
		if err := c.Get(ctx, "Secret", defaultNS(o), o.args[1], &s); err != nil {
			return err
		}
		s.Spec.SetData, s.Spec.RemoveKeys = data, o.secret.removeKeys
		return c.Update(ctx, &s)
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "secret/%s: version %d%s\n", s.Name, s.Status.Version, keysNote(s.Status.Keys))
	return nil
}

// revealValue prints a secret's (or a cluster secret's) value: one key's bytes (--key KEY), or
// every key as KEY: VALUE lines (--key "*").
func revealValue(ctx context.Context, c *client.Client, kind, ns, name, key string, stdout io.Writer) error {
	if key == "" {
		what := strings.ToLower(kind)
		return fmt.Errorf("--reveal needs --key: kvo get %s %s --reveal --key KEY for one key, or --key \"*\" for every key", what, name)
	}
	p, err := client.Path(kind, ns, name)
	if err != nil {
		return err
	}
	p += "/value?key=" + url.QueryEscape(key)
	var v client.SecretValue
	if err := c.Call(ctx, http.MethodGet, p, nil, &v); err != nil {
		return err
	}
	defer clear(v.Value)
	defer clearData(v.Data)
	if key != v1.AllKeys {
		_, err = stdout.Write(v.Value)
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

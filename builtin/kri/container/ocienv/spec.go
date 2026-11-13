package ocienv

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Var is one variable for the container's process.
type Var struct {
	Name  string
	Value []byte
}

// annotations reads the config's annotations (only those: process.env is never decoded here, so
// whatever the engine set there isn't copied about).
func annotations(config []byte) (map[string]string, error) {
	var c struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(config, &c); err != nil {
		return nil, fmt.Errorf("the bundle's config: %w", err)
	}
	return c.Annotations, nil
}

// member finds key in the JSON object obj: the bytes of its value are obj[start:end]. n is how
// many members the object has. A key that's there twice is an error: which one a runtime reads is
// its decoder's choice, and the variables must be in the one it reads.
func member(obj []byte, key string) (start, end, n int, found bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(obj))
	t, err := dec.Token()
	if err != nil {
		return 0, 0, 0, false, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return 0, 0, 0, false, errors.New("not an object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return 0, 0, 0, false, err
		}
		k, _ := t.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return 0, 0, 0, false, err
		}
		n++
		if k != key {
			continue
		}
		if found {
			return 0, 0, 0, false, fmt.Errorf("%q is there twice", key)
		}
		end = int(dec.InputOffset())
		start = end - len(raw)
		if start < 0 || !bytes.Equal(obj[start:end], raw) {
			return 0, 0, 0, false, fmt.Errorf("can't place %q", key)
		}
		found = true
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return 0, 0, 0, false, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return 0, 0, 0, false, errors.New("something after the object")
	}
	return start, end, n, found, nil
}

// SetEnv returns config (an OCI runtime config.json) with vars in process.env: a variable already
// there (from the image or the silo's own env) is replaced in place, the others are added after
// the engine's. Every byte outside process.env is kept as it was. A config with no process is an
// error: there's no process to give them to.
func SetEnv(config []byte, vars []Var) ([]byte, error) {
	for _, v := range vars {
		if !ValidName(v.Name) {
			return nil, fmt.Errorf("%q isn't a variable name", v.Name)
		}
		if !utf8.Valid(v.Value) || bytes.IndexByte(v.Value, 0) >= 0 {
			return nil, fmt.Errorf("the value of %s isn't valid UTF-8 text (the OCI config is JSON): deliver it as a file", v.Name)
		}
	}
	ps, pe, _, found, err := member(config, "process")
	if err != nil {
		return nil, fmt.Errorf("the bundle's config: %w", err)
	}
	if !found || bytes.Equal(config[ps:pe], []byte("null")) {
		return nil, errors.New("the bundle's config has no process to set the variables of")
	}
	proc := config[ps:pe]
	es, ee, n, hasEnv, err := member(proc, "env")
	if err != nil {
		return nil, fmt.Errorf("the bundle's config: process: %w", err)
	}
	var env []string
	if hasEnv {
		if err := json.Unmarshal(proc[es:ee], &env); err != nil {
			return nil, fmt.Errorf("the bundle's config: process.env: %w", err)
		}
	}
	text, err := envJSON(merge(env, vars))
	clearStrings(env)
	if err != nil {
		return nil, err
	}
	defer clear(text)
	var out bytes.Buffer
	out.Grow(len(config) + len(text) + 8)
	out.Write(config[:ps])
	if hasEnv {
		out.Write(proc[:es])
		out.Write(text)
		out.Write(proc[ee:])
	} else {
		i := bytes.IndexByte(proc, '{') + 1
		out.Write(proc[:i])
		out.WriteString(`"env":`)
		out.Write(text)
		if n > 0 {
			out.WriteByte(',')
		}
		out.Write(proc[i:])
	}
	out.Write(config[pe:])
	return out.Bytes(), nil
}

// merge is env with vars set: each replaces the first entry of its name (later ones of that name
// go), the rest are appended in vars' order.
func merge(env []string, vars []Var) []string {
	want := map[string]int{}
	for i, v := range vars {
		want[v.Name] = i
	}
	done := make([]bool, len(vars))
	out := make([]string, 0, len(env)+len(vars))
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		i, ok := want[name]
		if !ok {
			out = append(out, e)
			continue
		}
		if !done[i] {
			out = append(out, name+"="+string(vars[i].Value))
			done[i] = true
		}
	}
	for i, v := range vars {
		if !done[i] {
			out = append(out, v.Name+"="+string(v.Value))
		}
	}
	return out
}

func envJSON(env []string) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	err := enc.Encode(env)
	clearStrings(env)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// clearStrings drops the references (Go strings can't be overwritten; the garbage collector has
// them, in this short-lived process).
func clearStrings(l []string) { clear(l) }

// ValidName reports whether n is a portable variable name.
func ValidName(n string) bool {
	if n == "" {
		return false
	}
	for i, c := range n {
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// ParseEnvFile reads the host's env file: NAME=VALUE lines, as the container runtime writes them.
// An error names the line, never what's on it.
func ParseEnvFile(b []byte) ([]Var, error) {
	var vars []Var
	seen := map[string]bool{}
	for n, line := range bytes.Split(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		name, value, ok := bytes.Cut(line, []byte("="))
		if !ok || !ValidName(string(name)) {
			return nil, fmt.Errorf("line %d isn't NAME=VALUE", n+1)
		}
		if seen[string(name)] {
			return nil, fmt.Errorf("line %d: %s is there twice", n+1, name)
		}
		seen[string(name)] = true
		vars = append(vars, Var{Name: string(name), Value: value})
	}
	return vars, nil
}

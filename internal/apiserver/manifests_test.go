package apiserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	v1 "kevaso.com/core/api/v1"
)

// The repo's manifests are what people copy: every one in examples/ and docs/ (YAML files, fenced
// yaml blocks, and the printf '…' | kvo apply one-liners of the demos) decodes strictly and is
// admitted by the built-in kinds' rules, as kvo apply would send it.

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "examples")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no repo root above the test")
		}
		dir = parent
	}
}

var (
	fencedYAML = regexp.MustCompile("(?s)```ya?ml\n(.*?)```")
	printfDoc  = regexp.MustCompile(`printf '((?:[^'\\]|\\.)*apiVersion: kevaso/v1(?:[^'\\]|\\.)*)'`)
)

type manifest struct {
	where string
	doc   []byte // JSON
}

func docsOf(t *testing.T, where, text string) []manifest {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(text))
	var out []manifest
	for i := 0; ; i++ {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Errorf("%s: document %d isn't YAML: %v", where, i, err)
			return out
		}
		if doc == nil || doc["apiVersion"] == nil {
			continue
		}
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, manifest{where: where + "#" + string(rune('0'+i)), doc: b})
	}
}

func repoManifests(t *testing.T) []manifest {
	root := repoRoot(t)
	var out []manifest
	for _, top := range []string{"examples", "docs"} {
		_ = filepath.WalkDir(filepath.Join(root, top), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			switch filepath.Ext(p) {
			case ".yaml", ".yml":
				out = append(out, docsOf(t, rel, string(b))...)
			case ".md":
				for _, m := range fencedYAML.FindAllStringSubmatch(string(b), -1) {
					if strings.Contains(m[1], "apiVersion: kevaso/v1") {
						out = append(out, docsOf(t, rel, m[1])...)
					}
				}
				for _, m := range printfDoc.FindAllStringSubmatch(string(b), -1) {
					text := strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\\`, `\`).Replace(m[1])
					out = append(out, docsOf(t, rel+" (printf)", text)...)
				}
			}
			return nil
		})
	}
	return out
}

// stale are manifests known to be out of date, by file, with who fixes them: reported, not failed,
// so a fix elsewhere lands without a conflict here. Remove an entry once its file is fixed (the
// test says when).
var stale = map[string]string{
	"docs/notes/virtiofs-real-machine-checklist.md": "Silo spec.image predates ADR 0011 (vm: { image }): phase/lima-2 owns this file",
}

func TestEveryRepoManifestIsAdmitted(t *testing.T) {
	v, err := newValidator(builtinRules)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{valid: v}
	ms := repoManifests(t)
	if len(ms) < 10 {
		t.Fatalf("found only %d manifests: the walk is broken", len(ms))
	}
	kinds := map[string]int{}
	failed := map[string]bool{}
	errorf := func(where, f string, a ...any) {
		file := strings.SplitN(strings.SplitN(where, "#", 2)[0], " ", 2)[0]
		if why, ok := stale[file]; ok {
			failed[file] = true
			t.Logf("KNOWN STALE (%s): %s: %s", why, where, fmt.Sprintf(f, a...))
			return
		}
		t.Errorf("%s: %s", where, fmt.Sprintf(f, a...))
	}
	for _, m := range ms {
		var tm struct{ Kind string }
		_ = json.Unmarshal(m.doc, &tm)
		if tm.Kind == "PluginPackage" {
			continue // a plugin's package manifest, not an API object: internal/operators loads it strictly
		}
		obj, k, err := v1.DecodeStrict(m.doc)
		if err != nil {
			errorf(m.where, "%v", err)
			continue
		}
		if _, ok := obj.(*v1.Unstructured); ok {
			kinds["(defined) "+k.Kind]++
			continue // a KindDefinition's instance: checked against its schema by the server
		}
		obj, err = decodeStrict(m.doc, k)
		if err != nil {
			errorf(m.where, "%v", err)
			continue
		}
		kinds[k.Kind]++
		if _, err := s.admit(k.Kind, obj); err != nil {
			errorf(m.where, "%s %s refused: %v", k.Kind, obj.GetObjectMeta().Name, err)
		}
	}
	for file := range stale {
		if !failed[file] {
			t.Errorf("%s is listed as stale but all its manifests are admitted now: drop it from stale", file)
		}
	}
	t.Logf("%d manifests: %v", len(ms), kinds)
}

// Every built-in kind refuses a field it doesn't have, at the top, in metadata and in spec.
func TestEveryKindRefusesUnknownFields(t *testing.T) {
	for _, k := range v1.Kinds() {
		for where, doc := range map[string]string{
			"top":      `{"apiVersion":"kevaso/v1","kind":"` + k.Kind + `","metadata":{"name":"x"},"bogus":1}`,
			"metadata": `{"apiVersion":"kevaso/v1","kind":"` + k.Kind + `","metadata":{"name":"x","lables":{}}}`,
			"spec":     `{"apiVersion":"kevaso/v1","kind":"` + k.Kind + `","metadata":{"name":"x"},"spec":{"bogus":1}}`,
		} {
			if where == "spec" && !hasField(k, "spec") {
				continue
			}
			if _, err := decodeStrict([]byte(doc), k); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Errorf("%s with an unknown field in %s: %v", k.Kind, where, err)
			}
			if _, _, err := v1.DecodeStrict([]byte(doc)); err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Errorf("v1.DecodeStrict: %s with an unknown field in %s: %v", k.Kind, where, err)
			}
		}
	}
}

func hasField(k v1.KindInfo, name string) bool {
	b, _ := json.Marshal(k.New())
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	_, ok := m[name]
	return ok
}

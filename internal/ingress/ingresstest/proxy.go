// Package ingresstest is a pretend proxy silo for tests: a file system and the commands the
// applier runs (cat, ls, the write script, rm, mv), a config check and a reload, all recorded.
package ingresstest

import (
	"path"
	"slices"
	"sort"
	"strings"
	"sync"

	"kevaso.com/core/internal/ingress"
)

// Proxy is one silo's files and what was run in it.
type Proxy struct {
	mu      sync.Mutex
	Files   map[string][]byte
	Ran     []string // every command, argv joined by spaces (stdin never shown)
	Writes  []string // the paths written, in order
	Reloads int
	// CheckCmd and ReloadCmd are the driver's check and reload (argv[0], e.g. "nginx" and "-t");
	// Check, if set, refuses a staged config: it returns the check's output ("" passes).
	CheckCmd, ReloadCmd []string
	Check               func(config []byte, files map[string][]byte) string
}

// New is an empty proxy with nginx's check and reload.
func New() *Proxy {
	return &Proxy{Files: map[string][]byte{}, CheckCmd: []string{"nginx", "-t"}, ReloadCmd: []string{"nginx", "-s", "reload"}}
}

func prefix(argv, p []string) bool { return len(argv) >= len(p) && slices.Equal(argv[:len(p)], p) }

// Handle answers one command (the fake runtime's Handler shape, without the silo).
func (p *Proxy) Handle(argv []string, stdin []byte) (string, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Ran = append(p.Ran, strings.Join(argv, " "))
	write, list := ingress.WriteCmd("", ""), ingress.ListCmd("")
	switch {
	case len(argv) == 2 && argv[0] == "cat":
		if b, ok := p.Files[argv[1]]; ok {
			return string(b), 0
		}
		return "cat: no such file", 1
	case len(argv) == 5 && prefix(argv, list[:3]):
		var names []string
		for f := range p.Files {
			if path.Dir(f) == argv[4] {
				names = append(names, path.Base(f))
			}
		}
		sort.Strings(names)
		return strings.Join(names, "\n"), 0
	case len(argv) == 6 && prefix(argv, write[:3]):
		p.Files[argv[4]] = append([]byte(nil), stdin...)
		p.Writes = append(p.Writes, argv[4])
		return "", 0
	case len(argv) >= 2 && argv[0] == "rm":
		for _, f := range argv[2:] {
			delete(p.Files, f)
		}
		return "", 0
	case len(argv) == 4 && argv[0] == "mv":
		b, ok := p.Files[argv[2]]
		if !ok {
			return "mv: no such file", 1
		}
		p.Files[argv[3]] = b
		delete(p.Files, argv[2])
		return "", 0
	case prefix(argv, p.CheckCmd):
		cfg := p.Files[argv[len(argv)-1]]
		if p.Check != nil {
			if out := p.Check(cfg, p.Files); out != "" {
				return out, 1
			}
		}
		return "", 0
	case prefix(argv, p.ReloadCmd):
		p.Reloads++
		return "", 0
	}
	return "", 0
}

// Snapshot is a copy of the files and counters, safe to look at while the agent runs.
func (p *Proxy) Snapshot() (files map[string][]byte, writes []string, reloads int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	files = map[string][]byte{}
	for k, v := range p.Files {
		files[k] = v
	}
	return files, append([]string(nil), p.Writes...), p.Reloads
}

// Commands is a copy of every command run so far.
func (p *Proxy) Commands() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.Ran...)
}

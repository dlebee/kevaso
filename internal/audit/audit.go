// Package audit records who did (or tried to do) what (design §9.3: every decision, allowed or
// denied, is written down). Entries are JSON lines in a root-only file on the control plane.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one decision or event.
type Entry struct {
	Time      time.Time `json:"time"`
	User      string    `json:"user"`
	Type      string    `json:"type,omitempty"` // user | serviceaccount | host
	Groups    []string  `json:"groups,omitempty"`
	Verb      string    `json:"verb,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name,omitempty"`
	Event     string    `json:"event,omitempty"` // for things that aren't API requests: login, refresh-reuse, …
	Allowed   bool      `json:"allowed"`
	Reason    string    `json:"reason,omitempty"`
	Remote    string    `json:"remote,omitempty"` // client address
}

// Sink takes entries. Implementations must be safe for concurrent use and must not block long.
type Sink interface{ Record(Entry) }

// Nop drops everything.
type Nop struct{}

func (Nop) Record(Entry) {}

// Memory keeps entries (tests).
type Memory struct {
	mu      sync.Mutex
	entries []Entry
}

func (m *Memory) Record(e Entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
}

// Entries returns a copy of what was recorded.
func (m *Memory) Entries() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Entry(nil), m.entries...)
}

// File appends JSON lines to Path (0600), moving it to Path.1 when it grows past MaxBytes.
type File struct {
	Path     string
	MaxBytes int64 // default 100 MiB
	OnError  func(error)

	mu   sync.Mutex
	f    *os.File
	size int64
}

func (f *File) Record(e Entry) {
	b, err := json.Marshal(e)
	if err != nil {
		f.fail(err)
		return
	}
	b = append(b, '\n')
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.f == nil {
		if err := f.open(); err != nil {
			f.fail(err)
			return
		}
	}
	max := f.MaxBytes
	if max <= 0 {
		max = 100 << 20
	}
	if f.size+int64(len(b)) > max && f.size > 0 {
		_ = f.f.Close()
		f.f = nil
		if err := os.Rename(f.Path, f.Path+".1"); err != nil {
			f.fail(err)
		}
		if err := f.open(); err != nil {
			f.fail(err)
			return
		}
	}
	n, err := f.f.Write(b)
	f.size += int64(n)
	if err != nil {
		f.fail(err)
	}
}

func (f *File) open() error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(f.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	f.f, f.size = file, fi.Size()
	return nil
}

func (f *File) fail(err error) {
	if f.OnError != nil {
		f.OnError(err)
	}
}

// Close closes the file.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.f == nil {
		return nil
	}
	err := f.f.Close()
	f.f = nil
	return err
}

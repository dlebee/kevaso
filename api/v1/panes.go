package v1

import (
	"encoding/json"
	"time"

	"kevaso.com/core/api/meta"
)

// Panes (design §10.1): a silo reports what its status looks like; the control plane keeps the
// latest report per pane and relays it; clients render it. One way only: nothing flows back to the
// silo. Off unless the silo turns it on (spec.panes), and a client only shows panes it asked for.

// Pane kinds.
const (
	PaneStatus = "status" // structured fields the client draws with its own templates (safe)
	PaneHTML   = "html"   // a bundle (by digest) the client opens in a sealed view, plus data
)

// Pane states (status panes).
var PaneStates = []string{"idle", "running", "needs-you", "done", "failed"}

// PaneConfig is a silo's spec.panes.
type PaneConfig struct {
	Enabled  bool     `json:"enabled,omitempty"`
	Allow    []string `json:"allow,omitempty"`    // status, html (default: status)
	MaxPanes int      `json:"maxPanes,omitempty"` // default 4, at most 16
}

// Pane is one pane's latest report. Namespaced; named SILO.PANE. Only the control plane writes
// them (from the silo's broker channel); people read them with get/list/watch on panes.
type Pane struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            PaneReport `json:"spec"`
	Status          PaneState  `json:"status,omitempty"`
}

// PaneReport is what the silo sent. Text is plain text, always.
type PaneReport struct {
	Silo     string      `json:"silo"`
	SiloUID  string      `json:"siloUID"`
	Pane     string      `json:"pane"`
	Kind     string      `json:"kind"` // status | html
	Title    string      `json:"title,omitempty"`
	State    string      `json:"state,omitempty"`
	Progress *float64    `json:"progress,omitempty"` // 0…1
	Message  string      `json:"message,omitempty"`
	Fields   []PaneField `json:"fields,omitempty"`
	// HTML: the bundle's digest (sha256:…, uploaded once) and the data pushed to it. The bundle's
	// format is ADR 0007's (see PaneBundleMaxBytes); the control plane never opens it.
	Bundle string          `json:"bundle,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
	TTL    string          `json:"ttl,omitempty"` // past it without an update, the pane is stale
}

// PaneField is a label and a value.
type PaneField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// PaneState is the control plane's bookkeeping.
type PaneState struct {
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
	Updates   int64      `json:"updates,omitempty"`
}

// Stale reports whether the pane went past its TTL without an update.
func (p *Pane) Stale(now time.Time) bool {
	ttl, err := time.ParseDuration(p.Spec.TTL)
	if err != nil || ttl <= 0 || p.Status.UpdatedAt == nil {
		return false
	}
	return now.Sub(*p.Status.UpdatedAt) > ttl
}

// An HTML pane's bundle (ADR 0007) is one of:
//
//   - a POSIX ustar archive of regular files and folders only, holding index.html at its root:
//     relative names (no leading /, no empty, . or .. parts, no backslash or control characters,
//     under 256 bytes), at most PaneBundleMaxFiles files unpacking to at most
//     PaneBundleMaxUnpacked bytes;
//   - anything else: the pane's index.html, as it is.
//
// Either way it's at most PaneBundleMaxBytes, and named by its sha256 digest. The control plane
// only weighs and hashes it: it's opened by the panes app, which refuses anything else, and built
// by `kvo-guest pane html --bundle DIR` (sorted names, zeroed times and owners, modes 0644 and
// 0755, so the same files give the same digest).
const (
	PaneBundleMaxBytes    = 512 << 10
	PaneBundleMaxFiles    = 256
	PaneBundleMaxUnpacked = 8 << 20
)

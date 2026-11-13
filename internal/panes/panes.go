// Package panes holds the pane protocol's rules (design §10.1). Pure: whether a silo may report a
// pane, whether a report is within limits, how fast a silo may report, and the one check made on
// an HTML bundle (its size and digest). The control plane never parses, unpacks or renders a
// bundle: it's an opaque blob, served only as a download.
package panes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	v1 "kevaso.com/core/api/v1"
)

// Limits are the control plane's.
type Limits struct {
	MaxReport int           // a status report's text in bytes (title, message, fields)
	MaxData   int           // an HTML pane's data, bytes
	MaxBundle int           // an HTML bundle, bytes
	Rate      float64       // reports per second per silo, sustained
	Burst     int           // reports allowed at once
	MaxTTL    time.Duration // the longest TTL a pane may ask for
}

// Defaults: a few updates a second, a few hundred KiB per pane.
var Defaults = Limits{MaxReport: 16 << 10, MaxData: 64 << 10, MaxBundle: v1.PaneBundleMaxBytes, Rate: 4, Burst: 8, MaxTTL: time.Hour}

const defaultMaxPanes = 4

var paneName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,30}[a-z0-9])?$`)

// Name is the Pane object's name: SILO.PANE.
func Name(silo, pane string) string { return silo + "." + pane }

// Errors a report is refused with.
var (
	ErrOff     = errors.New("panes are off for this silo (spec.panes.enabled)")
	ErrKind    = errors.New("this kind of pane isn't allowed for this silo (spec.panes.allow)")
	ErrTooMany = errors.New("too many panes")
	ErrLimit   = errors.New("over the limit")
	ErrRate    = errors.New("reporting too fast")
	ErrDigest  = errors.New("bundle digest doesn't match")
)

func allowed(cfg *v1.PaneConfig) []string {
	if len(cfg.Allow) == 0 {
		return []string{v1.PaneStatus}
	}
	return cfg.Allow
}

// Check decides one report. existing are the silo's panes now (by pane name), so a new pane past
// maxPanes is refused while updates to existing ones go through.
func Check(cfg *v1.PaneConfig, r v1.PaneReport, existing []string, l Limits) error {
	if cfg == nil || !cfg.Enabled {
		return ErrOff
	}
	if !paneName.MatchString(r.Pane) {
		return fmt.Errorf("pane name %q: 1-32 lower-case letters, digits and -", r.Pane)
	}
	if !slices.Contains(allowed(cfg), r.Kind) {
		return fmt.Errorf("%w: %s (allowed: %v)", ErrKind, r.Kind, allowed(cfg))
	}
	max := cfg.MaxPanes
	if max == 0 {
		max = defaultMaxPanes
	}
	if !slices.Contains(existing, r.Pane) && len(existing) >= max {
		return fmt.Errorf("%w: this silo has %d (spec.panes.maxPanes %d)", ErrTooMany, len(existing), max)
	}
	if r.TTL != "" {
		ttl, err := time.ParseDuration(r.TTL)
		if err != nil || ttl <= 0 || ttl > l.MaxTTL {
			return fmt.Errorf("ttl %q: a duration up to %s", r.TTL, l.MaxTTL)
		}
	}
	text := len(r.Title) + len(r.Message) + len(r.State)
	for _, f := range r.Fields {
		text += len(f.Label) + len(f.Value)
	}
	if text > l.MaxReport {
		return fmt.Errorf("%w: %d bytes of text, at most %d", ErrLimit, text, l.MaxReport)
	}
	for _, s := range append([]string{r.Title, r.Message}, fieldText(r.Fields)...) {
		if !utf8.ValidString(s) {
			return errors.New("text must be UTF-8")
		}
	}
	switch r.Kind {
	case v1.PaneStatus:
		if r.State != "" && !slices.Contains(v1.PaneStates, r.State) {
			return fmt.Errorf("state %q: one of %v", r.State, v1.PaneStates)
		}
		if r.Progress != nil && (*r.Progress < 0 || *r.Progress > 1) {
			return fmt.Errorf("progress %v: from 0 to 1", *r.Progress)
		}
		if r.Bundle != "" || len(r.Data) > 0 {
			return errors.New("a status pane has no bundle or data")
		}
	case v1.PaneHTML:
		if !digestRE.MatchString(r.Bundle) {
			return fmt.Errorf("bundle %q: want sha256:<64 hex digits>", r.Bundle)
		}
		if len(r.Data) > l.MaxData {
			return fmt.Errorf("%w: data is %d bytes, at most %d", ErrLimit, len(r.Data), l.MaxData)
		}
		if len(r.Data) > 0 && !json.Valid(r.Data) {
			return errors.New("data must be JSON")
		}
	}
	return nil
}

func fieldText(fs []v1.PaneField) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Label, f.Value)
	}
	return out
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Digest is a bundle's name.
func Digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// CheckBundle is the only look the control plane takes at a bundle: its size, and that it is
// what its digest says. Its contents are never read.
func CheckBundle(digest string, b []byte, l Limits) error {
	if len(b) == 0 || len(b) > l.MaxBundle {
		return fmt.Errorf("%w: bundle is %d bytes, 1 to %d", ErrLimit, len(b), l.MaxBundle)
	}
	if Digest(b) != digest {
		return ErrDigest
	}
	return nil
}

// Bucket is one silo's rate limit (a token bucket).
type Bucket struct {
	Tokens float64
	At     time.Time
}

// Take spends one report from the bucket, refilled at l.Rate up to l.Burst.
func Take(b Bucket, l Limits, now time.Time) (Bucket, bool) {
	if b.At.IsZero() {
		b = Bucket{Tokens: float64(l.Burst), At: now}
	}
	if el := now.Sub(b.At).Seconds(); el > 0 {
		b.Tokens = min(float64(l.Burst), b.Tokens+el*l.Rate)
	}
	b.At = now
	if b.Tokens < 1 {
		return b, false
	}
	b.Tokens--
	return b, true
}

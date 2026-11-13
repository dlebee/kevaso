package panes

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
)

var on = &v1.PaneConfig{HTTP: &v1.PaneHTTP{Port: 7070}, Allow: []string{"status", "html"}, MaxPanes: 2}

func status() v1.PaneReport {
	p := 0.57
	return v1.PaneReport{Pane: "overview", Kind: "status", Title: "claude · refactor", State: "needs-you", Progress: &p,
		Message: "Keep legacy rounding?", Fields: []v1.PaneField{{Label: "tests", Value: "212/240"}}, TTL: "60s"}
}

func TestCheck(t *testing.T) {
	if err := Check(on, status(), nil, Defaults); err != nil {
		t.Fatal(err)
	}
	html := v1.PaneReport{Pane: "fleet-3d", Kind: "html", Bundle: Digest([]byte("<p>x</p>")), Data: json.RawMessage(`{"lit":3}`)}
	if err := Check(on, html, nil, Defaults); err != nil {
		t.Fatal(err)
	}
	if err := Check(&v1.PaneConfig{HTTP: &v1.PaneHTTP{Port: 7070}}, html, nil, Defaults); !errors.Is(err, ErrKind) {
		t.Fatalf("html when only status is allowed (the default): %v", err)
	}
	for name, tc := range map[string]struct {
		cfg  *v1.PaneConfig
		r    func(*v1.PaneReport)
		have []string
		want string
	}{
		"off":              {nil, nil, nil, "off"},
		"disabled":         {&v1.PaneConfig{}, nil, nil, "off"},
		"bad name":         {on, func(r *v1.PaneReport) { r.Pane = "../etc" }, nil, "pane name"},
		"too many":         {on, func(r *v1.PaneReport) { r.Pane = "third" }, []string{"a", "b"}, "too many"},
		"bad state":        {on, func(r *v1.PaneReport) { r.State = "<b>pwned</b>" }, nil, "state"},
		"progress":         {on, func(r *v1.PaneReport) { p := 1.5; r.Progress = &p }, nil, "progress"},
		"huge":             {on, func(r *v1.PaneReport) { r.Message = strings.Repeat("x", 17<<10) }, nil, "over the limit"},
		"ttl":              {on, func(r *v1.PaneReport) { r.TTL = "48h" }, nil, "ttl"},
		"status with data": {on, func(r *v1.PaneReport) { r.Data = json.RawMessage(`{}`) }, nil, "no bundle or data"},
		"not utf-8":        {on, func(r *v1.PaneReport) { r.Title = "\xff" }, nil, "UTF-8"},
	} {
		r := status()
		if tc.r != nil {
			tc.r(&r)
		}
		if err := Check(tc.cfg, r, tc.have, Defaults); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// An update to an existing pane is fine at the limit.
	if err := Check(on, status(), []string{"overview", "other"}, Defaults); err != nil {
		t.Fatalf("update at the limit: %v", err)
	}
	for name, mutate := range map[string]func(*v1.PaneReport){
		"bad digest": func(r *v1.PaneReport) { r.Bundle = "sha256:nothex" },
		"data size":  func(r *v1.PaneReport) { r.Data = json.RawMessage(`"` + strings.Repeat("x", 65<<10) + `"`) },
		"data json":  func(r *v1.PaneReport) { r.Data = json.RawMessage(`{nope`) },
	} {
		r := html
		mutate(&r)
		if err := Check(on, r, nil, Defaults); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestBundleIsOnlyWeighedAndHashed(t *testing.T) {
	b := []byte(`<script>fetch("https://evil.example")</script>`) // never looked at
	if err := CheckBundle(Digest(b), b, Defaults); err != nil {
		t.Fatal(err)
	}
	if err := CheckBundle(Digest([]byte("other")), b, Defaults); !errors.Is(err, ErrDigest) {
		t.Fatalf("wrong digest: %v", err)
	}
	big := make([]byte, Defaults.MaxBundle+1)
	if err := CheckBundle(Digest(big), big, Defaults); !errors.Is(err, ErrLimit) {
		t.Fatalf("too big: %v", err)
	}
	if err := CheckBundle(Digest(nil), nil, Defaults); !errors.Is(err, ErrLimit) {
		t.Fatalf("empty: %v", err)
	}
}

func TestRate(t *testing.T) {
	t0 := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	var b Bucket
	ok := 0
	for range 100 { // a burst of 100 at once
		var took bool
		if b, took = Take(b, Defaults, t0); took {
			ok++
		}
	}
	if ok != Defaults.Burst {
		t.Fatalf("burst let %d through, want %d", ok, Defaults.Burst)
	}
	b, took := Take(b, Defaults, t0.Add(250*time.Millisecond)) // 4/s: one more after 250ms
	if !took {
		t.Fatal("refill didn't happen")
	}
	if _, took := Take(b, Defaults, t0.Add(260*time.Millisecond)); took {
		t.Fatal("refilled too fast")
	}
	b, _ = Take(Bucket{}, Defaults, t0)
	if b, _ = Take(b, Defaults, t0.Add(time.Hour)); b.Tokens > float64(Defaults.Burst) {
		t.Fatalf("bucket grew past its burst: %v", b.Tokens)
	}
}

func TestStale(t *testing.T) {
	t0 := time.Now()
	p := &v1.Pane{Spec: v1.PaneReport{TTL: "30s"}, Status: v1.PaneState{UpdatedAt: &t0}}
	if p.Stale(t0.Add(10*time.Second)) || !p.Stale(t0.Add(31*time.Second)) {
		t.Fatal("stale")
	}
	if (&v1.Pane{}).Stale(t0) {
		t.Fatal("no ttl is never stale")
	}
}

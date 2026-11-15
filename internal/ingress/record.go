package ingress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"kevaso.com/core/sdk/kic"
)

// The record (K-063): what the agent last had the proxy accept, kept in the controller silo next
// to the rendered config, so that an agent that restarts knows what the proxy serves instead of
// assuming it from an empty memory. It is written as RECORD.next before an apply and moved over
// RECORD once the proxy took it (removed if the proxy refused), every time the config is written
// (K-090). It holds certificate keys: 0600, written on stdin, never logged. It says what was
// applied (the state), and how to recognise it in the proxy: the digest of the config file written
// with it, or the proxy's own fingerprint of what it ran once it took it (kic.Reader).
//
// The record is only a shortcut. Its absence, loss, truncation or corruption never changes what
// the proxy serves (K-089): what is served is established from the proxy first (readRecord).
//   - The proxy runs what RECORD (or a RECORD.next left by an apply under way) says: that is served.
//   - The proxy runs nothing of Kevaso's (the image's own config, or a proxy that runs none): no
//     Ingress of ours is served.
//   - Otherwise its running config is compared with a fresh render of the current Ingresses: equal,
//     it is adopted (and the record written on the next apply, which changes nothing); differing
//     only in Ingresses' own parts, those Ingresses are taken as changed and served at a version
//     that isn't known (an apply never removes them: the class is held instead), unless the record
//     says they didn't change.
//   - Anything else: what the proxy serves is unknown, and ApplyEach holds the class rather than
//     leave out an Ingress it may be serving.
// "No record" is never taken to mean "nothing of ours is served".

// AdminRecordPath is where the record goes for a driver with no config file (an admin API).
var AdminRecordPath = "/tmp/kevaso-ingress.json"

// RecordPath is where the record of what p's driver applied is kept in the silo: next to the
// config (outside Plan.Dir, which is swept after each apply), or AdminRecordPath.
func RecordPath(p kic.Plan) string {
	if p.Config.Path != "" {
		return p.Config.Path + ".kevaso"
	}
	return AdminRecordPath
}

type record struct {
	Driver string    `json:"driver"`
	State  kic.State `json:"state"`
	// Config is the SHA-256 of the config file written with State (a driver with a config file).
	Config string `json:"config,omitempty"`
	// Proxy is the proxy's fingerprint of what it ran once it took State (a kic.Reader).
	Proxy string `json:"proxy,omitempty"`
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// seen is what the proxy serves, as far as it could be established.
type seen struct {
	served   *kic.State // what it serves (nil: unknown)
	opaque   []string   // Ingresses it serves at a version that isn't known (taken as changed)
	inRecord bool       // served is what RECORD holds
	unknown  string     // why served is unknown
	// running is what the proxy runs now (its config's digest, or its fingerprint; "" with
	// exact: it runs none); exact: served is exactly that, so it can be remembered.
	running string
	exact   bool
}

// look is what the proxy runs now: its config file's digest and content, or its fingerprint (a
// kic.Reader; "": it runs none). why: it can't be told.
func look(ctx context.Context, exec Exec, call Caller, d kic.Driver, p0 kic.Plan) (digest string, data []byte, why string, err error) {
	if p0.Config.Path != "" {
		code, out, err := exec(ctx, ReadIfCmd(p0.Config.Path), nil)
		switch {
		case err != nil:
			return "", nil, "", err
		case code == 3:
			return "", nil, "there is no configuration at " + p0.Config.Path, nil
		case code != 0:
			return "", nil, "", fmt.Errorf("read %s: exit %d: %s", p0.Config.Path, code, tail(out))
		}
		return digestOf([]byte(out)), []byte(out), "", nil
	}
	rd, ok := d.(kic.Reader)
	if !ok || call == nil {
		return "", nil, "this driver's proxy can't be asked what it runs", nil
	}
	status, body, err := call(ctx, rd.Running(p0))
	if err != nil {
		return "", nil, "", err
	}
	fp, err := rd.Fingerprint(status, body)
	if err != nil {
		return "", nil, "the proxy can't say what it runs: " + tail(err.Error()), nil
	}
	return fp, nil, "", nil
}

// readRecord establishes what the proxy serves: from the proxy, with the record's help (see the
// top of this file). want is the class's desired state now (for a fresh render); p0 is any plan of
// the driver's (for the paths).
func readRecord(ctx context.Context, exec Exec, call Caller, d kic.Driver, p0 kic.Plan, want kic.State) (seen, error) {
	path := RecordPath(p0)
	read := func(p string) (*record, bool, error) {
		code, out, err := exec(ctx, ReadIfCmd(p), nil)
		switch {
		case err != nil:
			return nil, false, err
		case code == 3:
			return nil, false, nil
		case code != 0:
			return nil, false, fmt.Errorf("read %s: exit %d: %s", p, code, tail(out))
		}
		var r record
		if json.Unmarshal([]byte(out), &r) != nil || r.Driver != d.Info().Name {
			return nil, strings.TrimSpace(out) != "", nil // empty, truncated, corrupt or another driver's: no use
		}
		return &r, true, nil
	}
	cur, hasCur, err := read(path)
	if err != nil {
		return seen{}, err
	}
	next, hasNext, err := read(path + ".next")
	if err != nil {
		return seen{}, err
	}
	digest, data, why, err := look(ctx, exec, call, d, p0)
	if err != nil {
		return seen{}, err
	}
	if why != "" {
		// The proxy can't be looked at. A driver with no way to ask keeps to its record, if no
		// apply was under way; anything else is unknown.
		if p0.Config.Path == "" && cur != nil && !hasNext {
			return seen{served: &cur.State, inRecord: true}, nil
		}
		if !hasCur && !hasNext {
			why += ", and there is no record of what was applied"
		}
		return seen{unknown: why}, nil
	}
	// What the record says, if the proxy runs it (RECORD.next first: an apply under way may have
	// got that far).
	for _, r := range []*record{next, cur} {
		if r == nil {
			continue
		}
		match := false
		switch {
		case p0.Config.Path == "":
			match = r.Proxy != "" && r.Proxy == digest
		case r.Config != "":
			match = r.Config == digest
		default: // a record from before digests: it has to render to the running config
			p, err := d.Render(r.State)
			match = err == nil && p.Config.Path == p0.Config.Path && bytes.Equal(p.Config.Data, data)
		}
		if match {
			return seen{served: &r.State, inRecord: r == cur, running: digest, exact: true}, nil
		}
	}
	if p0.Config.Path == "" {
		if digest == "" {
			return seen{served: &kic.State{}, running: "", exact: true}, nil // the proxy runs no configuration
		}
		return seen{unknown: "the proxy runs a configuration its record of what was applied doesn't account for (the record is missing, from an older build, or not the last one)"}, nil
	}
	if !kic.Ours(data) {
		return seen{served: &kic.State{}, running: digest, exact: true}, nil // the image's own config: nothing of ours
	}
	ref := cur
	if ref == nil {
		ref = next
	}
	return establish(d, data, digest, want, ref), nil
}

// establish compares a running config of Kevaso's that no record accounts for with a fresh render
// of want: equal, it is what is served; differing only in Ingresses' own (marked) parts, those
// Ingresses are served at a version that isn't known (opaque), unless ref, the record, says they
// didn't change; anything else is unknown.
func establish(d kic.Driver, data []byte, digest string, want kic.State, ref *record) seen {
	fresh, err := d.Render(want)
	if err != nil {
		return seen{unknown: "the proxy's configuration isn't the one recorded as applied, and the current state can't be rendered to compare: " + err.Error()}
	}
	if bytes.Equal(fresh.Config.Data, data) {
		s := want
		return seen{served: &s, running: digest, exact: true}
	}
	outR, inR := kic.Sections(data)
	outF, inF := kic.Sections(fresh.Config.Data)
	if outR != outF {
		return seen{unknown: "its configuration is neither the one recorded as applied nor a render of the current Ingresses, outside any one Ingress's part"}
	}
	base, by := split(want)
	var before map[string]fragment
	if ref != nil {
		_, before = split(ref.State)
	}
	names := map[string]bool{}
	for _, m := range []map[string][]string{inR, inF} {
		for w := range m {
			names[w] = true
		}
	}
	for w := range by {
		names[w] = true
	}
	var keep, opaque []string
	for _, w := range slices.Sorted(maps.Keys(names)) {
		_, served := inR[w]
		if slices.Equal(inR[w], inF[w]) {
			if _, ok := by[w]; ok {
				keep = append(keep, w)
			}
			continue
		}
		if !served {
			continue // not in the running config: new since
		}
		if f, ok := before[w]; ok {
			if cur, has := by[w]; has && hashOf(f) == hashOf(cur) {
				return seen{unknown: "its configuration for " + w + " isn't the one recorded as applied, though " + w + " didn't change (edited by hand?)"}
			}
		}
		opaque = append(opaque, w)
	}
	s := join(base, by, keep)
	return seen{served: &s, opaque: opaque}
}

package ingress

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"kevaso.com/core/sdk/kic"
)

// The record (K-063): what the agent last had the proxy accept, kept in the controller silo next
// to the rendered config, so that an agent that restarts knows what the proxy serves instead of
// assuming it from an empty memory. It is written as RECORD.next before an apply and moved over
// RECORD once the proxy took it (removed if the proxy refused). It holds certificate keys: 0600,
// written on stdin, never logged.
//
// A restarted agent reads it back (readRecord): for a driver with a config file, the record (or a
// RECORD.next left by an apply that was under way) counts only if it renders exactly to the
// config the proxy has; for an admin-API driver, RECORD counts only if no apply was under way.
// No record at all: Kevaso never had this proxy accept anything, so it serves no Ingress of ours.
// Anything else (a record that doesn't match, or can't be read): what the proxy serves is unknown,
// and ApplyEach holds the class rather than leave out an Ingress it may be serving.

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
}

// readRecord is what the proxy serves, from the record: served (nil when unknown), and when it's
// unknown, why. inRecord: served is what RECORD itself holds (not a RECORD.next that matched). p0
// is any plan of the driver's (for the paths).
func readRecord(ctx context.Context, exec Exec, d kic.Driver, p0 kic.Plan) (served *kic.State, inRecord bool, unknown string, err error) {
	path := RecordPath(p0)
	read := func(p string) (string, bool, error) {
		code, out, err := exec(ctx, ReadIfCmd(p), nil)
		switch {
		case err != nil:
			return "", false, err
		case code == 3:
			return "", false, nil
		case code != 0:
			return "", false, fmt.Errorf("read %s: exit %d: %s", p, code, tail(out))
		}
		return out, strings.TrimSpace(out) != "", nil
	}
	parse := func(text string) *record {
		var r record
		if json.Unmarshal([]byte(text), &r) != nil || r.Driver != d.Info().Name {
			return nil
		}
		return &r
	}
	cur, hasCur, err := read(path)
	if err != nil {
		return nil, false, "", err
	}
	next, hasNext, err := read(path + ".next")
	if err != nil {
		return nil, false, "", err
	}
	if !hasCur && !hasNext {
		return &kic.State{}, false, "", nil // never applied: no Ingress of ours is served
	}
	if p0.Config.Path == "" {
		if hasNext {
			return nil, false, "an apply was under way when the agent stopped, and this driver's proxy can't be asked what it took", nil
		}
		if r := parse(cur); r != nil {
			return &r.State, true, "", nil
		}
		return nil, false, "its record of what was applied can't be read", nil
	}
	code, running, err := exec(ctx, ReadIfCmd(p0.Config.Path), nil)
	if err != nil {
		return nil, false, "", err
	}
	if code == 0 {
		// An apply under way may have got as far as the move: RECORD.next first.
		for i, text := range []string{next, cur} {
			if r := parse(text); r != nil {
				if p, err := d.Render(r.State); err == nil && p.Config.Path == p0.Config.Path && string(p.Config.Data) == running {
					return &r.State, i == 1, "", nil
				}
			}
		}
	}
	return nil, false, "its configuration isn't the one recorded as applied", nil
}

package ingress_test

import (
	"context"
	"strings"
	"testing"

	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/internal/ingress/ingresstest"
)

// K-090: the record is written whenever the config is, and a live agent notices when the proxy no
// longer runs what it applied (the controller silo recreated with the same UID, its files the
// image's again; Kong restarted with no config), instead of taking its memory's word for it.

// pass is one pass of the agent's loop: what it last applied (the plan's hash) and its Memory.
func pass(t *testing.T, r *rig, w ingress.Desired, m *ingress.Memory, last string) ingress.EachResult {
	t.Helper()
	res, err := ingress.ApplyEach(context.Background(), r.exec, r.call, r.driver, w, nil, last, m, 0)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// recreate puts the controller silo back to its image: its files (record included) for a config
// file driver, Kong running nothing.
func recreate(r *rig) {
	switch r.name {
	case "kong":
		r.px.Reset(nil)
		r.live = nil
	case "caddy":
		r.px.Reset(map[string][]byte{"/etc/caddy/Caddyfile": []byte(ingresstest.CaddyImageConfig)})
	default:
		r.px.Reset(map[string][]byte{"/etc/nginx/nginx.conf": []byte(ingresstest.NginxImageConfig)})
	}
}

// The silo is recreated under a live agent (same UID: same Memory, same plan hash): the next pass
// applies again and writes the record, so a later agent restart changes nothing.
func TestK090ARecreatedSiloGetsItsConfigAndRecordBack(t *testing.T) {
	for _, r := range rigs(true) {
		t.Run(r.name, func(t *testing.T) {
			m := &ingress.Memory{}
			w := want(append(many(8, 3), route("shop/new", "new.example.com", 200))...)
			res := pass(t, r, want(many(8)...), m, "")
			res = pass(t, r, w, m, res.Hash)
			res = pass(t, r, w, m, res.Hash)
			if !strings.Contains(r.served(), "h05.example.com") {
				t.Fatal("not served before")
			}
			recreate(r)
			res = pass(t, r, w, m, res.Hash)
			if res.Held != "" || !strings.Contains(r.served(), "h05.example.com") || !strings.Contains(r.served(), "new.example.com") {
				t.Fatalf("the recreated silo didn't get its config back: %+v\n%s", res, r.served())
			}
			if _, ok := r.px.Files[recordPath(t, r)]; !ok {
				t.Fatal("no record after the silo was recreated")
			}
			restartUnchangedAny(t, r, w)
		})
	}
}

// The auditor's form: the files go back to the image's and the next apply rewrites the config
// (last unknown) with the Memory's record hash unchanged: the record is written too.
func TestK090TheRecordIsWrittenWheneverTheConfigIs(t *testing.T) {
	for _, r := range rigs(false) {
		if r.name == "kong" {
			continue
		}
		t.Run(r.name, func(t *testing.T) {
			m := &ingress.Memory{}
			w := want(many(8, 3)...)
			pass(t, r, want(many(8)...), m, "")
			pass(t, r, w, m, "")
			recreate(r)
			pass(t, r, w, m, "")
			if _, ok := r.px.Files[recordPath(t, r)]; !ok {
				t.Fatal("the config was written again, its record wasn't")
			}
			restartUnchangedAny(t, r, w)
		})
	}
}

// A live agent whose proxy's config was edited by hand: what it serves is checked again, the
// edit isn't explained, so the class is held and nothing changes.
func TestK090AHandEditUnderALiveAgentIsSeen(t *testing.T) {
	for _, r := range rigs(false) {
		if r.name == "kong" {
			continue
		}
		t.Run(r.name, func(t *testing.T) {
			m := &ingress.Memory{}
			w := want(many(8, 3)...)
			res := pass(t, r, want(many(8)...), m, "")
			res = pass(t, r, w, m, res.Hash)
			cfg := configPath(t, r)
			r.px.Files[cfg] = []byte(strings.Replace(string(r.px.Files[cfg]), "10.64.0.5:85", "10.64.0.9:85", 1))
			changes, stop := watch(r)
			res = pass(t, r, w, m, res.Hash)
			stop()
			if changes() > 0 || res.Held == "" {
				t.Errorf("changed %d times, held %q", changes(), res.Held)
			}
		})
	}
}

// restartUnchangedAny: an agent restart after this changes nothing the proxy serves.
func restartUnchangedAny(t *testing.T, r *rig, w ingress.Desired) {
	t.Helper()
	changes, stop := watch(r)
	defer stop()
	res, _, _ := settle(t, r, w, &ingress.Memory{}, nil, "", 2)
	if n := changes(); n > 0 {
		t.Errorf("an agent restart changed what the proxy serves at %d moments (held %q, left out %v)", n, res.Held, res.LeftOut)
	}
}

// The config file is gone but the record is there: nothing can be loaded but what is written
// next, so the record says what may still be served: the broken edits stay at their last good
// versions and everything else is written back.
func TestK090AMissingConfigIsWrittenBackFromTheRecord(t *testing.T) {
	for _, r := range rigs(false) {
		if r.name == "kong" {
			continue
		}
		t.Run(r.name, func(t *testing.T) {
			w := served24(t, r)
			before := r.served()
			delete(r.px.Files, configPath(t, r))
			res, _, _ := settle(t, r, w, &ingress.Memory{}, nil, "", 2)
			if res.Held != "" || r.served() != before {
				t.Errorf("not written back as it was: held %q, left out %v", res.Held, res.LeftOut)
			}
		})
	}
}

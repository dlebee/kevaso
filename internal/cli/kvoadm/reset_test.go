package kvoadm

import (
	"bufio"
	"context"
	"errors"
	v1 "kevaso.com/core/api/v1"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/hostreset"
)

// fakeResetHost answers kvoadm reset's scripts: the inspection it is given, every plan step and
// check, and the state after the plan.
type fakeResetHost struct {
	inspection string
	after      hostreset.State
	leftovers  map[string]string // check name → what it prints
	ran        []string          // step and check names, in order
	steps      map[string]string // script → step name
	checks     map[string]string // script → check name
}

func (f *fakeResetHost) Run(_ context.Context, cmd string, _ []byte) ([]byte, error) {
	switch {
	case cmd == hostreset.InspectScript:
		return []byte(f.inspection), nil
	case cmd == hostreset.StateScript:
		return []byte(f.after.Render()), nil
	case f.checks[cmd] != "":
		f.ran = append(f.ran, "check:"+f.checks[cmd])
		return []byte(f.leftovers[f.checks[cmd]]), nil
	case f.steps[cmd] != "":
		f.ran = append(f.ran, "step:"+f.steps[cmd])
		return nil, nil
	}
	f.ran = append(f.ran, "unknown")
	return nil, nil
}

// expect registers the plan and checklist a decision leads to.
func (f *fakeResetHost) expect(d hostreset.Decision) {
	f.steps, f.checks = map[string]string{}, map[string]string{}
	for _, s := range hostreset.Plan(d.Plan) {
		f.steps[s.Script] = s.Name
	}
	for _, c := range hostreset.Checklist(d.Checks) {
		f.checks[c.Script] = c.Name
	}
}

var baseState = hostreset.State{Packages: []string{"bash", "lvm2", "nftables", "openssh-server"}, Tables: []string{"inet provider"}, IPForward: "0"}

func inspection(rec *hostreset.Record, silos []string, pvs []string, lvs []string, now hostreset.State) string {
	var b strings.Builder
	b.WriteString("== record\n")
	if rec != nil {
		b.WriteString(strings.ReplaceAll(rec.Render(), "== ", "=== "))
	}
	b.WriteString("== installed\nkevasod=yes\nrunning=yes\n== silos\n" + strings.Join(silos, "\n") + "\n== pvs\n" + strings.Join(pvs, "\n") +
		"\n== lvs\n" + strings.Join(lvs, "\n") + "\n== state\n" + strings.ReplaceAll(now.Render(), "== ", "=== "))
	return b.String()
}

func newResetHost(t *testing.T, rec *hostreset.Record, silos, pvs, lvs []string, f hostreset.Flags) *fakeResetHost {
	t.Helper()
	now := baseState
	now.Packages = append(slices.Clone(baseState.Packages), "docker.io", "qemu-utils")
	now.Tables = append(slices.Clone(baseState.Tables), "inet kevaso")
	now.IPForward = "1"
	h := &fakeResetHost{inspection: inspection(rec, silos, pvs, lvs, now), after: baseState}
	insp, err := hostreset.ParseInspection(h.inspection)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := hostreset.Decide(insp, f); err == nil {
		h.expect(d)
	}
	return h
}

func reset(h hostRunner, o ResetOptions, stdin string) (string, error) {
	var out strings.Builder
	o.Address = "203.0.113.10"
	err := runReset(context.Background(), h, o, bufio.NewReader(strings.NewReader(stdin)), &out)
	return out.String(), err
}

func TestResetRefusesAHostWithSilos(t *testing.T) {
	rec := &hostreset.Record{State: baseState}
	h := newResetHost(t, rec, []string{"container web/api"}, nil, nil, hostreset.Flags{})
	_, err := reset(h, ResetOptions{Yes: true}, "")
	if !errors.Is(err, hostreset.ErrSilos) || !strings.Contains(err.Error(), "web/api") {
		t.Fatalf("got %v", err)
	}
	if len(h.ran) != 0 {
		t.Fatalf("a refused reset ran %v", h.ran)
	}
	h = newResetHost(t, rec, []string{"container web/api"}, nil, nil, hostreset.Flags{Force: true})
	out, err := reset(h, ResetOptions{Yes: true, Force: true}, "")
	if err != nil || !strings.Contains(out, "destroy the silos still here (--force): container web/api") {
		t.Fatalf("--force: %v\n%s", err, out)
	}
}

func TestResetAsksFirst(t *testing.T) {
	rec := &hostreset.Record{State: baseState}
	for _, answer := range []string{"", "no\n", "y\n"} {
		h := newResetHost(t, rec, nil, nil, nil, hostreset.Flags{})
		out, err := reset(h, ResetOptions{}, answer)
		if err == nil || !strings.Contains(err.Error(), "not confirmed") || len(h.ran) != 0 {
			t.Fatalf("answer %q: %v, ran %v", answer, err, h.ran)
		}
		if !strings.Contains(out, "Type yes to reset 203.0.113.10") || !strings.Contains(out, "purge docker.io, qemu-utils") {
			t.Errorf("answer %q: the plan wasn't shown first:\n%s", answer, out)
		}
	}
	h := newResetHost(t, rec, nil, nil, nil, hostreset.Flags{})
	if _, err := reset(h, ResetOptions{}, "yes\n"); err != nil {
		t.Fatalf("yes: %v", err)
	}
	h = newResetHost(t, rec, nil, nil, nil, hostreset.Flags{})
	var o ResetOptions
	o.DryRun = true
	if _, err := reset(h, o, "yes\n"); !errors.Is(err, ErrDryRun) || len(h.ran) != 0 {
		t.Fatalf("--dry-run: %v, ran %v", err, h.ran)
	}
}

func TestResetRunsThePlanThenTheChecklist(t *testing.T) {
	rec := &hostreset.Record{State: baseState}
	h := newResetHost(t, rec, nil, []string{"/dev/loop3 " + hostreset.StorageImage}, []string{"kv-01-ab 1.00g"}, hostreset.Flags{})
	out, err := reset(h, ResetOptions{Yes: true}, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if slices.Contains(h.ran, "unknown") {
		t.Fatalf("sent a script outside the plan and checklist: %v", h.ran)
	}
	first := slices.IndexFunc(h.ran, func(s string) bool { return strings.HasPrefix(s, "check:") })
	if first < 1 || slices.ContainsFunc(h.ran[first:], func(s string) bool { return strings.HasPrefix(s, "step:") }) {
		t.Fatalf("steps and checks interleaved: %v", h.ran)
	}
	for _, want := range []string{"step:purge docker.io qemu-utils", "step:delete nftables tables", "step:remove volume group kevaso (on the loop file only)", "step:restore net.ipv4.ip_forward"} {
		if !slices.Contains(h.ran, want) {
			t.Errorf("never ran %q: %v", want, h.ran)
		}
	}
	if !strings.Contains(out, "These volumes, and the data on them, will be lost:\n  kv-01-ab 1.00g") || !strings.Contains(out, "is clean") {
		t.Errorf("output:\n%s", out)
	}
}

func TestResetNamesWhatIsLeft(t *testing.T) {
	rec := &hostreset.Record{State: baseState}
	h := newResetHost(t, rec, nil, nil, nil, hostreset.Flags{})
	h.leftovers = map[string]string{"no Kevaso link is left": "kvbr0\n"}
	h.after.Packages = append(slices.Clone(baseState.Packages), "docker.io")
	_, err := reset(h, ResetOptions{Yes: true}, "")
	if !errors.Is(err, hostreset.ErrNotClean) || !strings.Contains(err.Error(), "kvbr0") || !strings.Contains(err.Error(), "package still installed: docker.io") {
		t.Fatalf("got %v", err)
	}
}

func TestResetKeepsADiskVolumeGroupUnlessWiped(t *testing.T) {
	rec := &hostreset.Record{State: baseState}
	pvs, lvs := []string{"/dev/nvme1n1 disk"}, []string{"kv-01 20.00g", "kv-01-ab 100.00g"}
	h := newResetHost(t, rec, nil, pvs, lvs, hostreset.Flags{})
	out, err := reset(h, ResetOptions{Yes: true}, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, r := range h.ran {
		if strings.Contains(r, "volume group") {
			t.Errorf("a disk volume group was touched without --wipe-storage: %s", r)
		}
	}
	if !strings.Contains(out, "KEEP the volume group kevaso") || strings.Contains(out, "will be lost") {
		t.Errorf("output:\n%s", out)
	}
	h = newResetHost(t, rec, nil, pvs, lvs, hostreset.Flags{WipeStorage: true})
	out, err = reset(h, ResetOptions{Yes: true, WipeStorage: true}, "")
	if err != nil || !slices.Contains(h.ran, "step:wipe volume group kevaso and every volume on it") {
		t.Fatalf("--wipe-storage: %v %v", err, h.ran)
	}
	if !strings.Contains(out, "will be lost:\n  kv-01 20.00g\n  kv-01-ab 100.00g") {
		t.Errorf("the volumes weren't named first:\n%s", out)
	}
}

func TestResetWithoutARecordSaysSo(t *testing.T) {
	h := newResetHost(t, nil, nil, nil, nil, hostreset.Flags{})
	out, err := reset(h, ResetOptions{Yes: true}, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "NO INSTALL RECORD") || strings.Contains(strings.Join(h.ran, " "), "step:purge") {
		t.Errorf("no record: %v\n%s", h.ran, out)
	}
}

func TestParseReset(t *testing.T) {
	key := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := parseReset([]string{"ubuntu@203.0.113.10", "--ssh-key", key, "--host-key", "SHA256:x", "--yes", "--force", "--wipe-storage", "--dry-run"})
	if err != nil || o.User != "ubuntu" || o.Address != "203.0.113.10" || !o.Yes || !o.Force || !o.WipeStorage || !o.DryRun || o.HostKey != "SHA256:x" {
		t.Fatalf("%+v %v", o, err)
	}
	if o, _ := parseReset([]string{"203.0.113.10", "--ssh-key", key}); o.User != "root" {
		t.Errorf("default login %q", o.User)
	}
	for _, bad := range [][]string{{}, {"h", "--ssh-key", key, "--kevasod", "x"}, {"h", "--ssh-key", key, "--nope"}} {
		if _, err := parseReset(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestBackupTakesTheLoginFromTheTarget(t *testing.T) {
	out := filepath.Join(t.TempDir(), "b.kvb")
	o, file, err := parseBackup([]string{"ubuntu@203.0.113.10", "--output", out, "--ssh-key", "/k"})
	if err != nil || o.User != "ubuntu" || o.Address != "203.0.113.10" || file != out {
		t.Fatalf("%+v %q %v", o, file, err)
	}
	if o, _, _ := parseBackup([]string{"203.0.113.10", "-o", out, "--ssh-key", "/k"}); o.User != "root" {
		t.Errorf("default login %q", o.User)
	}
	if err := os.WriteFile(out, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseBackup([]string{"h", "-o", out}); err == nil || !strings.Contains(err.Error(), "never overwritten") {
		t.Errorf("an existing file: %v", err)
	}
}

func TestSplitTarget(t *testing.T) {
	for in, want := range map[string]string{"h": "root h", "ubuntu@h": "ubuntu h", "@h": "root h", "a@b@c": "a b@c"} {
		u, a := splitTarget(in)
		if u+" "+a != want {
			t.Errorf("%q: %s %s", in, u, a)
		}
	}
}

func TestRecordInstall(t *testing.T) {
	for answer, want := range map[string]string{"recorded\n": "recorded the host", "kept\n": "kept the install record", "older\n": "without an install record"} {
		var said []string
		err := recordInstall(context.Background(), answerRunner(answer), func(f string, a ...any) { said = append(said, f) })
		if err != nil || len(said) != 1 || !strings.Contains(said[0], want) {
			t.Errorf("%q: %v %v", answer, said, err)
		}
	}
	if err := recordInstall(context.Background(), answerRunner("huh"), func(string, ...any) {}); err == nil {
		t.Error("an odd answer was accepted")
	}
}

type answerRunner string

func (a answerRunner) Run(_ context.Context, cmd string, _ []byte) ([]byte, error) {
	if cmd != hostreset.RecordScript {
		return nil, errors.New("not the record script")
	}
	return []byte(a), nil
}

// Found by test-gaps: drain cleared a Recreate silo's host without a handoff, so the host it
// landed on could start it while the old one still ran it.
func TestDrainHandsOff(t *testing.T) {
	s := &v1.Silo{}
	s.Status.Host, s.Status.Phase, s.Status.SiloIP = "hv1", "Running", "10.64.1.2"
	st := DrainStatus(s, "hv1", time.Now())
	if st.Host != "" || st.Phase != "Pending" || st.SiloIP != "" || st.MovingFrom != "hv1" {
		t.Fatalf("drained: %+v", st)
	}
	if s.Status.Host != "hv1" || len(s.Status.Conditions) != 0 {
		t.Error("DrainStatus changed the silo it was given")
	}
}

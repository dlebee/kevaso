package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A failed lvs is not "no volume". Absent is only lvs's own "not found". Empty output is
// an error too.
func TestLVExistsIsThreeState(t *testing.T) {
	h := newFakeHost()
	r := newRuntime(t, h)
	ctx := context.Background()
	n := NamesFor(id("db"))
	h.lvs[n.LV] = true
	present, err := r.lvExists(ctx, n.LV)
	if err != nil || !present {
		t.Fatalf("present: %v %v", present, err)
	}
	delete(h.lvs, n.LV)
	present, err = r.lvExists(ctx, n.LV)
	if err != nil || present {
		t.Fatalf("absent: %v %v", present, err)
	}
	h.answer = func(cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "empty"):
			return " \n", nil
		default:
			return "", errors.New("lvs: Input/output error")
		}
	}
	if _, err := r.lvExists(ctx, "io"); err == nil {
		t.Fatal("an lvs failure was treated as absent")
	}
	if _, err := r.lvExists(ctx, "empty"); err == nil {
		t.Fatal("empty lvs output was treated as absent")
	}
}

// Create returns before it saves state when the root volume cannot be checked, and it
// removes nothing.
func TestCreateReturnsWhenLVSFails(t *testing.T) {
	h := newFakeHost()
	sp := spec("db")
	n := NamesFor(sp.ID)
	h.lvs[n.LV] = true
	h.answer = func(cmd string) (string, error) {
		if cmd == "lvs --noheadings "+VG+"/"+n.LV {
			return "", errors.New("lvs: Input/output error")
		}
		if f := strings.Fields(cmd); len(f) > 0 && (f[0] == "lvs" || f[0] == "lvcreate" || f[0] == "lvremove") {
			out, err := h.lv(f[0], f[1:])
			return string(out), err
		}
		return "", nil
	}
	r := newRuntime(t, h)
	err := r.Create(context.Background(), sp)
	if err == nil || !strings.Contains(err.Error(), "not making the silo and removing nothing") {
		t.Fatalf("create: %v", err)
	}
	if _, ok := r.state(sp.ID); ok {
		t.Fatal("state was saved after a failed lvs")
	}
	if !h.lvs[n.LV] {
		t.Fatal("the volume was removed")
	}
	for _, c := range h.commands() {
		if strings.Contains(hostCmd(c), "lvcreate") || strings.Contains(hostCmd(c), "lvremove") {
			t.Fatalf("a command changed volumes: %s", c)
		}
	}
}

// The group listing refuses the root LV's own name, not only names with its prefix.
func TestCreateRefusesTheRootLVsOwnName(t *testing.T) {
	h := newFakeHost()
	sp := spec("db")
	n := NamesFor(sp.ID)
	h.lvs[n.LV] = true
	h.answer = func(cmd string) (string, error) {
		if cmd == "lvs --noheadings "+VG+"/"+n.LV {
			return "", errors.New("Failed to find logical volume " + VG + "/" + n.LV)
		}
		if strings.HasPrefix(cmd, "lvs --noheadings -o lv_name") {
			return n.LV, nil // the root LV's own name, with no "-" after it
		}
		if f := strings.Fields(cmd); len(f) > 0 && (f[0] == "lvs" || f[0] == "lvcreate" || f[0] == "lvremove") {
			out, err := h.lv(f[0], f[1:])
			return string(out), err
		}
		return "", nil
	}
	r := newRuntime(t, h)
	err := r.Create(context.Background(), sp)
	if err == nil || !strings.Contains(err.Error(), n.LV) || !strings.Contains(err.Error(), "not making the silo") {
		t.Fatalf("create: %v", err)
	}
	if !h.lvs[n.LV] {
		t.Fatal("the volume was removed")
	}
	for _, c := range h.commands() {
		if strings.Contains(hostCmd(c), "lvcreate") || strings.Contains(hostCmd(c), "lvremove") {
			t.Fatalf("a command changed volumes: %s", c)
		}
	}
}

// A step that fails before this Create made the root LV does not remove that LV.
func TestCreateStepFailureKeepsARootLVItDidNotMake(t *testing.T) {
	h := newFakeHost()
	sp := spec("db")
	n := NamesFor(sp.ID)
	h.lvs[n.LV] = true
	nCalls := 0
	h.answer = func(cmd string) (string, error) {
		if cmd == "lvs --noheadings "+VG+"/"+n.LV {
			nCalls++
			switch nCalls {
			case 1:
				return "", errors.New("Failed to find logical volume " + VG + "/" + n.LV)
			case 2:
				return "", errors.New("lvs: Input/output error")
			default:
				return "  " + n.LV, nil
			}
		}
		if strings.HasPrefix(cmd, "lvs --noheadings -o lv_name") {
			return "", nil
		}
		if f := strings.Fields(cmd); len(f) > 0 && (f[0] == "lvs" || f[0] == "lvcreate" || f[0] == "lvremove") {
			out, err := h.lv(f[0], f[1:])
			return string(out), err
		}
		return "", nil
	}
	r := newRuntime(t, h)
	err := r.Create(context.Background(), sp)
	if err == nil || !strings.Contains(err.Error(), "not removing it") {
		t.Fatalf("create: %v", err)
	}
	if !h.lvs[n.LV] {
		t.Fatal("a step failure removed a root volume this Create did not make")
	}
	for _, c := range h.commands() {
		if strings.Contains(hostCmd(c), "lvremove") && strings.Contains(c, n.LV) {
			t.Fatalf("lvremove of the root: %s", c)
		}
	}
}

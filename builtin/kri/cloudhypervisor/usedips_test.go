package cloudhypervisor

import (
	"context"
	"strings"
	"testing"
)

// K-105's shape in the address book: a silo whose state file can't be read holds an address
// nobody can tell, and may still run. No address is given out on the host until it is readable
// (a new silo could get the running one's), and the error names the file.
func TestNoAddressIsGivenOutWhileAStateIsUnreadable(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	r := newRuntime(t, h)
	if err := r.Create(ctx, spec("web")); err != nil {
		t.Fatal(err)
	}
	bad := NamesFor(spec("web").ID).Dir + "/silo.json"
	good := h.files[bad]
	h.files[bad] = []byte(`{"id": `)
	err := r.Create(ctx, spec("db"))
	if err == nil || !strings.Contains(err.Error(), bad) {
		t.Fatalf("Create with %s unreadable: %v, want a refusal naming it", bad, err)
	}
	if _, ok := r.state(spec("db").ID); ok {
		t.Fatal("db was given an address while web's was unknown")
	}
	h.files[bad] = good
	if err := r.Create(ctx, spec("db")); err != nil {
		t.Fatal(err)
	}
	web, _ := r.state(spec("web").ID)
	db, _ := r.state(spec("db").ID)
	if web.IP == db.IP {
		t.Fatalf("two silos at %s", db.IP)
	}
}

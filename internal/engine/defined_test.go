package engine

import (
	"testing"
	"time"

	"kevaso.com/core/internal/clock"
)

// A defined kind is named by its resource, PLURAL.GROUP (ADR 0005): the engine routes it like any
// kind, and a built-in kind with the same short name stays apart.
func TestDefinedKindKeys(t *testing.T) {
	dbs, silos := newFake("databases.acme.dev"), newFake("Silo")
	e := New(clock.NewFake(time.Now()))
	e.Register(dbs, Options{})
	e.Register(silos, Options{})
	run(t, e)
	db := Key{Kind: "databases.acme.dev", Namespace: "web3", Name: "orders"}
	e.Changed(db)
	eventually(t, "database reconciled", func() bool { return dbs.count(db) == 1 })
	if n := silos.count(Key{Kind: "Silo", Namespace: "web3", Name: "orders"}); n != 0 {
		t.Errorf("the silo controller ran %d times for a database", n)
	}
}

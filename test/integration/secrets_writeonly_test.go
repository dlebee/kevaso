package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

const valuePath = "/apis/kevaso/v1/namespaces/web3/secrets/%s/value?key=token"

// readers polls a secret's value from several goroutines until stop, and records every value any
// of them was given.
type readers struct {
	stop atomic.Bool
	wg   sync.WaitGroup
	mu   sync.Mutex
	seen map[string]int
}

func startReaders(c *cluster, who *client.Client, name string, n int) *readers {
	r := &readers{seen: map[string]int{}}
	for i := 0; i < n; i++ {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for !r.stop.Load() {
				var v client.SecretValue
				if err := who.Call(c.ctx, http.MethodGet, fmt.Sprintf(valuePath, name), nil, &v); err == nil {
					r.mu.Lock()
					r.seen[string(v.Value)]++
					r.mu.Unlock()
				}
			}
		}()
	}
	return r
}

func (r *readers) finish() map[string]int {
	r.stop.Store(true)
	r.wg.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen
}

func getSecret(t *testing.T, who *client.Client, c *cluster, name string) *v1.Secret {
	t.Helper()
	s := &v1.Secret{}
	if err := who.Get(c.ctx, "Secret", "web3", name, s); err != nil {
		t.Fatal(err)
	}
	return s
}

// K-060 (K-018's remainder): the write that loosens a write-only secret, with a new value, must
// never let the old value out. The old value must not be readable at any moment of the write, with
// readers polling all along.
func TestLooseningWriteNeverLetsTheOldValueOut(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	c.bind(t, "ada", "ClusterRole", "admin")
	ada := c.as(t, "ada")
	no, yes := false, true
	const trials = 150
	leaked := 0
	for i := 0; i < trials; i++ {
		name := fmt.Sprintf("wo%d", i)
		sec := secretObj(name, nil, "the-old-write-only-value")
		sec.Spec.ValueReadable = &no
		if err := ada.Create(c.ctx, sec); err != nil {
			t.Fatal(err)
		}
		cur := getSecret(t, ada, c, name)
		rd := startReaders(c, ada, name, 8)
		cur.Spec.ValueReadable = &yes
		cur.Spec.Data = map[string][]byte{"token": []byte("dummy")}
		err := ada.Update(c.ctx, cur)
		seen := rd.finish()
		if err != nil {
			t.Fatal(err)
		}
		if seen["the-old-write-only-value"] > 0 {
			leaked++
		}
		for v := range seen {
			if v != "dummy" {
				t.Errorf("trial %d: a reader was given %q", i, v)
			}
		}
		// And once the write is done the new value is what is read.
		var v client.SecretValue
		if err := ada.Call(c.ctx, http.MethodGet, fmt.Sprintf(valuePath, name), nil, &v); err != nil || string(v.Value) != "dummy" {
			t.Fatalf("trial %d after the write: %q, %v", i, v.Value, err)
		}
	}
	if leaked > 0 {
		t.Errorf("the old write-only value was read back in %d of %d trials", leaked, trials)
	}
}

// K-060: whatever sits between the two writes, a value written while the secret was write-only is
// not returned once the object is readable. (The state is made directly in the store: it is the
// state a reader finds in the window, or after a writer that was slow or a store that was edited.)
func TestValueWrittenWhileWriteOnlyIsNotServedWhenTheObjectTurnsReadable(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	c.bind(t, "ada", "ClusterRole", "admin")
	ada := c.as(t, "ada")
	no, yes := false, true
	sec := secretObj("held", nil, "written-while-write-only")
	sec.Spec.ValueReadable = &no
	if err := ada.Create(c.ctx, sec); err != nil {
		t.Fatal(err)
	}
	k := store.Key{Kind: "Secret", Namespace: "web3", Name: "held"}
	o, err := c.store.Get(c.ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		t.Fatal(err)
	}
	obj.(*v1.Secret).Spec.ValueReadable = &yes
	_, data, err := toMapForTest(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.Update(c.ctx, k, data, o.Revision); err != nil {
		t.Fatal(err)
	}
	var v client.SecretValue
	if err := ada.Call(c.ctx, http.MethodGet, fmt.Sprintf(valuePath, "held"), nil, &v); err == nil || bytes.Contains(v.Value, []byte("written-while")) {
		t.Fatalf("the object turned readable under a value written while it was write-only: err=%v value=%q", err, v.Value)
	}
	// A write that brings its own value makes it readable, with that value.
	cur := getSecret(t, ada, c, "held")
	cur.Spec.Data = map[string][]byte{"token": []byte("fresh")}
	if err := ada.Update(c.ctx, cur); err != nil {
		t.Fatal(err)
	}
	if err := ada.Call(c.ctx, http.MethodGet, fmt.Sprintf(valuePath, "held"), nil, &v); err != nil || string(v.Value) != "fresh" {
		t.Fatalf("after a new value: %q, %v", v.Value, err)
	}
}

// K-060: a mutation policy that sets the setting after the check does not get past it: the check
// is on the object as it will be stored.
func TestMutationPolicyCannotLoosenAWriteOnlySecret(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	c.bind(t, "ada", "ClusterRole", "admin")
	ada := c.as(t, "ada")
	no := false
	sec := secretObj("wo", nil, "write-only-value")
	sec.Spec.ValueReadable = &no
	sec.Spec.AllowedDelivery = []string{v1.DeliverInject}
	if err := ada.Create(c.ctx, sec); err != nil {
		t.Fatal(err)
	}
	flip := func(name, field, value string) {
		t.Helper()
		p := &v1.MutationPolicy{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "MutationPolicy"}, ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.MutationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{"Secret"}}, Mutations: []v1.Mutation{{Field: field, Value: value}}}}
		if err := c.admin.Create(c.ctx, p); err != nil {
			t.Fatalf("policy %s: %v", name, err)
		}
	}
	flip("make-readable", "spec.valueReadable", "true")
	flip("any-delivery", "spec.allowedDelivery", "[]")
	cur := getSecret(t, ada, c, "wo")
	cur.Labels = map[string]string{"touched": "yes"}
	if err := ada.Update(c.ctx, cur); status(err) != http.StatusUnprocessableEntity {
		t.Errorf("an update with no value, loosened by policies: %v, want 422", err)
	}
	var v client.SecretValue
	if err := ada.Call(c.ctx, http.MethodGet, fmt.Sprintf(valuePath, "wo"), nil, &v); err == nil || len(v.Value) != 0 {
		t.Errorf("the write-only value was read back: %v %q", err, v.Value)
	}
	if got := getSecret(t, ada, c, "wo"); got.Readable() || len(got.Spec.AllowedDelivery) != 1 {
		t.Errorf("stored secret was loosened: readable %v, delivery %v", got.Readable(), got.Spec.AllowedDelivery)
	}
	// With a new value in the same write the policies' loosening is a write the person made:
	// allowed, and the old value is gone.
	cur = getSecret(t, ada, c, "wo")
	cur.Spec.Data = map[string][]byte{"token": []byte("new")}
	if err := ada.Update(c.ctx, cur); err != nil {
		t.Fatalf("a write with a new value: %v", err)
	}
	if err := ada.Call(c.ctx, http.MethodGet, fmt.Sprintf(valuePath, "wo"), nil, &v); err != nil || string(v.Value) != "new" {
		t.Errorf("after the write with a value: %q, %v", v.Value, err)
	}
}

// K-060, the invariant: several writers flip a secret between write-only and readable, each write
// carrying a value that says which it was written as, while readers poll. No reader is ever given a
// value that was written while the secret was write-only.
func TestWriteOnlyValuesAreNeverReadUnderConcurrentWriters(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	c.bind(t, "ada", "ClusterRole", "admin")
	ada := c.as(t, "ada")
	no := false
	sec := secretObj("flip", nil, "wo-initial")
	sec.Spec.ValueReadable = &no
	if err := ada.Create(c.ctx, sec); err != nil {
		t.Fatal(err)
	}
	rd := startReaders(c, ada, "flip", 6)
	var wg sync.WaitGroup
	deadline := time.Now().Add(3 * time.Second)
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; time.Now().Before(deadline); i++ {
				s := &v1.Secret{}
				if err := ada.Get(c.ctx, "Secret", "web3", "flip", s); err != nil {
					t.Error(err)
					return
				}
				readable := i%2 == 0
				s.Spec.ValueReadable = &readable
				if readable {
					s.Spec.Data = map[string][]byte{"token": []byte(fmt.Sprintf("ro-%d-%d", w, i))}
				} else {
					s.Spec.Data = map[string][]byte{"token": []byte(fmt.Sprintf("wo-%d-%d", w, i))}
				}
				if err := ada.Update(c.ctx, s); err != nil && status(err) != http.StatusConflict {
					t.Errorf("writer %d: %v", w, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	seen := rd.finish()
	total := 0
	for v, n := range seen {
		total += n
		if len(v) >= 3 && v[:3] == "wo-" {
			t.Errorf("a reader was given %q (%d times): a value written while the secret was write-only", v, n)
		}
	}
	t.Logf("%d reads of %d distinct values", total, len(seen))
}

func toMapForTest(obj meta.Object) (map[string]any, []byte, error) {
	b, err := json.Marshal(obj)
	return nil, b, err
}

// K-060, the same pattern: the type can't change after the check either, or a policy could turn a
// signing key (never readable) into an opaque secret (readable) and read it.
func TestMutationPolicyCannotTurnASigningKeyIntoAReadableSecret(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	c.bind(t, "ada", "ClusterRole", "admin")
	ada := c.as(t, "ada")
	key := secretObj("signer", nil, "")
	key.Spec.Type, key.Spec.Generate = v1.SecretEd25519, v1.PrivateKeyKey
	if err := ada.Create(c.ctx, key); err != nil {
		t.Fatal(err)
	}
	p := &v1.MutationPolicy{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "MutationPolicy"}, ObjectMeta: meta.ObjectMeta{Name: "to-opaque"},
		Spec: v1.MutationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{"Secret"}}, Mutations: []v1.Mutation{{Field: "spec.type", Value: "'opaque'"}}}}
	if err := c.admin.Create(c.ctx, p); err != nil {
		t.Fatal(err)
	}
	var v client.SecretValue
	k := getSecret(t, ada, c, "signer")
	k.Labels = map[string]string{"touched": "yes"}
	err := ada.Update(c.ctx, k)
	if status(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "type can't change") {
		t.Errorf("a policy turning a key into an opaque secret: %v, want 422 saying the type can't change", err)
	}
	if err := ada.Call(c.ctx, http.MethodGet, fmt.Sprintf(valuePath, "signer"), nil, &v); err == nil || len(v.Value) != 0 {
		t.Errorf("the signing key's value was read back: %v", err)
	}
	if got := getSecret(t, ada, c, "signer"); got.Spec.Type != v1.SecretEd25519 {
		t.Errorf("stored type is %s", got.Spec.Type)
	}
}

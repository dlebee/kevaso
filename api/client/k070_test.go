package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// oneSilo is a store of one silo behind the API's paths: GET it, PUT its status at the version
// read (409 otherwise), as the API server does.
type oneSilo struct {
	mu   sync.Mutex
	s    v1.Silo
	puts int
}

func (o *oneSilo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	p, _ := Path("Silo", o.s.Namespace, o.s.Name)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == p:
		_ = json.NewEncoder(w).Encode(&o.s)
	case r.Method == http.MethodPut && r.URL.Path == p+"/status":
		b, _ := io.ReadAll(r.Body)
		var in v1.Silo
		_ = json.Unmarshal(b, &in)
		if in.ResourceVersion != o.s.ResourceVersion || (in.UID != "" && in.UID != o.s.UID) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":409,"reason":"Conflict","message":"stale"}`))
			return
		}
		o.puts++
		o.s.Status = in.Status
		rv, _ := strconv.Atoi(o.s.ResourceVersion)
		o.s.ResourceVersion = strconv.Itoa(rv + 1)
		_ = json.NewEncoder(w).Encode(&o.s)
	default:
		http.NotFound(w, r)
	}
}

func (o *oneSilo) set(f func(*v1.SiloStatus)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	f(&o.s.Status)
	rv, _ := strconv.Atoi(o.s.ResourceVersion)
	o.s.ResourceVersion = strconv.Itoa(rv + 1)
}

func newOneSilo(t *testing.T, st v1.SiloStatus) (*Client, *oneSilo, *v1.Silo) {
	o := &oneSilo{s: v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"},
		ObjectMeta: meta.ObjectMeta{Namespace: "d", Name: "s", UID: "u1", ResourceVersion: "7"}, Status: st}}
	ts := httptest.NewServer(o)
	t.Cleanup(ts.Close)
	read := o.s
	return New(ts.URL), o, &read
}

func drain(host string) func(*v1.Silo) (v1.SiloStatus, error) {
	return func(s *v1.Silo) (v1.SiloStatus, error) {
		st := s.Status
		st.Host, st.Phase, st.MovingFrom = "", "Pending", host
		return st, nil
	}
}

// K-070: StartHandoff never overwrites a handoff under way: it reads afresh, refuses a silo whose
// movingFrom is set, and writes at the version it read; on a conflict it reads again.
func TestK070StartHandoffReadsAfreshAndWritesAtThatVersion(t *testing.T) {
	ctx := context.Background()

	c, o, s := newOneSilo(t, v1.SiloStatus{Host: "D", MovingFrom: "S"})
	if _, err := c.StartHandoff(ctx, s, drain("D")); !errors.Is(err, ErrHandoffUnderWay) {
		t.Fatalf("during S → D: %v, want ErrHandoffUnderWay", err)
	}
	if o.puts != 0 || o.s.Status.MovingFrom != "S" {
		t.Fatalf("written anyway: %d puts, movingFrom %q", o.puts, o.s.Status.MovingFrom)
	}

	// Read before the move began; the move lands before StartHandoff.
	c, o, s = newOneSilo(t, v1.SiloStatus{Host: "D"})
	o.set(func(st *v1.SiloStatus) { st.Host, st.MovingFrom = "E", "D" })
	if _, err := c.StartHandoff(ctx, s, drain("D")); !errors.Is(err, ErrHandoffUnderWay) {
		t.Fatalf("from a stale read: %v, want ErrHandoffUnderWay", err)
	}

	// The move lands between StartHandoff's read and its write.
	c, o, s = newOneSilo(t, v1.SiloStatus{Host: "D"})
	calls := 0
	_, err := c.StartHandoff(ctx, s, func(cur *v1.Silo) (v1.SiloStatus, error) {
		calls++
		if calls == 1 {
			o.set(func(st *v1.SiloStatus) { st.Host, st.MovingFrom = "E", "D" })
		}
		return drain("D")(cur)
	})
	if !errors.Is(err, ErrHandoffUnderWay) || o.s.Status.Host != "E" || o.s.Status.MovingFrom != "D" {
		t.Fatalf("racing move: %v; host %q movingFrom %q", err, o.s.Status.Host, o.s.Status.MovingFrom)
	}

	// Another silo under the name.
	c, _, s = newOneSilo(t, v1.SiloStatus{Host: "D"})
	s.UID = "u0"
	if _, err := c.StartHandoff(ctx, s, drain("D")); !IsConflict(err) {
		t.Fatalf("another UID: %v, want Conflict", err)
	}

	// No handoff: written once, at the version read.
	c, o, s = newOneSilo(t, v1.SiloStatus{Host: "D"})
	out, err := c.StartHandoff(ctx, s, drain("D"))
	if err != nil || o.puts != 1 || out.Status.MovingFrom != "D" || out.ResourceVersion != "8" {
		t.Fatalf("%v: %d puts, %+v", err, o.puts, out)
	}

	// It keeps changing: a few tries, then the conflict, never a silent success.
	c, o, s = newOneSilo(t, v1.SiloStatus{Host: "D"})
	if _, err := c.StartHandoff(ctx, s, func(cur *v1.Silo) (v1.SiloStatus, error) {
		o.set(func(st *v1.SiloStatus) { st.Phase += "." })
		return drain("D")(cur)
	}); !IsConflict(err) || o.puts != 0 {
		t.Fatalf("a silo that keeps changing: %v, %d puts; want a Conflict", err, o.puts)
	}

	// The status function's error stops it, nothing written.
	c, o, s = newOneSilo(t, v1.SiloStatus{Host: "D"})
	boom := errors.New("no")
	if _, err := c.StartHandoff(ctx, s, func(*v1.Silo) (v1.SiloStatus, error) { return v1.SiloStatus{}, boom }); !errors.Is(err, boom) || o.puts != 0 {
		t.Fatalf("%v, %d puts", err, o.puts)
	}
}

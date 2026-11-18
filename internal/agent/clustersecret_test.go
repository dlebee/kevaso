package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/plugins"
)

const clusterSecretPayload = "kevaso-cluster-secret-payload"

// csAPI is a control plane that lists and watches ClusterSecrets and serves their values.
// Answers carry the control-plane headers the test set.
type csAPI struct {
	mu       sync.Mutex
	seen     client.ControlPlaneSeen
	plugin   string
	objs     map[string]*v1.ClusterSecret
	values   map[string][]byte
	forbid   bool
	worker   bool // a worker certificate: side=controller is refused, naming the side
	rev      int64
	fetches  atomic.Int64
	lastFor  atomic.Value // string
	lastSide atomic.Value // string
	watches  []chan []byte
}

func newCSAPI(plugin string) *csAPI {
	return &csAPI{
		seen:   client.ControlPlaneSeen{ClusterID: "c1", History: "h1", Epoch: 1, Revision: 100},
		plugin: plugin,
		objs:   map[string]*v1.ClusterSecret{},
		values: map[string][]byte{},
		rev:    1,
	}
}

func (s *csAPI) stamp(h http.Header) {
	s.mu.Lock()
	seen := s.seen
	s.mu.Unlock()
	client.SetControlPlane(h, seen)
}

func (s *csAPI) watchers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.watches)
}

func (s *csAPI) set(name string, version int64, value []byte) {
	s.mu.Lock()
	s.rev++
	o := &v1.ClusterSecret{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterSecret"},
		ObjectMeta: meta.ObjectMeta{Name: name, UID: "uid-" + name, ResourceVersion: strconv.FormatInt(s.rev, 10)},
		Spec:       v1.ClusterSecretSpec{Value: append([]byte(nil), value...)},
		Status:     v1.ClusterSecretStatus{Version: version},
	}
	s.objs[name] = o
	s.values[name] = append([]byte(nil), value...)
	s.mu.Unlock()
	s.broadcast("MODIFIED", o)
}

func (s *csAPI) del(name string) {
	s.mu.Lock()
	o := s.objs[name]
	delete(s.objs, name)
	delete(s.values, name)
	s.mu.Unlock()
	if o != nil {
		s.broadcast("DELETED", o)
	}
}

// public is the object a list or a watch may carry: metadata and status, never the value.
func (s *csAPI) public(o *v1.ClusterSecret) *v1.ClusterSecret {
	c := *o
	c.Spec.Value = nil
	return &c
}

// recreate is a delete and a create that the watch reports as one new object: the same
// status.version, a new UID, new bytes. The old delivery must not be treated as this one.
func (s *csAPI) recreate(name string, version int64, value []byte) {
	s.mu.Lock()
	s.rev++
	o := &v1.ClusterSecret{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterSecret"},
		ObjectMeta: meta.ObjectMeta{Name: name, UID: "uid-" + name + "-new-" + strconv.FormatInt(s.rev, 10), ResourceVersion: strconv.FormatInt(s.rev, 10)},
		Spec:       v1.ClusterSecretSpec{Value: append([]byte(nil), value...)},
		Status:     v1.ClusterSecretStatus{Version: version},
	}
	s.objs[name] = o
	s.values[name] = append([]byte(nil), value...)
	s.mu.Unlock()
	s.broadcast("MODIFIED", o)
}

func (s *csAPI) broadcast(typ string, o *v1.ClusterSecret) {
	b, err := json.Marshal(s.public(o))
	if err != nil {
		return
	}
	ev, err := json.Marshal(struct {
		Type   string          `json:"type"`
		Object json.RawMessage `json:"object"`
	}{typ, b})
	if err != nil {
		return
	}
	ev = append(ev, '\n')
	s.mu.Lock()
	chs := append([]chan []byte(nil), s.watches...)
	s.mu.Unlock()
	for _, ch := range chs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (s *csAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.stamp(w.Header())
	switch {
	case r.URL.Query().Get("watch") == "true":
		s.serveWatch(w, r)
	case strings.HasSuffix(r.URL.Path, "/value"):
		s.serveValue(w, r)
	default:
		s.serveList(w, r)
	}
}

func (s *csAPI) serveList(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	rev := s.rev
	var items []json.RawMessage
	for _, o := range s.objs {
		b, _ := json.Marshal(s.public(o))
		items = append(items, b)
	}
	s.mu.Unlock()
	if items == nil {
		items = []json.RawMessage{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []json.RawMessage `json:"items"`
	}{struct {
		ResourceVersion string `json:"resourceVersion"`
	}{strconv.FormatInt(rev, 10)}, items})
}

func (s *csAPI) serveWatch(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no flush", http.StatusInternalServerError)
		return
	}
	ch := make(chan []byte, 16)
	s.mu.Lock()
	s.watches = append(s.watches, ch)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		left := s.watches[:0]
		for _, c := range s.watches {
			if c != ch {
				left = append(left, c)
			}
		}
		s.watches = left
		s.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-ch:
			if _, err := w.Write(b); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

func (s *csAPI) serveValue(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/apis/kevaso/v1/clustersecrets/"), "/value")
	s.fetches.Add(1)
	forPlugin := r.URL.Query().Get("for")
	side := r.URL.Query().Get("side")
	s.lastFor.Store(forPlugin)
	s.lastSide.Store(side)
	s.mu.Lock()
	forbid := s.forbid
	worker := s.worker
	want := s.plugin
	val := append([]byte(nil), s.values[name]...)
	ver := int64(0)
	if o := s.objs[name]; o != nil {
		ver = o.Status.Version
	}
	_, ok := s.values[name]
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if forPlugin != want || (side != "node" && side != "controller") {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(client.Error{Code: http.StatusForbidden, Reason: "Forbidden", Message: "a host reads a clustersecret's value with side=node or side=controller"})
		return
	}
	if worker && side != "node" { // a worker certificate asks only for the node side
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(client.Error{Code: http.StatusForbidden, Reason: "Forbidden", Message: "a worker reads a clustersecret only for a plugin's node side (side=node)"})
		return
	}
	if forbid {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(client.Error{Code: http.StatusForbidden, Reason: "Forbidden", Message: "plugin may not read clustersecret " + name})
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(client.Error{Code: http.StatusNotFound, Reason: "NotFound", Message: "not found"})
		return
	}
	_ = json.NewEncoder(w).Encode(client.SecretValue{Value: val, Version: ver})
}

type restartLog struct {
	mu sync.Mutex
	u  []string
}

func (r *restartLog) call(_ context.Context, unit string) error {
	r.mu.Lock()
	r.u = append(r.u, unit)
	r.mu.Unlock()
	return nil
}

func (r *restartLog) units() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.u...)
}

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

type csRig struct {
	t        *testing.T
	api      *csAPI
	a        *Agent
	restarts *restartLog
	logs     *logBuf
	dir      string
	secret   string
	url      string
	cut      atomic.Bool
}

func newCSRig(t *testing.T) *csRig {
	t.Helper()
	dir := t.TempDir()
	plugin := "juicefs"
	if err := os.MkdirAll(filepath.Join(dir, plugin), 0o700); err != nil {
		t.Fatal(err)
	}
	rec, err := plugins.EncodeClusterSecrets([]string{"token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plugins.ClusterSecretsPath(dir, plugin, ""), rec, 0o600); err != nil {
		t.Fatal(err)
	}
	api := newCSAPI(plugin)
	ts := httptest.NewServer(api)
	t.Cleanup(ts.Close)
	logs := &logBuf{}
	restarts := &restartLog{}
	c := client.New(ts.URL)
	wm := OpenWatermark("", func(f string, args ...any) { logs.write(f, args...) })
	a := &Agent{
		Client: c, HostName: "hv1", Clock: clock.Real{}, PluginsEtc: dir,
		ClusterSecretEvery: 20 * time.Millisecond, RestartUnit: restarts.call,
		Watermark: wm, Log: func(f string, args ...any) { logs.write(f, args...) },
	}
	r := &csRig{t: t, api: api, a: a, restarts: restarts, logs: logs, dir: dir, secret: clusterSecretPayload, url: ts.URL}
	r.a.LastContact = func() time.Time {
		if r.cut.Load() {
			return time.Now().Add(-time.Hour)
		}
		return time.Now()
	}
	return r
}

func (l *logBuf) write(f string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.b, f, args...)
	l.b.WriteByte('\n')
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (r *csRig) start() {
	r.t.Helper()
	if r.a.Client.ControlPlane == nil {
		r.a.Client.ControlPlane = r.a.ControlPlaneJudge()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.a.RunClusterSecrets(ctx)
	}()
	r.t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			r.t.Errorf("cluster-secret delivery did not stop")
		}
	})
}

func (r *csRig) path() string { return filepath.Join(r.dir, "juicefs", "token") }

func (r *csRig) wait(d time.Duration, what string, cond func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatalf("timed out waiting for %s; restarts %v; log:\n%s", what, r.restarts.units(), r.logs.String())
}

func (r *csRig) waitWatchers(n int) {
	r.t.Helper()
	r.wait(5*time.Second, "watches to settle", func() bool {
		if r.api.watchers() < n {
			return false
		}
		deadline := time.Now().Add(80 * time.Millisecond)
		for time.Now().Before(deadline) {
			if r.api.watchers() < n {
				return false
			}
			time.Sleep(5 * time.Millisecond)
		}
		return true
	})
}

func (r *csRig) mode() os.FileMode {
	r.t.Helper()
	fi, err := os.Stat(r.path())
	if err != nil {
		r.t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// The first fetch writes the value mode 0600 and restarts the plugin's unit once.
// A later pass with the same version does not restart again, and the value is neither
// logged nor handed to the restart.
func TestClusterSecretFirstDelivery(t *testing.T) {
	r := newCSRig(t)
	r.api.set("token", 1, []byte(r.secret))
	r.start()
	r.wait(3*time.Second, "the file", func() bool {
		b, err := os.ReadFile(r.path())
		return err == nil && string(b) == r.secret && len(r.restarts.units()) == 1
	})
	if got := r.mode(); got != 0o600 {
		t.Fatalf("mode %o, want 0600", got)
	}
	if os.Geteuid() == 0 {
		fi, err := os.Stat(r.path())
		if err != nil {
			t.Fatal(err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			t.Fatalf("owner is not root: %+v", fi.Sys())
		}
	}
	if _, err := os.Stat(r.path() + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file left behind: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if units := r.restarts.units(); len(units) != 1 || units[0] != "kevaso-plugin-juicefs.service" {
		t.Fatalf("restarts %v, want one of the plugin unit", units)
	}
	if forPlugin, _ := r.api.lastFor.Load().(string); forPlugin != "juicefs" {
		t.Fatalf("fetched ?for=%q, want juicefs", forPlugin)
	}
	if side, _ := r.api.lastSide.Load().(string); side != "controller" {
		t.Fatalf("fetched side=%q, want controller", side)
	}
	resp, err := http.Get(r.url + "/apis/kevaso/v1/clustersecrets")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), r.secret) || strings.Contains(string(body), `"value"`) {
		t.Fatalf("list carries a value: %s", body)
	}
	if strings.Contains(r.logs.String(), r.secret) {
		t.Fatalf("the value was logged:\n%s", r.logs.String())
	}
	for _, u := range r.restarts.units() {
		if strings.Contains(u, r.secret) {
			t.Fatalf("the value was passed to the restart: %q", u)
		}
	}
	cmd := systemctlRestart("kevaso-plugin-juicefs.service")
	if cmd.Name != "systemctl" || cmd.Env != nil || cmd.Stdin != nil || len(cmd.Args) != 2 || cmd.Args[0] != "restart" || cmd.Args[1] != "kevaso-plugin-juicefs.service" {
		t.Fatalf("restart command carries more than the unit: %+v", cmd)
	}
}

// A new status.version whose bytes are the ones already on disk rewrites nothing and
// restarts nothing.
func TestClusterSecretUnchangedValueDoesNotRestart(t *testing.T) {
	r := newCSRig(t)
	r.api.set("token", 1, []byte(r.secret))
	r.start()
	r.wait(3*time.Second, "the first write", func() bool {
		b, err := os.ReadFile(r.path())
		return err == nil && string(b) == r.secret && len(r.restarts.units()) == 1
	})
	r.waitWatchers(1)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(r.path(), old, old); err != nil {
		t.Fatal(err)
	}
	before := r.api.fetches.Load()
	r.api.set("token", 2, []byte(r.secret))
	r.wait(3*time.Second, "a refetch of the new version", func() bool { return r.api.fetches.Load() > before })
	time.Sleep(150 * time.Millisecond)
	fi, err := os.Stat(r.path())
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(old) && fi.ModTime().Sub(old).Abs() > time.Second {
		t.Fatalf("unchanged bytes were rewritten (mtime %s)", fi.ModTime())
	}
	if units := r.restarts.units(); len(units) != 1 {
		t.Fatalf("unchanged bytes restarted the plugin: %v", units)
	}
	b, err := os.ReadFile(r.path())
	if err != nil || string(b) != r.secret {
		t.Fatalf("file %q %v", b, err)
	}
}

// A rotation (a new version, different bytes) rewrites the file and restarts the unit.
func TestClusterSecretRotationRewritesAndRestarts(t *testing.T) {
	r := newCSRig(t)
	r.api.set("token", 1, []byte(r.secret))
	r.start()
	r.wait(3*time.Second, "the first write", func() bool {
		b, err := os.ReadFile(r.path())
		return err == nil && string(b) == r.secret && len(r.restarts.units()) == 1
	})
	r.waitWatchers(1)
	rotated := r.secret + "-rotated"
	r.api.set("token", 2, []byte(rotated))
	r.wait(3*time.Second, "the rotated value", func() bool {
		b, err := os.ReadFile(r.path())
		return err == nil && string(b) == rotated && len(r.restarts.units()) == 2
	})
	if got := r.mode(); got != 0o600 {
		t.Fatalf("mode %o after rotation", got)
	}
	time.Sleep(150 * time.Millisecond)
	if units := r.restarts.units(); len(units) != 2 {
		t.Fatalf("restarts %v, want the first delivery and the rotation", units)
	}
	if strings.Contains(r.logs.String(), r.secret) || strings.Contains(r.logs.String(), rotated) {
		t.Fatalf("the value was logged:\n%s", r.logs.String())
	}
}

// A 403 while the agent is held leaves the cached file where it is.
func TestClusterSecretForbiddenWhileHeldKeepsTheFile(t *testing.T) {
	r := newCSRig(t)
	if err := os.WriteFile(r.path(), []byte(r.secret), 0o600); err != nil {
		t.Fatal(err)
	}
	wmFile := filepath.Join(t.TempDir(), "control-plane-watermark.json")
	b, _ := json.Marshal(client.Watermark{ClusterID: "c1", History: "h1", Epoch: 1, Revision: 100, Held: true})
	if err := os.WriteFile(wmFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	wm := OpenWatermark(wmFile, func(f string, args ...any) { r.logs.write(f, args...) })
	r.a.Watermark = wm
	r.a.Client.ControlPlane = wm
	r.api.mu.Lock()
	r.api.forbid = true
	r.api.mu.Unlock()
	r.api.set("token", 1, []byte("other-value-not-the-cache"))
	r.start()
	r.wait(3*time.Second, "a 403", func() bool { return r.api.fetches.Load() > 0 })
	time.Sleep(200 * time.Millisecond)
	got, err := os.ReadFile(r.path())
	if err != nil || string(got) != r.secret {
		t.Fatalf("held 403 removed or rewrote the cache: %q %v", got, err)
	}
	if units := r.restarts.units(); len(units) != 0 {
		t.Fatalf("held 403 restarted the plugin: %v", units)
	}
	if strings.Contains(r.logs.String(), r.secret) {
		t.Fatalf("the value was logged:\n%s", r.logs.String())
	}
}

// A delete seen on the watch, while the agent is not held and is in contact, removes the
// cached file and restarts the plugin.
func TestClusterSecretSeenDeleteRemovesTheFile(t *testing.T) {
	r := newCSRig(t)
	r.api.set("token", 1, []byte(r.secret))
	r.start()
	r.wait(3*time.Second, "the first write", func() bool {
		b, err := os.ReadFile(r.path())
		return err == nil && string(b) == r.secret && len(r.restarts.units()) == 1
	})
	r.waitWatchers(2)
	r.api.del("token")
	r.wait(3*time.Second, "the file to go", func() bool {
		_, err := os.Stat(r.path())
		return os.IsNotExist(err) && len(r.restarts.units()) == 2
	})
	time.Sleep(150 * time.Millisecond)
	if _, err := os.Stat(r.path()); !os.IsNotExist(err) {
		t.Fatalf("the file came back: %v", err)
	}
	if units := r.restarts.units(); len(units) != 2 || units[1] != "kevaso-plugin-juicefs.service" {
		t.Fatalf("restarts %v, want one more after the removal", units)
	}
}

// Cut off from the control plane, a seen delete leaves the cached file in place.
func TestClusterSecretCutOffKeepsTheFile(t *testing.T) {
	r := newCSRig(t)
	r.api.set("token", 1, []byte(r.secret))
	r.start()
	r.wait(3*time.Second, "the first write", func() bool {
		b, err := os.ReadFile(r.path())
		return err == nil && string(b) == r.secret && len(r.restarts.units()) == 1
	})
	r.waitWatchers(2)
	r.cut.Store(true)
	r.api.del("token")
	// Long enough that a delete this agent were willing to act on would have removed the file
	// (the in-contact case does). It must still be here, and leave once contact is back: that
	// is how this test knows the delete was seen and only the cut-off kept the file.
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		got, err := os.ReadFile(r.path())
		if err != nil || string(got) != r.secret {
			t.Fatalf("cut off, the cache was removed: %q %v; restarts %v", got, err, r.restarts.units())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if units := r.restarts.units(); len(units) != 1 {
		t.Fatalf("cut off, the plugin was restarted: %v", units)
	}
	r.cut.Store(false)
	r.wait(3*time.Second, "the file to go once contact is back", func() bool {
		_, err := os.Stat(r.path())
		return os.IsNotExist(err)
	})
}

// A delete and a re-create reuse status.version 1. The new object's UID is not the one
// already delivered, so the new bytes are written again.
func TestClusterSecretRecreateIsDeliveredAgain(t *testing.T) {
	r := newCSRig(t)
	r.api.set("token", 1, []byte(r.secret))
	r.start()
	r.wait(3*time.Second, "the first write", func() bool {
		b, err := os.ReadFile(r.path())
		return err == nil && string(b) == r.secret && len(r.restarts.units()) == 1
	})
	r.waitWatchers(1)
	before := r.api.fetches.Load()
	again := r.secret + "-recreated"
	r.api.recreate("token", 1, []byte(again))
	r.wait(3*time.Second, "the re-created value", func() bool {
		b, err := os.ReadFile(r.path())
		return err == nil && string(b) == again && r.api.fetches.Load() > before
	})
}

// A worker refused the controller side keeps the file. That 403 names the side; it is not
// "the plugin may not read", which is what removes a file.
func TestClusterSecretSideRefusalKeepsTheFile(t *testing.T) {
	r := newCSRig(t)
	if err := os.WriteFile(r.path(), []byte(r.secret), 0o600); err != nil {
		t.Fatal(err)
	}
	r.api.mu.Lock()
	r.api.worker = true
	r.api.mu.Unlock()
	r.api.set("token", 1, []byte(r.secret+"-other"))
	r.start()
	r.wait(3*time.Second, "the side refusal", func() bool {
		return r.api.fetches.Load() > 0 && strings.Contains(r.logs.String(), "only for a plugin's node side")
	})
	time.Sleep(200 * time.Millisecond)
	got, err := os.ReadFile(r.path())
	if err != nil || string(got) != r.secret {
		t.Fatalf("a side refusal removed the file: %q %v", got, err)
	}
	if units := r.restarts.units(); len(units) != 0 {
		t.Fatalf("a side refusal restarted the plugin: %v", units)
	}
}

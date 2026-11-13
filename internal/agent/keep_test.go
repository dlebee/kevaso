package agent_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// Daemons and upkeep through the agent, against a fake silo that answers like the real scripts:
// a daemon that isn't there is started once and then reported Running; an upkeep check that fails
// runs the fix and passes after it (Fixed); a fix that doesn't help marks the silo Degraded.
func TestAgentKeepsDaemonsAndUpkeep(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})

	var mu sync.Mutex
	started := map[string]int{}
	fixed := false
	rt := fake.New()
	rt.Handler = func(_ kri.ID, cmd []string, _ []byte) (string, int) {
		mu.Lock()
		defer mu.Unlock()
		script := strings.Join(cmd, " ")
		switch {
		case strings.Contains(script, "kill -0"): // probe
			if strings.Contains(script, "claude.pid") && started["claude"] > 0 {
				return "running\n", 0
			}
			return "absent\n", 0
		case strings.Contains(script, "setsid"): // start
			if strings.Contains(script, "claude remote-control") {
				started["claude"]++
			}
			return "", 0
		case strings.Contains(script, "version-is-current"):
			if fixed {
				return "", 0
			}
			return "", 1
		case strings.Contains(script, "npm install"):
			fixed = true
			return "", 0
		case strings.Contains(script, "disk-has-room"):
			return "", 1
		case strings.Contains(script, "clean-cache"):
			return "rm: cannot remove /cache: busy", 1
		}
		return "", 0
	}
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}}
	go a.Run(ctx)

	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "agent", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Daemons: []v1.Daemon{{Name: "claude", Run: "claude remote-control", User: "dev"}},
			Upkeep: []v1.Upkeep{
				{Name: "claude up to date", Every: "6h", Check: "version-is-current", Fix: "npm install -g claude"},
				{Name: "room on disk", Every: "1h", Check: "disk-has-room", Fix: "clean-cache"},
			}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	var got v1.Silo
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.Get(ctx, "Silo", "dev", "agent", &got)
		if len(got.Status.Daemons) == 1 && len(got.Status.Upkeep) == 2 && meta.IsTrue(got.Status.Conditions, "Degraded") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(got.Status.Daemons) != 1 || got.Status.Daemons[0].State != v1.DaemonRunning {
		t.Fatalf("daemons: %+v", got.Status.Daemons)
	}
	up := map[string]v1.UpkeepStatus{}
	for _, u := range got.Status.Upkeep {
		up[u.Name] = u
	}
	if up["claude up to date"].State != v1.UpkeepFixed || up["room on disk"].State != v1.UpkeepFailed || !strings.Contains(up["room on disk"].Message, "busy") {
		t.Fatalf("upkeep: %+v", got.Status.Upkeep)
	}
	if c := meta.FindCondition(got.Status.Conditions, "Degraded"); c == nil || !strings.Contains(c.Message, "room on disk") {
		t.Fatalf("Degraded: %+v", c)
	}
	mu.Lock()
	defer mu.Unlock()
	if started["claude"] != 1 {
		t.Fatalf("claude started %d times", started["claude"])
	}
}

// A probe that prints something else (here a warning and nothing more) is unknown, not absent: a
// started daemon isn't started again. Before, every such probe started another copy, and each
// start changed the silo's status, which brought the next round, and the next copy.
func TestAgentDoesntStartADaemonTwiceOnAnOddProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})

	var mu sync.Mutex
	started, probes := 0, 0
	rt := fake.New()
	rt.Handler = func(_ kri.ID, cmd []string, _ []byte) (string, int) {
		mu.Lock()
		defer mu.Unlock()
		script := strings.Join(cmd, " ")
		switch {
		case strings.Contains(script, "kill -0"): // probe
			probes++
			if started == 0 {
				return "absent\n", 0
			}
			return "sudo: unable to resolve host agent\n", 0
		case strings.Contains(script, "setsid"): // start
			started++
		}
		return "", 0
	}
	var logs safeLog
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}, Log: logs.printf}
	go a.Run(ctx)
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "agent", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Daemons: []v1.Daemon{{Name: "ticker", Run: "while true; do sleep 1; done"}}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		p := probes
		mu.Unlock()
		if p >= 3 {
			break
		}
		// Changes to the silo bring rounds sooner than the probe period.
		var got v1.Silo
		if c.Get(ctx, "Silo", "dev", "agent", &got) == nil {
			if got.Labels == nil {
				got.Labels = map[string]string{}
			}
			got.Labels["poke"] = time.Now().Format("150405.000000")
			_ = c.Update(ctx, &got)
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if probes < 3 {
		t.Fatalf("only %d probes", probes)
	}
	if started != 1 {
		t.Fatalf("the daemon was started %d times after %d probes", started, probes)
	}
	if !strings.Contains(logs.String(), `the probe said "sudo: unable to resolve host agent"`) {
		t.Errorf("the odd probe isn't logged:\n%s", logs.String())
	}
}

type safeLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *safeLog) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.b, format+"\n", args...)
}

func (l *safeLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

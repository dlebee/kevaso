package plugins

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"

	"kevaso.com/core/sdk/kplugin"
	pb "kevaso.com/core/sdk/kplugin/kpluginpb"
)

// oldIdentity is a plugin built against an sdk of another wire revision: what its Identity
// service answers, as it would over the wire.
type oldIdentity struct {
	pb.UnimplementedIdentityServer
	revision uint32
}

func (o oldIdentity) GetPluginInfo(context.Context, *pb.GetPluginInfoRequest) (*pb.PluginInfo, error) {
	return &pb.PluginInfo{Name: "old", Version: "0.1.0", Protocol: kplugin.Protocol, Revision: o.revision,
		Storage: []*pb.Class{{Name: "old-block"}}}, nil
}

func serveIdentity(t *testing.T, sock string, revision uint32) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(sock), 0o750); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	pb.RegisterIdentityServer(s, oldIdentity{revision: revision})
	go func() { _ = s.Serve(l) }()
	t.Cleanup(s.Stop)
}

type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) logf(f string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
	l.mu.Unlock()
}

func (l *logs) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// Version skew: the only check was the protocol string, which the sdk's own server fills in, so a
// plugin built against an sdk whose messages meant other things registered and served. Core now
// refuses a plugin whose wire revision it doesn't serve, saying once what to do; one it serves
// registers.
func TestPluginsOfAnotherSDKRevisionAreRefused(t *testing.T) {
	for _, tc := range []struct {
		revision uint32
		ok       bool
		says     string
	}{
		{0, false, "built against an sdk from before wire revisions"},
		{kplugin.Revision + 1, false, fmt.Sprintf("wire revision %d", kplugin.Revision+1)},
		{kplugin.Revision, true, ""},
	} {
		t.Run(fmt.Sprint(tc.revision), func(t *testing.T) {
			dir, _ := os.MkdirTemp("", "kps")
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			serveIdentity(t, filepath.Join(dir, "old", "plugin.sock"), tc.revision)
			var l logs
			r := &Registry{Dir: dir, Log: l.logf}
			for range 3 {
				r.scan(context.Background(), dir)
			}
			_, _, found := r.Storage("old-block")
			if found != tc.ok {
				t.Fatalf("registered: %v, want %v (log: %s)", found, tc.ok, l.all())
			}
			if tc.ok {
				return
			}
			if got := l.all(); !strings.Contains(got, tc.says) || !strings.Contains(got, "rebuild") || strings.Count(got, "refused") != 1 {
				t.Errorf("log, want one line saying %q:\n%s", tc.says, got)
			}
		})
	}
}

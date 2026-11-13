package apiserver

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/pki"
)

func TestFileCommand(t *testing.T) {
	for _, c := range []struct {
		op, path string
		want     []string
	}{
		{client.FileRead, "/srv/app/", []string{"tar", "-cf", "-", "-C", "/srv/", "./app"}},
		{client.FileRead, "/tmp/-rf", []string{"tar", "-cf", "-", "-C", "/tmp/", "./-rf"}}, // never an option
		{client.FileRead, "/", []string{"tar", "-cf", "-", "-C", "/", "."}},
		{client.FileWrite, "/srv/../srv/x", []string{"tar", "-xf", "-", "-C", "/srv/x"}},
		{client.FileList, "/etc", []string{"ls", "-lAn", "--", "/etc/"}},
		{client.FileList, "/", []string{"ls", "-lAn", "--", "/"}},
		{client.FileStat, "/etc/hosts", []string{"ls", "-ldn", "--", "/etc/hosts"}},
	} {
		got, err := FileCommand(c.op, c.path)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%s %s: %q %v, want %q", c.op, c.path, got, err, c.want)
		}
	}
	for _, bad := range [][2]string{{client.FileRead, "relative"}, {client.FileRead, ""}, {client.FileList, "/a\nb"}, {"rm", "/"}} {
		if _, err := FileCommand(bad[0], bad[1]); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

// RBAC terms of the new subresources, and worker hosts never get them.
func TestSiloStreamAttributes(t *testing.T) {
	id := pki.Identity{Type: "user", Name: "bob"}
	for _, c := range []struct {
		method, path, verb, res string
	}{
		{http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/web/ssh", "create", "silos/ssh"},
		{http.MethodGet, "/apis/kevaso/v1/namespaces/dev/silos/web/files?op=read&path=/x", "get", "silos/files"},
		{http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/web/files?op=write&path=/x", "create", "silos/files"},
	} {
		r := httptest.NewRequest(c.method, c.path, nil)
		tg, err := parsePath(r.URL.Path)
		if err != nil {
			t.Fatal(err)
		}
		a := attributes(id, nil, r, tg)
		if a.Verb != c.verb || a.Resource != c.res || a.Name != "web" || a.Namespace != "dev" {
			t.Errorf("%s %s: %+v", c.method, c.path, a)
		}
		if hostAuthorize(pki.Identity{Type: "host", Name: "hv1", Role: "worker"}, r, tg) {
			t.Errorf("a worker host may %s %s", c.method, c.path)
		}
	}
	if _, err := parsePath("/apis/kevaso/v1/namespaces/dev/hosts/web/ssh"); err == nil {
		t.Error("ssh on a host")
	}
}

// The capped relay ends a transfer once either way is over its limit, telling the client why.
func TestRelayLimited(t *testing.T) {
	for _, way := range []string{"upload", "download"} {
		cli, srvSide := net.Pipe()
		agentSide, agent := net.Pipe()
		go relayLimited(srvSide, bufio.NewReader(srvSide), agentSide, 10)
		go func() { // the agent: reads frames, answers with output
			br := bufio.NewReader(agent)
			if way == "download" {
				_ = client.WriteFrame(agent, client.FrameStdout, []byte("0123456789"))
				_ = client.WriteFrame(agent, client.FrameStdout, []byte("x"))
			}
			for {
				if _, _, err := client.ReadFrame(br); err != nil {
					return
				}
			}
		}()
		if way == "upload" {
			go func() {
				_ = client.WriteFrame(cli, client.FrameStdin, []byte("01234"))
				_ = client.WriteFrame(cli, client.FrameStdin, []byte("567890"))
			}()
		}
		_, err := client.ReadOutput(cli, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "the "+way+" is over the 10 byte limit") {
			t.Errorf("%s: %v", way, err)
		}
		_ = cli.Close()
		_ = agent.Close()
	}
}

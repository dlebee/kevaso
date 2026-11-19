package cloudhypervisor

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withDownloadHooks(t *testing.T,
	lookup func(context.Context, string, string) ([]netip.Addr, error),
	connect func(context.Context, string, string) (net.Conn, error),
) {
	t.Helper()
	downloadMu.Lock()
	oldL, oldC := downloadLookup, downloadConnect
	downloadLookup, downloadConnect = lookup, connect
	downloadMu.Unlock()
	t.Cleanup(func() {
		downloadMu.Lock()
		downloadLookup, downloadConnect = oldL, oldC
		downloadMu.Unlock()
	})
}

func publicDisk(t *testing.T, h http.Handler) (string, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	withDownloadHooks(t, func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}, func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, err
		}
		if why, no := fetchRefused(ip); no {
			t.Errorf("dialed a refused address %s (%s)", ip, why)
			return nil, errDiskTooBig
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	})
	return "http://files.example", srv
}

func TestDiskDownloadRefusesABodyLargerThanTheDisk(t *testing.T) {
	body := bytesRepeat(64)
	base, _ := publicDisk(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			if _, err := w.Write(body[:8]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			_, _ = w.Write(body[8:])
			return
		}
		_, _ = w.Write(body)
	}))
	dst := filepath.Join(t.TempDir(), "disk.download")
	err := download(context.Background(), base+"/disk", dst, 8)
	if err == nil || !strings.Contains(err.Error(), "larger than the disk") {
		t.Fatalf("sized body: %v", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("partial file: %v", statErr)
	}
	stream := filepath.Join(t.TempDir(), "stream.download")
	err = download(context.Background(), base+"/stream", stream, 8)
	if err == nil || !strings.Contains(err.Error(), "larger than the disk") {
		t.Fatalf("streamed body: %v", err)
	}
	if _, statErr := os.Stat(stream); !os.IsNotExist(statErr) {
		t.Fatalf("streamed partial file: %v", statErr)
	}
	exact := filepath.Join(t.TempDir(), "exact.download")
	if err := download(context.Background(), base+"/disk", exact, int64(len(body))); err != nil {
		t.Fatalf("a body the size of the disk: %v", err)
	}
}

func TestDiskDownloadRefusesAPrivateRedirect(t *testing.T) {
	for _, dest := range []struct{ url, why string }{
		{"http://127.0.0.1/x", "loopback"},
		{"http://10.64.0.5/x", "silo range"},
		{"http://192.168.1.1/x", "private"},
		{"http://169.254.169.254/latest", "link-local"},
	} {
		t.Run(dest.why, func(t *testing.T) {
			base, _ := publicDisk(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, dest.url, http.StatusFound)
			}))
			err := download(context.Background(), base+"/go", filepath.Join(t.TempDir(), "disk.download"), 0)
			if err == nil || !strings.Contains(err.Error(), dest.why) {
				t.Fatalf("redirect to %s: %v, want %s", dest.url, err, dest.why)
			}
		})
	}
}

func TestDiskDownloadRefusesAClusterAddress(t *testing.T) {
	err := download(context.Background(), "http://10.64.0.5/disk", filepath.Join(t.TempDir(), "disk.download"), 0)
	if err == nil || !strings.Contains(err.Error(), "silo range") {
		t.Fatal(err)
	}
}

func bytesRepeat(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return b
}

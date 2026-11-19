package cloudhypervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"

	v1 "kevaso.com/core/api/v1"
)

// The disk fetch stays in this process. runConfined, the kevaso-img unit, has PrivateNetwork=yes
// and runs only qemu-img, with one image and one target bind-mounted. Opening that unit's network
// would undo the confinement, and the unit cannot speak HTTPS. The bounds are here instead: the
// body is capped at the disk's size, and every address, after DNS and including a redirect, is
// refused when it is inside a cluster range, loopback, link-local or a private range.

// downloadLookup and downloadConnect are the dial. Tests point a public name at a local server
// without turning the refusal off: a literal private, loopback or link-local address is still
// refused before connect.
var (
	downloadMu     sync.Mutex
	downloadLookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, network, host)
	}
	downloadConnect = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
)

func fetchHooks() (
	func(context.Context, string, string) ([]netip.Addr, error),
	func(context.Context, string, string) (net.Conn, error),
) {
	downloadMu.Lock()
	defer downloadMu.Unlock()
	return downloadLookup, downloadConnect
}

// fetchRefused says why ip must not be fetched from. A cluster range, loopback or link-local is
// named by ClosedRange first (10.64 is the silo range, not "a private address"); other private
// ranges are the egress gate's Special.
func fetchRefused(ip netip.Addr) (string, bool) {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return "not an address", true
	}
	if _, why := v1.ClosedRange(netip.PrefixFrom(ip, ip.BitLen())); why != "" {
		return why, true
	}
	if _, why := v1.Special(ip); why != "" {
		return why, true
	}
	return "", false
}

func resolveFetch(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap().WithZone("")}, nil
	}
	lookup, _ := fetchHooks()
	return lookup(ctx, "ip", host)
}

// fetchDial checks every address the name resolved to, then dials one of those addresses. It does
// not resolve again, so a name cannot move to a private address between the check and the connect.
// A redirect is checked the same way: the client dials the redirect's target through here.
func fetchDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := resolveFetch(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("GET %s: no address", host)
	}
	var why string
	for _, ip := range ips {
		if w, no := fetchRefused(ip); no {
			why = w
		}
	}
	if why != "" {
		return nil, fmt.Errorf("GET %s: %s", host, why)
	}
	_, connect := fetchHooks()
	var last error
	for _, ip := range ips {
		c, err := connect(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

var errDiskTooBig = errors.New("larger than the disk")

// download GETs rawURL into dst. limit caps the body (0: no cap, a release asset). A larger body
// is refused and dst, including a partial one, is removed. An env proxy is not used: it would
// connect somewhere the address check did not see.
func download(ctx context.Context, rawURL, dst string, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: fetchDial}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	if limit > 0 && resp.ContentLength > limit {
		_ = os.Remove(dst)
		return fmt.Errorf("GET %s: %d bytes, larger than the disk's %d bytes", rawURL, resp.ContentLength, limit)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	body := io.Reader(resp.Body)
	if limit > 0 {
		body = &maxReader{r: resp.Body, n: limit}
	}
	_, copyErr := io.Copy(f, body)
	closeErr := f.Close()
	if errors.Is(copyErr, errDiskTooBig) {
		_ = os.Remove(dst)
		return fmt.Errorf("GET %s: body is larger than the disk's %d bytes", rawURL, limit)
	}
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// maxReader reads at most n bytes, then one more: that extra byte is a body over the disk's size.
type maxReader struct {
	r io.Reader
	n int64
}

func (m *maxReader) Read(p []byte) (int, error) {
	if m.n <= 0 {
		var b [1]byte
		n, err := m.r.Read(b[:])
		if n > 0 {
			return 0, errDiskTooBig
		}
		if err == io.EOF || err == nil {
			return 0, io.EOF
		}
		return 0, err
	}
	if int64(len(p)) > m.n {
		p = p[:m.n]
	}
	n, err := m.r.Read(p)
	m.n -= int64(n)
	return n, err
}

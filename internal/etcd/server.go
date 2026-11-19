// Package etcd runs the control plane's embedded etcd member (design §4.1: SQLite for one system
// node, embedded etcd for HA) and decides how its membership changes (membership.go).
//
// The member keeps its data under Config.Dir. Client and peer traffic are TLS from the cluster CA
// (internal/pki), both directions authenticated: a member's certificate is a server and client
// certificate with the common name "kevaso-etcd", and both listeners accept only that name, so a
// host's or a user's certificate from the same CA (common names "host:…", "user:…") can't speak to
// etcd. The client listener is meant for loopback (the control plane on this host); the peer
// listener opens only when Config.PeerListen says where.
package etcd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
	"go.uber.org/zap"

	"kevaso.com/core/internal/pki"
)

// MemberCN is the common name of every etcd member's certificate, and the only one etcd accepts.
const MemberCN = "kevaso-etcd"

// DefaultClientListen is where the member serves its clients: loopback, for this host's control plane.
const DefaultClientListen = "127.0.0.1:2379"

// unlistenedPeer is the peer URL a member without a peer listener advertises. A single member never
// dials its own peer URL; when peers are configured later, Start updates the member's entry.
const unlistenedPeer = "https://127.0.0.1:2380"

// Config is one etcd member.
type Config struct {
	Name string // the member's name: the host's name
	Dir  string // its data directory (e.g. <data>/etcd)
	CA   *pki.CA
	// ClientListen is host:port for clients (default DefaultClientListen; port 0 picks one).
	ClientListen string
	// PeerListen is host:port for the other members; "" opens no peer listener (one member).
	PeerListen string
	// AdvertisePeer is the host:port other members dial; "" means PeerListen.
	AdvertisePeer string
	// local reports whether an IP is on this machine. Nil uses the machine's interfaces.
	// Tests set it so the bind decision does not depend on the host that runs them.
	local func(string) bool
	// Names are more DNS names or IPs for the member's certificate (the host's address).
	Names []string
	// InitialCluster is name → peer URL of every member when joining an existing cluster
	// (Join true); empty for a new one-member cluster.
	InitialCluster map[string]string
	Join           bool
	// UnsafeNoFsync skips fsync: tests only.
	UnsafeNoFsync bool
	// Logger gets etcd's own logs; nil: none.
	Logger *zap.Logger
	// ReadyTimeout bounds the wait for the member to serve (default 1 minute).
	ReadyTimeout time.Duration
}

// Server is a started member.
type Server struct {
	Etcd      *embed.Etcd
	ClientURL string // where its client listener is, e.g. https://127.0.0.1:2379
	PeerURL   string // what it advertises to peers
	clientTLS *tls.Config
	ca        *pki.CA
	names     []string
	files     tlsFiles
}

// Start starts the member and returns once it serves.
func Start(ctx context.Context, c Config) (*Server, error) {
	if c.Name == "" || c.Dir == "" || c.CA == nil {
		return nil, errors.New("etcd member needs a name, a directory and the cluster CA")
	}
	if c.ClientListen == "" {
		c.ClientListen = DefaultClientListen
	}
	if c.AdvertisePeer == "" {
		c.AdvertisePeer = c.PeerListen
	}
	if c.ReadyTimeout <= 0 {
		c.ReadyTimeout = time.Minute
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return nil, err
	}
	tlsDir := filepath.Join(c.Dir, "tls")
	names := append([]string{c.Name, "127.0.0.1", "localhost"}, c.Names...)
	for _, hp := range []string{c.PeerListen, c.AdvertisePeer, c.ClientListen} {
		if h, _, err := net.SplitHostPort(hp); err == nil && h != "" && h != "0.0.0.0" && h != "::" {
			names = append(names, h)
		}
	}
	cert, err := MemberCert(c.CA, names, time.Now(), 365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	files, err := writeTLS(tlsDir, c.CA, cert)
	if err != nil {
		return nil, err
	}

	cfg := embed.NewConfig()
	cfg.Name = c.Name
	cfg.Dir = filepath.Join(c.Dir, "data")
	cfg.InitialClusterToken = "kevaso"
	cfg.UnsafeNoFsync = c.UnsafeNoFsync
	cfg.StrictReconfigCheck = true // etcd refuses a member change that would lose quorum
	cfg.ListenClientUrls = []url.URL{{Scheme: "https", Host: c.ClientListen}}
	cfg.AdvertiseClientUrls = cfg.ListenClientUrls
	peer := unlistenedPeer
	cfg.ListenPeerUrls = nil
	if c.PeerListen != "" {
		local := c.local
		if local == nil {
			local = addrIsLocal
		}
		for _, hp := range peerListenHosts(c.PeerListen, c.AdvertisePeer, local) {
			cfg.ListenPeerUrls = append(cfg.ListenPeerUrls, url.URL{Scheme: "https", Host: hp})
		}
		peer = "https://" + c.AdvertisePeer
	}
	pu, err := url.Parse(peer)
	if err != nil {
		return nil, err
	}
	cfg.AdvertisePeerUrls = []url.URL{*pu}
	tlsInfo := files.info()
	cfg.ClientTLSInfo, cfg.PeerTLSInfo = tlsInfo, tlsInfo
	cfg.ClusterState = embed.ClusterStateFlagNew
	cfg.InitialCluster = c.Name + "=" + peer
	if c.Join {
		cfg.ClusterState = embed.ClusterStateFlagExisting
		var parts []string
		for n, u := range c.InitialCluster {
			parts = append(parts, n+"="+u)
		}
		sort.Strings(parts)
		cfg.InitialCluster = strings.Join(parts, ",")
	}
	logger := c.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	cfg.ZapLoggerBuilder = embed.NewZapLoggerBuilder(logger)

	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return nil, fmt.Errorf("etcd: %w", err)
	}
	select {
	case <-e.Server.ReadyNotify():
	case err := <-e.Err():
		e.Close()
		return nil, fmt.Errorf("etcd: %w", err)
	case <-time.After(c.ReadyTimeout):
		e.Close()
		return nil, fmt.Errorf("etcd: member %s not ready after %v (no quorum?)", c.Name, c.ReadyTimeout)
	case <-ctx.Done():
		e.Close()
		return nil, ctx.Err()
	}
	s := &Server{
		Etcd:      e,
		ClientURL: "https://" + e.Clients[0].Addr().String(),
		PeerURL:   peer,
		clientTLS: &tls.Config{RootCAs: c.CA.Pool(), MinVersion: tls.VersionTLS12,
			// Read from the files at each handshake, as etcd does: a rotated certificate (rotate.go)
			// is used from the next connection on, with no restart.
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				c, err := tls.LoadX509KeyPair(files.cert, files.key)
				return &c, err
			}},
		ca: c.CA, names: names, files: files,
	}
	if err := s.advertise(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// peerListenHosts is where the member binds for peers. listen is the internal address.
// advertise is what other members dial. When that address is a different one and it is
// on a local interface, bind it too: peers dial it, and the internal listener would not
// answer. When it is not local (1:1 NAT delivers it to the internal listener), bind the
// internal address only. Never 0.0.0.0 or ::. The peer port is mutual TLS, which limits
// who finishes a handshake and does not keep the port off an unrelated interface.
func peerListenHosts(listen, advertise string, local func(string) bool) []string {
	if listen == "" {
		return nil
	}
	out := []string{listen}
	if advertise == "" || advertise == listen {
		return out
	}
	host, _, err := net.SplitHostPort(advertise)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		return out
	}
	if !local(host) {
		return out
	}
	return append(out, advertise)
}

// addrIsLocal reports whether host is an IP on one of this machine's interfaces.
// An error, or a name that is not an IP, is not local: an address that cannot be
// confirmed is not bound.
func addrIsLocal(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var got net.IP
		switch v := a.(type) {
		case *net.IPNet:
			got = v.IP
		case *net.IPAddr:
			got = v.IP
		}
		if got != nil && got.Equal(ip) {
			return true
		}
	}
	return false
}

// advertise makes the member's entry carry the peer URL it now advertises: a member first started
// without peers advertised unlistenedPeer, and opening its peer listener later must say so to the
// cluster before a second member can join.
func (s *Server) advertise(ctx context.Context) error {
	if s.Etcd.Server.IsLearner() {
		return nil // a learner just joined with the URL it was added with (and can't change members)
	}
	cli, err := s.Client()
	if err != nil {
		return err
	}
	defer func() { _ = cli.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	id := uint64(s.Etcd.Server.MemberID())
	ml, err := cli.MemberList(ctx)
	if err != nil {
		return fmt.Errorf("etcd member list: %w", err)
	}
	for _, m := range ml.Members {
		if m.ID == id && (len(m.PeerURLs) != 1 || m.PeerURLs[0] != s.PeerURL) {
			if _, err := cli.MemberUpdate(ctx, id, []string{s.PeerURL}); err != nil {
				return fmt.Errorf("etcd: advertising peer URL %s: %w", s.PeerURL, err)
			}
		}
	}
	return nil
}

// Client returns a new client of this member, authenticated with the member's certificate.
func (s *Server) Client() (*clientv3.Client, error) {
	return clientv3.New(clientv3.Config{
		Endpoints:   []string{s.ClientURL},
		TLS:         s.clientTLS.Clone(),
		DialTimeout: 5 * time.Second,
		Logger:      zap.NewNop(),
	})
}

// Close stops the member.
func (s *Server) Close() { s.Etcd.Close() }

// MemberCert issues an etcd member's certificate: server and client, common name MemberCN.
func MemberCert(ca *pki.CA, names []string, now time.Time, ttl time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: MemberCN},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

type tlsFiles struct{ ca, cert, key string }

func (f tlsFiles) info() (ti transport.TLSInfo) {
	ti.CertFile, ti.KeyFile, ti.TrustedCAFile = f.cert, f.key, f.ca
	ti.ClientCertAuth = true
	ti.AllowedCNs = []string{MemberCN}
	return ti
}

// writeTLS writes the CA and the member's certificate and key where etcd reads them (it takes files).
func writeTLS(dir string, ca *pki.CA, cert tls.Certificate) (tlsFiles, error) {
	f := tlsFiles{ca: filepath.Join(dir, "ca.crt"), cert: filepath.Join(dir, "member.crt"), key: filepath.Join(dir, "member.key")}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return f, err
	}
	kd, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return f, err
	}
	for _, w := range []struct {
		path string
		data []byte
	}{
		{f.ca, ca.PEM},
		{f.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})},
		{f.key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})},
	} {
		if err := os.WriteFile(w.path, w.data, 0o600); err != nil {
			return f, err
		}
	}
	return f, nil
}

package client

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSplitServers(t *testing.T) {
	got := SplitServers(" https://a:6443/, https://b:6443 ,,")
	if strings.Join(got, "|") != "https://a:6443|https://b:6443" {
		t.Fatal(got)
	}
}

// The first control plane can't be reached: requests go to the next, and stay there.
func TestFailoverToTheNextControlPlane(t *testing.T) {
	hits := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"type":"user","name":"ops"}`))
	}))
	defer ts.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "https://" + l.Addr().String()
	_ = l.Close() // nothing listens there now
	c, err := NewTLSEndpoints([]string{dead, ts.URL}, ca, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		var who WhoAmI
		if err := c.Call(context.Background(), http.MethodPost, "/auth/whoami", map[string]string{"a": "b"}, &who); err != nil || who.Name != "ops" {
			t.Fatalf("call %d: %v %+v", i, err, who)
		}
	}
	if hits != 3 {
		t.Fatalf("%d hits", hits)
	}
	if f := c.HTTP.Transport.(*failover); f.start() != 1 {
		t.Fatalf("didn't stick to the live one: %d", f.start())
	}
	if eps := c.Endpoints(); len(eps) != 2 {
		t.Fatal(eps)
	}
	if p := c.Pinned(ts.URL); p.BaseURL != ts.URL || p.HTTP.Transport == c.HTTP.Transport {
		t.Fatal("Pinned kept the failover")
	}
	// Every control plane down: the error says so (a dial error), no hang.
	c2, _ := NewTLSEndpoints([]string{dead, dead}, ca, nil, nil)
	if err := c2.Call(context.Background(), http.MethodGet, "/healthz", nil, nil); err == nil {
		t.Fatal("no error with every endpoint down")
	}
}

// A client set up with one control plane learns more (an agent, from the system nodes' Hosts),
// and fails over to them when its first is gone.
func TestAddEndpoints(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"user","name":"ops"}`))
	}))
	defer ts.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "https://" + l.Addr().String()
	_ = l.Close()
	c, err := NewTLSEndpoints([]string{dead}, ca, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Call(context.Background(), http.MethodGet, "/healthz", nil, nil); err == nil {
		t.Fatal("reached a dead control plane")
	}
	if !c.AddEndpoints(dead, ts.URL+"/") || c.AddEndpoints(ts.URL) {
		t.Fatal("AddEndpoints: want new once, then nothing new")
	}
	var who WhoAmI
	if err := c.Call(context.Background(), http.MethodPost, "/auth/whoami", map[string]string{}, &who); err != nil || who.Name != "ops" {
		t.Fatalf("after learning %s: %v", ts.URL, err)
	}
	if eps := c.Endpoints(); len(eps) != 2 || eps[0] != dead {
		t.Fatal(eps)
	}
	if one, _ := NewTLS(ts.URL, ca, nil, nil); one.AddEndpoints(dead) {
		t.Fatal("a one-server client took another")
	}
}

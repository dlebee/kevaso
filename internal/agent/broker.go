package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"sync"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// Broker serves the secret broker on this host: one listener per silo, on the silo's own channel
// (vsock), so who is asking is the listener a connection arrived on (E014). Requests are relayed to
// the control plane, which decides; only the ops a silo may ask for are forwarded.
type Broker struct {
	Client   *client.Client
	HostName string
	Log      func(string, ...any)

	mu        sync.Mutex
	listeners map[string]net.Listener             // by silo uid
	watchers  map[string]map[chan string]struct{} // by namespace/name
	ids       map[string]kri.ID                   // by uid
}

var siloOps = []string{client.OpGetSecret, client.OpSign, client.OpPublicKey, client.OpDeliveries, client.OpWatch}

func (b *Broker) log(f string, a ...any) {
	if b.Log != nil {
		b.Log(f, a...)
	}
}

// Ensure listens on id's channel if it isn't yet.
func (b *Broker) Ensure(ctx context.Context, rt kri.Broker, id kri.ID) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listeners == nil {
		b.listeners, b.watchers, b.ids = map[string]net.Listener{}, map[string]map[chan string]struct{}{}, map[string]kri.ID{}
	}
	if _, ok := b.listeners[id.UID]; ok {
		return nil
	}
	l, err := rt.BrokerListen(id, client.BrokerPort)
	if err != nil {
		return err
	}
	b.listeners[id.UID], b.ids[id.UID] = l, id
	go b.accept(ctx, l, id)
	return nil
}

// Close stops serving a silo (it's gone from this host).
func (b *Broker) Close(uid string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if l, ok := b.listeners[uid]; ok {
		_ = l.Close()
		delete(b.listeners, uid)
		delete(b.ids, uid)
	}
}

// Notify tells a silo's watchers that something it receives changed (a secret rotated, a grant
// changed): its guest helper reads again.
func (b *Broker) Notify(namespace, name, what string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.watchers[namespace+"/"+name] {
		select {
		case ch <- what:
		default: // one pending event is enough: the helper re-reads everything
		}
	}
}

func (b *Broker) accept(ctx context.Context, l net.Listener, id kri.ID) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go b.serve(ctx, c, id)
	}
}

// serve answers one connection's requests, one JSON line each.
func (b *Broker) serve(ctx context.Context, c net.Conn, id kri.ID) {
	defer func() { _ = c.Close() }()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	enc := json.NewEncoder(c)
	for sc.Scan() {
		var req client.BrokerRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			_ = enc.Encode(client.BrokerResponse{Error: "bad request: one JSON object per line"})
			return
		}
		if !slices.Contains(siloOps, req.Op) {
			_ = enc.Encode(client.BrokerResponse{Error: "unknown op " + req.Op})
			continue
		}
		if req.Op == client.OpWatch {
			b.watch(ctx, c, enc, id)
			return
		}
		var resp client.BrokerResponse
		err := b.Client.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
			Namespace: id.Namespace, Name: id.Name, UID: id.UID, Host: b.HostName, Request: req}, &resp)
		if err != nil {
			b.log("broker %s/%s: %v", id.Namespace, id.Name, err)
			resp = client.BrokerResponse{Error: "the control plane can't be reached; try again"}
		}
		err = enc.Encode(resp)
		clear(resp.Value)
		if err != nil {
			return
		}
	}
}

// watch streams events until the connection or the silo goes.
func (b *Broker) watch(ctx context.Context, c net.Conn, enc *json.Encoder, id kri.ID) {
	key := id.Namespace + "/" + id.Name
	ch := make(chan string, 1)
	b.mu.Lock()
	if b.watchers[key] == nil {
		b.watchers[key] = map[chan string]struct{}{}
	}
	b.watchers[key][ch] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.watchers[key], ch)
		b.mu.Unlock()
	}()
	closed := make(chan struct{})
	go func() { // the guest hanging up ends the watch
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		close(closed)
	}()
	if enc.Encode(client.BrokerResponse{Event: "ready"}) != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case what := <-ch:
			if enc.Encode(client.BrokerResponse{Event: "changed", Secret: what}) != nil {
				return
			}
		}
	}
}

// Affected returns the silos (of those given) that receive something from a changed secret or
// grant: for a secret, every silo with a grant naming it; for a grant, every silo listing it.
// That's the rotation fan-out: one secret, many silos, renewed in one place (design §8.4).
func Affected(silos []*v1.Silo, grants []*v1.Grant, kind, namespace, name string) []*v1.Silo {
	var out []*v1.Silo
	for _, s := range silos {
		if s.Namespace != namespace {
			continue
		}
		switch kind {
		case "Grant":
			if slices.Contains(s.Spec.Grants, name) {
				out = append(out, s)
			}
		case "Secret":
			for _, g := range v1.GrantsFor(s, grants) {
				if slices.Contains(g.SecretNames(), name) {
					out = append(out, s)
					break
				}
			}
		}
	}
	return out
}

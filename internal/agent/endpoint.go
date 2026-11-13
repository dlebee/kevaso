package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// Endpoint is a host's local endpoint for its silos (design §8.2, ADR 0009): plain HTTP at
// http://169.254.42.1 inside every silo on the bridge, for what a silo asks for itself. It relays
// each request to the control plane, which decides; only the transport is here.
//
// Who is asking is where the request arrived: by default its source address, which the agent
// registered for the silo from the runtime's own status (the bridge drops anything a silo sends
// from another address), never anything in the request. A silo whose grants need no endpoint is
// never registered: the firewall drops its packets, and this answers 404 if one gets through.
//
// Every request needs the header Kevaso-Local: 1, and is refused with an Origin or Sec-Fetch-*
// header (a browser made it) or a Host that isn't the endpoint's (DNS rebinding). There are no
// redirects and no CORS headers, ever. The routes, all answering errors as {"error": "…"}:
//
//	GET  /v1/secrets/NAME[?for=D&wait=D&approval=A]          200 the value (application/octet-stream), Kevaso-Version: N
//	POST /v1/sign/KEY[?slot=N&for=D&wait=D&approval=A]       body: the payload (≤ 512 KiB); 200 the signature, hex
//	GET  /v1/keys/KEY                                        200 the public key, hex
//	POST /v1/ports/NAME/open[?for=D&wait=D&approval=A]       200 {"port": NAME, "until": TIME, "clamped": BOOL}
//	POST /v1/ports/NAME/close                                200 {"port": NAME, "closed": true}
//
// A call that needs a person's yes (§8.7) answers 428 {"pending": {"namespace", "name",
// "expiresAt"}, "error": …} (and Kevaso-Approval: NAME): the client asks again with approval=NAME
// until it's answered. A secret or key that isn't the silo's answers 404 exactly like one that
// doesn't exist.
type Endpoint struct {
	Client   *client.Client
	HostName string
	Log      func(string, ...any)
	// Identify says which silo a request came from, from where it arrived only (nil: its source
	// address, as registered).
	Identify func(*http.Request) (kri.ID, bool)
	// Hosts are the Host headers accepted (nil: 169.254.42.1 and 169.254.42.1:80).
	Hosts []string

	mu       sync.Mutex
	byAddr   map[netip.Addr]kri.ID
	inFlight map[string]int // by silo uid
}

// Endpoint limits.
const (
	endpointMaxBody     = 512 << 10
	endpointMaxInFlight = 8
)

// Server is an http.Server for the endpoint, with its limits.
func (e *Endpoint) Server() *http.Server {
	return &http.Server{Handler: e, MaxHeaderBytes: 8 << 10, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
}

// Register says that requests from addr are silo id's (its address on the bridge, from its
// runtime). An address registered for another silo before is now this one's.
func (e *Endpoint) Register(addr netip.Addr, id kri.ID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.byAddr == nil {
		e.byAddr = map[netip.Addr]kri.ID{}
	}
	for a, cur := range e.byAddr {
		if cur.UID == id.UID && a != addr {
			delete(e.byAddr, a)
		}
	}
	e.byAddr[addr] = id
}

// Unregister forgets a silo (it's gone from this host, or needs no endpoint any more).
func (e *Endpoint) Unregister(uid string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for a, cur := range e.byAddr {
		if cur.UID == uid {
			delete(e.byAddr, a)
		}
	}
}

// BySource is the default Identify: the registered silo whose address the request came from.
func (e *Endpoint) BySource(r *http.Request) (kri.ID, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return kri.ID{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	id, ok := e.byAddr[ap.Addr().Unmap()]
	return id, ok
}

func (e *Endpoint) log(f string, a ...any) {
	if e.Log != nil {
		e.Log(f, a...)
	}
}

type endpointError struct {
	Error   string               `json:"error"`
	Pending *client.ApprovalWait `json:"pending,omitempty"`
}

func endpointFail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(endpointError{Error: msg})
}

var endpointName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// ServeHTTP implements http.Handler.
func (e *Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	identify := e.Identify
	if identify == nil {
		identify = e.BySource
	}
	id, ok := identify(r)
	if !ok {
		endpointFail(w, http.StatusNotFound, "no Kevaso endpoint for this address")
		return
	}
	hosts := e.Hosts
	if hosts == nil {
		hosts = []string{v1.EndpointAddress, v1.EndpointAddress + ":" + strconv.Itoa(v1.EndpointPort)}
	}
	switch {
	case r.Method == http.MethodOptions:
		endpointFail(w, http.StatusMethodNotAllowed, "no OPTIONS here (and no CORS)")
		return
	case r.Header.Get(v1.EndpointHeader) != "1":
		endpointFail(w, http.StatusForbidden, "every request needs the header "+v1.EndpointHeader+": 1")
		return
	case len(r.Header.Values("Origin")) > 0 || hasSecFetch(r.Header):
		endpointFail(w, http.StatusForbidden, "requests from a browser are refused")
		return
	case !slices.Contains(hosts, r.Host):
		endpointFail(w, http.StatusForbidden, "Host must be "+v1.EndpointAddress)
		return
	}
	op, name, method, ok := endpointRoute(r.URL.Path)
	if !ok {
		endpointFail(w, http.StatusNotFound, "no such route: "+r.URL.Path)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		endpointFail(w, http.StatusMethodNotAllowed, r.Method+" "+r.URL.Path+": use "+method)
		return
	}
	if !endpointName.MatchString(name) {
		endpointFail(w, http.StatusBadRequest, fmt.Sprintf("name %q: lower-case letters, digits, - and .", name))
		return
	}
	if !e.enter(id.UID) {
		endpointFail(w, http.StatusTooManyRequests, "too many requests at once from this silo")
		return
	}
	defer e.leave(id.UID)
	req := client.BrokerRequest{Op: op, Name: name}
	q := r.URL.Query()
	if op != client.OpPublicKey && op != client.OpPortClose {
		for _, p := range []struct {
			key string
			to  *string
		}{{"for", &req.For}, {"wait", &req.Wait}} {
			if v := q.Get(p.key); v != "" {
				if d, err := time.ParseDuration(v); err != nil || d <= 0 {
					endpointFail(w, http.StatusBadRequest, fmt.Sprintf("%s=%q: a duration such as 30m", p.key, v))
					return
				}
				*p.to = v
			}
		}
		if a := q.Get("approval"); a != "" {
			if !endpointName.MatchString(a) {
				endpointFail(w, http.StatusBadRequest, fmt.Sprintf("approval=%q: an approval's name", a))
				return
			}
			req.Approval = a
		}
	}
	if op == client.OpSign {
		if v := q.Get("slot"); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				endpointFail(w, http.StatusBadRequest, fmt.Sprintf("slot=%q: a number", v))
				return
			}
			req.Slot = &n
		}
		payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, endpointMaxBody))
		if err != nil {
			endpointFail(w, http.StatusRequestEntityTooLarge, "the payload is at most 512 KiB")
			return
		}
		req.Payload = payload
	}
	var resp client.BrokerResponse
	err := e.Client.Call(r.Context(), http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
		Namespace: id.Namespace, Name: id.Name, UID: id.UID, Host: e.HostName, Request: req}, &resp)
	defer clear(resp.Value)
	if err != nil {
		e.log("endpoint %s/%s: %v", id.Namespace, id.Name, err)
		endpointFail(w, http.StatusServiceUnavailable, "the control plane can't be reached; try again")
		return
	}
	e.answer(w, op, name, resp)
}

func hasSecFetch(h http.Header) bool {
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "Sec-Fetch-") {
			return true
		}
	}
	return false
}

// endpointRoute maps a path to its op, the name in it and its method. Exact matches only: no
// cleaning, no trailing slashes, no redirects.
func endpointRoute(path string) (op, name, method string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 3 || parts[0] != "v1" || parts[2] == "" {
		return "", "", "", false
	}
	switch {
	case len(parts) == 3 && parts[1] == "secrets":
		return client.OpGetSecret, parts[2], http.MethodGet, true
	case len(parts) == 3 && parts[1] == "sign":
		return client.OpSign, parts[2], http.MethodPost, true
	case len(parts) == 3 && parts[1] == "keys":
		return client.OpPublicKey, parts[2], http.MethodGet, true
	case len(parts) == 4 && parts[1] == "ports" && parts[3] == "open":
		return client.OpPortOpen, parts[2], http.MethodPost, true
	case len(parts) == 4 && parts[1] == "ports" && parts[3] == "close":
		return client.OpPortClose, parts[2], http.MethodPost, true
	}
	return "", "", "", false
}

// answer writes the control plane's answer as the route's.
func (e *Endpoint) answer(w http.ResponseWriter, op, name string, resp client.BrokerResponse) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if resp.Pending != nil {
		p := resp.Pending
		h.Set("Content-Type", "application/json")
		h.Set("Kevaso-Approval", p.Name)
		w.WriteHeader(http.StatusPreconditionRequired)
		_ = json.NewEncoder(w).Encode(endpointError{Pending: p,
			Error: fmt.Sprintf("waiting for a person's yes: kvo approve %s -n %s (ask again with approval=%s)", p.Name, p.Namespace, p.Name)})
		return
	}
	if resp.Error != "" {
		status := http.StatusForbidden
		switch resp.Code {
		case client.CodeNotFound:
			status = http.StatusNotFound
		case client.CodeConflict:
			status = http.StatusConflict
		}
		endpointFail(w, status, resp.Error)
		return
	}
	switch op {
	case client.OpGetSecret:
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Kevaso-Version", strconv.FormatInt(resp.Version, 10))
		h.Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp.Value)
	case client.OpSign:
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, hex.EncodeToString(resp.Signature)+"\n")
	case client.OpPublicKey:
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, resp.PublicKey+"\n")
	case client.OpPortOpen:
		if resp.Until == nil {
			endpointFail(w, http.StatusBadGateway, "port "+name+": no end time in the control plane's answer")
			return
		}
		h.Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PortOpened{Port: name, Until: *resp.Until, Clamped: resp.Clamped})
	case client.OpPortClose:
		h.Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(PortClosed{Port: name, Closed: true})
	}
}

// PortOpened is the answer to POST /v1/ports/NAME/open. Clamped: the time asked was more than the
// lease's max, so it's open for the max.
type PortOpened struct {
	Port    string    `json:"port"`
	Until   time.Time `json:"until"`
	Clamped bool      `json:"clamped"`
}

// PortClosed is the answer to POST /v1/ports/NAME/close.
type PortClosed struct {
	Port   string `json:"port"`
	Closed bool   `json:"closed"`
}

func (e *Endpoint) enter(uid string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inFlight == nil {
		e.inFlight = map[string]int{}
	}
	if e.inFlight[uid] >= endpointMaxInFlight {
		return false
	}
	e.inFlight[uid]++
	return true
}

func (e *Endpoint) leave(uid string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inFlight[uid]--; e.inFlight[uid] <= 0 {
		delete(e.inFlight, uid)
	}
}

// ServeEndpoint serves the endpoint on addr until ctx ends, trying again while the address isn't
// there yet (the network side puts it on the bridge once the bridge exists).
func (e *Endpoint) ServeEndpoint(ctx context.Context, addr string) {
	srv := e.Server()
	go func() { <-ctx.Done(); _ = srv.Close() }()
	for ctx.Err() == nil {
		var lc net.ListenConfig
		l, err := lc.Listen(ctx, "tcp4", addr)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}
		e.log("local endpoint for silos on %s", addr)
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			e.log("local endpoint: %v", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
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

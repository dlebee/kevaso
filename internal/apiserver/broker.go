package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/audit"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
)

// The broker's decisions (design §8.2), on the control plane. A host relays what one of its silos
// asked, and the silo's identity is what the host's channel said (the per-silo vsock listener), never
// the silo's own words. The control plane then checks:
//   - the host is the silo's host (a host only ever gets secrets for silos placed on it);
//   - one of the silo's grants gives it that secret, that way, and the secret allows it;
//   - the grant's required assurance is one the silo has (host only, for now).
//
// Anything refused answers like a name that doesn't exist, so a silo can't probe for secrets.
// Every call is audited, allowed or not.

// errNoSecret is the one answer for "doesn't exist", "not yours" and "not that way".
func errNoSecret(name string) error { return fmt.Errorf("no secret %q for this silo", name) }

type brokerCall struct {
	silo   *v1.Silo
	grants []*v1.Grant
}

func (s *Server) agentBroker(w http.ResponseWriter, r *http.Request) {
	id, ok := IdentityFrom(r.Context())
	if s.auth == nil { // kevasod dev: no authentication, it's all one process
		id, ok = Component, true
	}
	if !ok || (id.Type != "host" && id != Component) || r.Method != http.MethodPost {
		writeErr(w, errf(http.StatusForbidden, "Forbidden", "only hosts relay broker requests"))
		return
	}
	if s.vault == nil {
		writeErr(w, errf(http.StatusServiceUnavailable, "Unavailable", "this server has no KMS"))
		return
	}
	var req client.AgentBrokerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "broker request: %v", err))
		return
	}
	host := id.Name
	if id == Component {
		host = req.Host
	}
	ctx := r.Context()
	resp, reason, allowed := s.broker(ctx, host, req)
	if s.auth != nil && s.auth.Audit != nil {
		s.auth.Audit.Record(audit.Entry{
			Time: s.clock.Now(), Event: "broker", User: "system:silo:" + req.Namespace + ":" + req.Name, Type: "silo",
			Verb: req.Request.Op, Resource: "secrets", Namespace: req.Namespace, Name: req.Request.Name,
			Allowed: allowed, Reason: reason + " (via host " + host + ")",
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// broker decides and answers one request; the reason is for the audit log only.
func (s *Server) broker(ctx context.Context, host string, req client.AgentBrokerRequest) (client.BrokerResponse, string, bool) {
	call, err := s.brokerSilo(ctx, host, req)
	if err != nil {
		return client.BrokerResponse{Error: "this silo has no access to the broker"}, err.Error(), false
	}
	op := req.Request
	refuse := func(why string) (client.BrokerResponse, string, bool) {
		return client.BrokerResponse{Error: errNoSecret(op.Name).Error()}, why, false
	}
	switch op.Op {
	case client.OpGetSecret:
		sec, g, mode, why := s.grantedSecret(ctx, call, op.Name, v1.DeliverBroker, v1.DeliverFile, v1.DeliverEnv)
		if sec == nil {
			return refuse(why)
		}
		value, ver, err := s.vault.Value(ctx, sec)
		if err != nil {
			return refuse(err.Error())
		}
		return client.BrokerResponse{Value: value, Version: ver}, fmt.Sprintf("grant %s, %s", g.Name, mode), true
	case client.OpSign, client.OpPublicKey:
		sec, g, protection, why := s.grantedKey(ctx, call, op.Name)
		if sec == nil {
			return refuse(why)
		}
		if op.Op == client.OpPublicKey {
			return client.BrokerResponse{PublicKey: sec.Status.PublicKey, Version: sec.Status.Version}, "grant " + g.Name, true
		}
		sig, err := s.vault.Sign(ctx, sec, secrets.SignRequest{Payload: op.Payload, Slot: op.Slot, Protection: protection})
		if errors.Is(err, secrets.ErrSlashing) {
			return client.BrokerResponse{Error: err.Error()}, err.Error(), false
		}
		if err != nil {
			return refuse(err.Error())
		}
		return client.BrokerResponse{Signature: sig}, "grant " + g.Name + ", sign", true
	case client.OpDeliveries:
		var out []client.Delivery
		for _, g := range call.grants {
			if !assured(g) {
				continue
			}
			for _, gs := range g.Spec.Secrets {
				mode := gs.Delivery()
				if mode != v1.DeliverFile && mode != v1.DeliverEnv {
					continue
				}
				sec := s.secretNamed(ctx, call.silo.Namespace, gs.Name)
				if sec == nil || !sec.Allows(mode) || sec.Status.Version == 0 {
					continue
				}
				d := client.Delivery{Name: gs.Name, Mode: mode, Version: sec.Status.Version}
				if mode == v1.DeliverFile {
					d.Path = gs.Path
					if d.Path == "" {
						d.Path = "/run/secrets/" + gs.Name
					}
				} else {
					d.Env = gs.Env
					if d.Env == "" {
						d.Env = strings.ToUpper(strings.ReplaceAll(gs.Name, "-", "_"))
					}
				}
				out = append(out, d)
			}
		}
		return client.BrokerResponse{Deliveries: out}, fmt.Sprintf("%d file/env deliveries", len(out)), true
	case client.OpIngress:
		cfg, n, err := s.ingressConfig(ctx, call.silo)
		if err != nil {
			return client.BrokerResponse{Error: err.Error()}, err.Error(), false
		}
		return client.BrokerResponse{Ingress: cfg}, fmt.Sprintf("ingress controller for %d classes: %d routes, %d certificates", n, len(cfg.Routes), len(cfg.Certs)), true
	case client.OpInjections:
		var out []client.Injection
		for _, g := range call.grants {
			if !assured(g) {
				continue
			}
			for _, gs := range g.Spec.Secrets {
				if gs.Delivery() != v1.DeliverInject || gs.To == nil {
					continue
				}
				sec := s.secretNamed(ctx, call.silo.Namespace, gs.Name)
				if sec == nil || !sec.Allows(v1.DeliverInject) {
					continue
				}
				value, ver, err := s.vault.Value(ctx, sec)
				if err != nil {
					continue
				}
				header, format := gs.To.Header, gs.To.Format
				if header == "" {
					header = "Authorization"
				}
				if format == "" {
					format = "Bearer {{value}}"
				}
				env := gs.Env
				if env == "" {
					env = strings.ToUpper(strings.ReplaceAll(gs.Name, "-", "_"))
				}
				out = append(out, client.Injection{Host: strings.ToLower(gs.To.Host), Header: header,
					Value: strings.Replace(format, "{{value}}", string(value), 1), Raw: value, Format: format,
					Env: env, Secret: gs.Name, Version: ver})
			}
		}
		return client.BrokerResponse{Injections: out}, fmt.Sprintf("%d injections for the egress gate", len(out)), true
	}
	return client.BrokerResponse{Error: "unknown op " + op.Op}, "unknown op", false
}

// brokerSilo finds the silo and checks it's on the asking host.
func (s *Server) brokerSilo(ctx context.Context, host string, req client.AgentBrokerRequest) (*brokerCall, error) {
	o, err := s.store.Get(ctx, store.Key{Kind: "Silo", Namespace: req.Namespace, Name: req.Name})
	if err != nil {
		return nil, fmt.Errorf("silo %s/%s: %w", req.Namespace, req.Name, err)
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return nil, err
	}
	silo := obj.(*v1.Silo)
	switch {
	case silo.UID != req.UID:
		return nil, fmt.Errorf("silo %s/%s is another one now (uid %s, asked for %s)", req.Namespace, req.Name, silo.UID, req.UID)
	case host == "" || silo.Status.Host != host:
		return nil, fmt.Errorf("silo %s/%s isn't placed on host %q", req.Namespace, req.Name, host)
	case silo.DeletionTimestamp != nil:
		return nil, fmt.Errorf("silo %s/%s is being deleted", req.Namespace, req.Name)
	}
	call := &brokerCall{silo: silo}
	for _, name := range silo.Spec.Grants {
		stored, err := s.store.Get(ctx, store.Key{Kind: "Grant", Namespace: silo.Namespace, Name: name})
		if err != nil {
			continue
		}
		if g, _, err := v1.Decode(stored.Data); err == nil {
			call.grants = append(call.grants, g.(*v1.Grant))
		}
	}
	return call, nil
}

// assured: a grant asking for vtpm or confidential can't be met yet (every silo is "host").
func assured(g *v1.Grant) bool {
	return g.Spec.Requires == nil || g.Spec.Requires.Assurance == "" || g.Spec.Requires.Assurance == v1.AssuranceHost
}

func (s *Server) secretNamed(ctx context.Context, ns, name string) *v1.Secret {
	o, err := s.store.Get(ctx, store.Key{Kind: "Secret", Namespace: ns, Name: name})
	if err != nil {
		return nil
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return nil
	}
	return obj.(*v1.Secret)
}

// grantedSecret finds a grant giving the silo secret name in one of modes.
func (s *Server) grantedSecret(ctx context.Context, call *brokerCall, name string, modes ...string) (*v1.Secret, *v1.Grant, string, string) {
	why := "no grant of the silo gives it this secret that way"
	for _, g := range call.grants {
		for _, gs := range g.Spec.Secrets {
			mode := gs.Delivery()
			if gs.Name != name || !contains(modes, mode) {
				continue
			}
			if !assured(g) {
				why = "grant " + g.Name + " needs " + g.Spec.Requires.Assurance + " assurance; the silo has host"
				continue
			}
			sec := s.secretNamed(ctx, call.silo.Namespace, name)
			if sec == nil {
				return nil, nil, "", "the secret doesn't exist"
			}
			if !sec.Allows(mode) {
				why = "the secret doesn't allow delivery " + mode
				continue
			}
			return sec, g, mode, ""
		}
	}
	return nil, nil, "", why
}

// grantedKey finds a grant letting the silo sign with key name.
func (s *Server) grantedKey(ctx context.Context, call *brokerCall, name string) (*v1.Secret, *v1.Grant, bool, string) {
	why := "no grant of the silo lets it sign with this key"
	for _, g := range call.grants {
		op := g.Spec.Operations
		if op == nil || op.Sign == nil || op.Sign.KeyRef != name {
			continue
		}
		if !assured(g) {
			why = "grant " + g.Name + " needs " + g.Spec.Requires.Assurance + " assurance; the silo has host"
			continue
		}
		sec := s.secretNamed(ctx, call.silo.Namespace, name)
		if sec == nil || !sec.Allows(v1.DeliverSign) {
			return nil, nil, false, "not a signing key"
		}
		return sec, g, op.Sign.SlashingProtection, ""
	}
	return nil, nil, false, why
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

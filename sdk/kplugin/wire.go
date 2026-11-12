package kplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// The wire: POST /v1/OPERATION with the request as JSON, the answer as JSON (200), or
// {"error": "...", "code": "InProgress|NotFound|Unsupported|Conflict"} with a 4xx/5xx.

type wireError struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

var codes = map[string]error{"InProgress": ErrInProgress, "NotFound": ErrNotFound, "Unsupported": ErrUnsupported, "Conflict": ErrConflict}

func codeOf(err error) (string, int) {
	for c, e := range codes {
		if errors.Is(err, e) {
			if c == "InProgress" {
				return c, http.StatusAccepted
			}
			return c, http.StatusConflict
		}
	}
	return "", http.StatusInternalServerError
}

// Handler serves p over HTTP (the operations it implements; others answer Unsupported).
func Handler(p Plugin) http.Handler {
	mux := http.NewServeMux()
	handle := func(op string, fn func(ctx context.Context, body []byte) (any, error)) {
		mux.HandleFunc("POST /v1/"+op, func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			out, err := fn(r.Context(), body)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				code, status := codeOf(err)
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(wireError{Error: err.Error(), Code: code})
				return
			}
			if out == nil {
				out = struct{}{}
			}
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	call := func(op string, fn func(ctx context.Context, in json.RawMessage) (any, error)) {
		handle(op, func(ctx context.Context, b []byte) (any, error) { return fn(ctx, b) })
	}
	call("info", func(ctx context.Context, _ json.RawMessage) (any, error) {
		i, err := p.Info(ctx)
		i.Protocol = Protocol
		return i, err
	})
	hd, _ := p.(HostDescriber)
	call("hosts/describe", func(ctx context.Context, b json.RawMessage) (any, error) {
		if hd == nil {
			return nil, ErrUnsupported
		}
		var in []Host
		if err := json.Unmarshal(b, &in); err != nil {
			return nil, err
		}
		return hd.DescribeHosts(ctx, in)
	})
	lbs, _ := p.(LoadBalancers)
	call("loadbalancers/ensure", func(ctx context.Context, b json.RawMessage) (any, error) {
		var in LoadBalancer
		if lbs == nil {
			return nil, ErrUnsupported
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return nil, err
		}
		return lbs.EnsureLoadBalancer(ctx, in)
	})
	call("loadbalancers/delete", func(ctx context.Context, b json.RawMessage) (any, error) {
		var in LoadBalancerRef
		if lbs == nil {
			return nil, ErrUnsupported
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return nil, err
		}
		return nil, lbs.DeleteLoadBalancer(ctx, in)
	})
	vols, _ := p.(Volumes)
	call("volumes/ensure", func(ctx context.Context, b json.RawMessage) (any, error) {
		var in Volume
		if vols == nil {
			return nil, ErrUnsupported
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return nil, err
		}
		return vols.EnsureVolume(ctx, in)
	})
	call("volumes/attach", func(ctx context.Context, b json.RawMessage) (any, error) {
		var in Attachment
		if vols == nil {
			return nil, ErrUnsupported
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return nil, err
		}
		return vols.AttachVolume(ctx, in)
	})
	call("volumes/detach", func(ctx context.Context, b json.RawMessage) (any, error) {
		var in Attachment
		if vols == nil {
			return nil, ErrUnsupported
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return nil, err
		}
		return nil, vols.DetachVolume(ctx, in)
	})
	call("volumes/delete", func(ctx context.Context, b json.RawMessage) (any, error) {
		var in VolumeRef
		if vols == nil {
			return nil, ErrUnsupported
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return nil, err
		}
		return nil, vols.DeleteVolume(ctx, in)
	})
	dns, _ := p.(DNS)
	call("dns/ensure", func(ctx context.Context, b json.RawMessage) (any, error) {
		var in Record
		if dns == nil {
			return nil, ErrUnsupported
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return nil, err
		}
		return nil, dns.EnsureRecord(ctx, in)
	})
	call("dns/delete", func(ctx context.Context, b json.RawMessage) (any, error) {
		var in Record
		if dns == nil {
			return nil, ErrUnsupported
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return nil, err
		}
		return nil, dns.DeleteRecord(ctx, in)
	})
	return mux
}

// Serve serves p on the unix socket at path (replacing a stale one) until ctx ends. The socket is
// 0660: the control plane runs as root; nobody else needs it.
func Serve(ctx context.Context, path string, p Plugin) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = l.Close()
		return err
	}
	srv := &http.Server{Handler: Handler(p), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Client calls a plugin. It implements every interface; calls a plugin doesn't serve return
// ErrUnsupported.
type Client struct {
	Socket string // unix socket path
	HTTP   *http.Client
}

// Dial returns a client for the plugin at socket.
func Dial(socket string) *Client {
	return &Client{Socket: socket, HTTP: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}}
}

func (c *Client) call(ctx context.Context, op string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://plugin/v1/"+op, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var we wireError
		if json.Unmarshal(body, &we) != nil || we.Error == "" {
			return fmt.Errorf("plugin %s: HTTP %d: %s", op, resp.StatusCode, bytes.TrimSpace(body))
		}
		if e, ok := codes[we.Code]; ok {
			if we.Error == e.Error() {
				return e
			}
			return fmt.Errorf("%s: %w", trimSuffix(we.Error, ": "+e.Error()), e)
		}
		return errors.New(we.Error)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func trimSuffix(s, suf string) string {
	if len(s) >= len(suf) && s[len(s)-len(suf):] == suf {
		return s[:len(s)-len(suf)]
	}
	return s
}

// Info implements Plugin.
func (c *Client) Info(ctx context.Context) (Info, error) {
	var i Info
	err := c.call(ctx, "info", struct{}{}, &i)
	return i, err
}

// DescribeHosts implements HostDescriber.
func (c *Client) DescribeHosts(ctx context.Context, hosts []Host) ([]HostInfo, error) {
	var out []HostInfo
	err := c.call(ctx, "hosts/describe", hosts, &out)
	return out, err
}

// EnsureLoadBalancer implements LoadBalancers.
func (c *Client) EnsureLoadBalancer(ctx context.Context, lb LoadBalancer) (LoadBalancerStatus, error) {
	var out LoadBalancerStatus
	err := c.call(ctx, "loadbalancers/ensure", lb, &out)
	return out, err
}

// DeleteLoadBalancer implements LoadBalancers.
func (c *Client) DeleteLoadBalancer(ctx context.Context, ref LoadBalancerRef) error {
	return c.call(ctx, "loadbalancers/delete", ref, nil)
}

// EnsureVolume implements Volumes.
func (c *Client) EnsureVolume(ctx context.Context, v Volume) (VolumeStatus, error) {
	var out VolumeStatus
	err := c.call(ctx, "volumes/ensure", v, &out)
	return out, err
}

// AttachVolume implements Volumes.
func (c *Client) AttachVolume(ctx context.Context, a Attachment) (AttachmentStatus, error) {
	var out AttachmentStatus
	err := c.call(ctx, "volumes/attach", a, &out)
	return out, err
}

// DetachVolume implements Volumes.
func (c *Client) DetachVolume(ctx context.Context, a Attachment) error {
	return c.call(ctx, "volumes/detach", a, nil)
}

// DeleteVolume implements Volumes.
func (c *Client) DeleteVolume(ctx context.Context, ref VolumeRef) error {
	return c.call(ctx, "volumes/delete", ref, nil)
}

// EnsureRecord implements DNS.
func (c *Client) EnsureRecord(ctx context.Context, r Record) error {
	return c.call(ctx, "dns/ensure", r, nil)
}

// DeleteRecord implements DNS.
func (c *Client) DeleteRecord(ctx context.Context, r Record) error {
	return c.call(ctx, "dns/delete", r, nil)
}

var (
	_ Plugin        = (*Client)(nil)
	_ HostDescriber = (*Client)(nil)
	_ LoadBalancers = (*Client)(nil)
	_ Volumes       = (*Client)(nil)
	_ DNS           = (*Client)(nil)
)

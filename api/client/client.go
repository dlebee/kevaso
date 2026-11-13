// Package client talks to the Kevaso API: get, list, create, update (spec or status), delete and
// watch, for any kind. `kvo`, controllers and plugins all use it.
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Client is an API client. The zero HTTP uses http.DefaultClient.
type Client struct {
	BaseURL string // e.g. http://127.0.0.1:6443
	HTTP    *http.Client
	// Token, if set, gives the bearer token for each request (kvo login's access token, refreshed
	// as needed).
	Token func(ctx context.Context) (string, error)

	kindsMu sync.Mutex
	kinds   []v1.APIResource // what the server serves, once asked (kinds.go)
}

// send adds credentials and sends a request.
func (c *Client) send(hc *http.Client, req *http.Request) (*http.Response, error) {
	if c.Token != nil {
		tok, err := c.Token(req.Context())
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return hc.Do(req)
}

// New returns a client for the server at baseURL.
func New(baseURL string) *Client { return &Client{BaseURL: strings.TrimRight(baseURL, "/")} }

// Error is an API error.
type Error struct {
	Code    int    `json:"code"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("%s (%d): %s", e.Reason, e.Code, e.Message) }

func reasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool { return reasonOf(err) == "NotFound" }

// IgnoreNotFound is nil for a NotFound error, err otherwise.
func IgnoreNotFound(err error) error {
	if IsNotFound(err) {
		return nil
	}
	return err
}

// IsConflict reports a stale resourceVersion: re-read and try again.
func IsConflict(err error) bool { return reasonOf(err) == "Conflict" }

// IsAlreadyExists reports a create on an existing name.
func IsAlreadyExists(err error) bool { return reasonOf(err) == "AlreadyExists" }

// IsInvalid reports a refused object (schema or validation rules).
func IsInvalid(err error) bool { return reasonOf(err) == "Invalid" }

// Path returns the API path for a kind, namespace and optional name.
func Path(kind, namespace, name string) (string, error) {
	k, ok := v1.Lookup(kind)
	if !ok {
		return "", fmt.Errorf("unknown kind %q", kind)
	}
	p := "/apis/kevaso/v1/"
	if k.Scope == v1.Namespaced && namespace != "" {
		p += "namespaces/" + url.PathEscape(namespace) + "/"
	}
	p += k.Plural
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p, nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) do(ctx context.Context, method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.send(c.http(), req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		e := &Error{Code: resp.StatusCode}
		if json.Unmarshal(data, e) != nil || e.Reason == "" {
			e.Reason, e.Message = http.StatusText(resp.StatusCode), strings.TrimSpace(string(data))
		}
		return e
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Raw sends a request without a body and returns the answer's body as it is (a pane's bundle:
// never decoded).
func (c *Client) Raw(ctx context.Context, method, path string) ([]byte, error) {
	b, _, err := c.Fetch(ctx, method, path)
	return b, err
}

// Fetch is Raw with the response headers.
func (c *Client) Fetch(ctx context.Context, method, path string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.send(c.http(), req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 300 {
		e := &Error{Code: resp.StatusCode}
		if json.Unmarshal(data, e) != nil || e.Reason == "" {
			e.Reason, e.Message = http.StatusText(resp.StatusCode), strings.TrimSpace(string(data))
		}
		return nil, nil, e
	}
	return data, resp.Header, nil
}

// Get reads one object into out (a pointer to the kind's type).
func (c *Client) Get(ctx context.Context, kind, namespace, name string, out meta.Object) error {
	p, err := c.pathFor(ctx, kind, namespace, name)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodGet, p, nil, out)
}

// List is a list response: raw items (decode with v1.Decode) and the revision to watch from.
type List struct {
	Items    []json.RawMessage `json:"items"`
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
}

// List lists a kind, in one namespace or (namespace "") in all of them.
func (c *Client) List(ctx context.Context, kind, namespace string) (*List, error) {
	p, err := c.pathFor(ctx, kind, namespace, "")
	if err != nil {
		return nil, err
	}
	var l List
	return &l, c.do(ctx, http.MethodGet, p, nil, &l)
}

// Create creates obj and updates it in place with what the server stored.
func (c *Client) Create(ctx context.Context, obj meta.Object) error {
	p, err := c.objPathFor(ctx, obj, "", false)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, p, obj, obj)
}

// Update replaces obj's spec and metadata; obj must carry the resourceVersion it was read at.
func (c *Client) Update(ctx context.Context, obj meta.Object) error {
	p, err := c.objPathFor(ctx, obj, obj.GetObjectMeta().Name, false)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPut, p, obj, obj)
}

// UpdateStatus replaces only obj's status (what controllers write).
func (c *Client) UpdateStatus(ctx context.Context, obj meta.Object) error {
	p, err := c.objPathFor(ctx, obj, obj.GetObjectMeta().Name, true)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPut, p, obj, obj)
}

// Delete deletes an object (or starts deleting it, while it has finalizers).
func (c *Client) Delete(ctx context.Context, kind, namespace, name string) error {
	p, err := c.pathFor(ctx, kind, namespace, name)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, p, nil, nil)
}

// Event is one watch event; decode Object with v1.Decode.
type Event struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// Watch streams events for a kind after resourceVersion (from a List). The channel closes when ctx
// ends or the server ends the stream; a 410 error means re-list.
func (c *Client) Watch(ctx context.Context, kind, namespace, resourceVersion string) (<-chan Event, error) {
	p, err := c.pathFor(ctx, kind, namespace, "")
	if err != nil {
		return nil, err
	}
	q := url.Values{"watch": {"true"}}
	if resourceVersion != "" {
		q.Set("resourceVersion", resourceVersion)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+p+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.send(c.http(), req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		e := &Error{Code: resp.StatusCode}
		_ = json.Unmarshal(data, e)
		return nil, e
	}
	ch := make(chan Event)
	go func() {
		defer close(ch)
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64<<10), 8<<20)
		for sc.Scan() {
			var ev Event
			if json.Unmarshal(sc.Bytes(), &ev) != nil {
				return
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// Call sends any JSON request (for endpoints outside the object API: /admin/…, /auth/…).
func (c *Client) Call(ctx context.Context, method, path string, in, out any) error {
	return c.do(ctx, method, path, in, out)
}

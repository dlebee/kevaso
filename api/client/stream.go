package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Frame types on an exec stream. Every leg (kvo ↔ API server ↔ agent) speaks the same frames, so
// the API server only relays bytes.
const (
	FrameStdin      byte = 1
	FrameStdout     byte = 2
	FrameStderr     byte = 3
	FrameStdinClose byte = 4 // no more stdin (streams can't half-close)
	FrameExit       byte = 5 // payload: exit code, int32 big-endian
	FrameError      byte = 6 // payload: message
)

// MaxFrame is the largest payload in one frame.
const MaxFrame = 64 << 10

// WriteFrame writes one frame: type, length, payload.
func WriteFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > MaxFrame {
		return fmt.Errorf("frame of %d bytes is over the %d limit", len(payload), MaxFrame)
	}
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(append(hdr, payload...)); err != nil {
		return err
	}
	return nil
}

// ReadFrame reads one frame.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > MaxFrame {
		return 0, nil, fmt.Errorf("frame of %d bytes is over the %d limit", n, MaxFrame)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return hdr[0], p, nil
}

// FrameWriter writes everything as frames of one type (for stdout/stderr). Safe for concurrent use
// with other FrameWriters sharing the same mutex.
type FrameWriter struct {
	W   io.Writer
	Typ byte
	Mu  *sync.Mutex
}

func (f FrameWriter) Write(p []byte) (int, error) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	for off := 0; off < len(p); off += MaxFrame {
		end := min(off+MaxFrame, len(p))
		if err := WriteFrame(f.W, f.Typ, p[off:end]); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

// ExecRequest is what a client asks the API server to run.
type ExecRequest struct {
	Command []string `json:"command"`
	TTY     bool     `json:"tty,omitempty"` // on a terminal of Rows x Cols (FrameResize changes it)
	Rows    uint16   `json:"rows,omitempty"`
	Cols    uint16   `json:"cols,omitempty"`
}

// ExecHeader is the first line (JSON) on an exec stream from the API server to a host's agent.
type ExecHeader struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	UID       string   `json:"uid"`
	Runtime   string   `json:"runtime"`
	Command   []string `json:"command"`
	TTY       bool     `json:"tty,omitempty"`
	Rows      uint16   `json:"rows,omitempty"`
	Cols      uint16   `json:"cols,omitempty"`
}

// upgradeClient returns an HTTP client that can do HTTP/1.1 upgrades (HTTP/2 can't hijack).
func (c *Client) upgradeClient() *http.Client {
	base := c.http()
	t, ok := base.Transport.(*http.Transport)
	if !ok || t == nil {
		t = http.DefaultTransport.(*http.Transport)
	}
	u := t.Clone()
	u.ForceAttemptHTTP2 = false
	u.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if u.TLSClientConfig != nil {
		u.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
	return &http.Client{Transport: u}
}

// Upgrade sends a request asking to switch to a raw stream and returns that stream.
func (c *Client) Upgrade(ctx context.Context, method, path, proto string, body any) (io.ReadWriteCloser, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", proto)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.send(c.upgradeClient(), req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		e := &Error{Code: resp.StatusCode}
		if json.Unmarshal(data, e) != nil || e.Reason == "" {
			e.Reason, e.Message = http.StatusText(resp.StatusCode), string(data)
		}
		return nil, e
	}
	rw, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		_ = resp.Body.Close()
		return nil, errors.New("server switched protocols but the stream isn't writable")
	}
	return rw, nil
}

// Exec runs a command in a silo and returns its exit code. stdin may be nil.
func (c *Client) Exec(ctx context.Context, namespace, name string, command []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	s, err := c.OpenExec(ctx, namespace, name, ExecRequest{Command: command})
	if err != nil {
		return -1, err
	}
	defer func() { _ = s.Close() }()
	go s.SendStdin(stdin)
	return s.Wait(stdout, stderr)
}

// ReadOutput reads output frames until the exit code (or an error frame).
func ReadOutput(r io.Reader, stdout, stderr io.Writer) (int, error) {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	for {
		typ, p, err := ReadFrame(r)
		if err != nil {
			return -1, fmt.Errorf("exec stream ended without an exit code: %w", err)
		}
		switch typ {
		case FrameStdout:
			_, _ = stdout.Write(p)
		case FrameStderr:
			_, _ = stderr.Write(p)
		case FrameExit:
			if len(p) != 4 {
				return -1, errors.New("bad exit frame")
			}
			return int(int32(binary.BigEndian.Uint32(p))), nil
		case FrameError:
			return -1, errors.New(string(p))
		}
	}
}

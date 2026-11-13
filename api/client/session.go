package client

import (
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/url"
	"sync"
)

// FrameResize changes a terminal's size: payload rows, cols, each uint16 big-endian.
const FrameResize byte = 7

// ResizePayload is a FrameResize's payload.
func ResizePayload(rows, cols uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, rows)
	binary.BigEndian.PutUint16(b[2:], cols)
	return b
}

// ParseResize reads a FrameResize's payload.
func ParseResize(p []byte) (rows, cols uint16, ok bool) {
	if len(p) != 4 {
		return 0, 0, false
	}
	rows, cols = binary.BigEndian.Uint16(p), binary.BigEndian.Uint16(p[2:])
	return rows, cols, rows > 0 && cols > 0
}

// File operations on a silo (POST …/silos/NAME/files for write, GET for the others). They run tar
// and ls inside the silo through its runtime's exec; nothing is installed in it.
const (
	FileRead  = "read"  // stdout: a tar of PATH (a file or a folder), its entry named ./BASE
	FileWrite = "write" // stdin: a tar unpacked into the folder PATH
	FileList  = "list"  // stdout: `ls -lAn` of the folder PATH
	FileStat  = "stat"  // stdout: `ls -ldn` of PATH
)

// MaxFileTransfer is the most one file stream carries each way through the API server.
const MaxFileTransfer = 4 << 30

// Session is one open exec stream: stdin, terminal size and output frames.
type Session struct {
	s    io.ReadWriteCloser
	mu   sync.Mutex // one frame at a time
	stop func() bool
}

// OpenExec starts a command in a silo (with req.TTY, on a terminal).
func (c *Client) OpenExec(ctx context.Context, namespace, name string, req ExecRequest) (*Session, error) {
	return c.open(ctx, http.MethodPost, namespace, name, "/exec", req)
}

// OpenShell starts a login shell in a silo on a terminal of rows x cols (`kvo ssh`; RBAC: create
// silos/ssh).
func (c *Client) OpenShell(ctx context.Context, namespace, name string, rows, cols uint16) (*Session, error) {
	return c.open(ctx, http.MethodPost, namespace, name, "/ssh", ExecRequest{TTY: true, Rows: rows, Cols: cols})
}

// OpenFiles starts a file operation (FileRead…) on path, an absolute path in the silo (RBAC: get
// silos/files to read, create silos/files to write).
func (c *Client) OpenFiles(ctx context.Context, namespace, name, op, path string) (*Session, error) {
	method := http.MethodGet
	if op == FileWrite {
		method = http.MethodPost
	}
	q := url.Values{"op": {op}, "path": {path}}
	return c.open(ctx, method, namespace, name, "/files?"+q.Encode(), nil)
}

func (c *Client) open(ctx context.Context, method, namespace, name, sub string, body any) (*Session, error) {
	p, err := Path("Silo", namespace, name)
	if err != nil {
		return nil, err
	}
	s, err := c.Upgrade(ctx, method, p+sub, "kevaso-exec", body)
	if err != nil {
		return nil, err
	}
	return &Session{s: s, stop: context.AfterFunc(ctx, func() { _ = s.Close() })}, nil
}

// Write sends stdin.
func (s *Session) Write(p []byte) (int, error) {
	return FrameWriter{W: s.s, Typ: FrameStdin, Mu: &s.mu}.Write(p)
}

// CloseStdin says there's no more stdin.
func (s *Session) CloseStdin() error { return s.frame(FrameStdinClose, nil) }

// SendStdin copies r (nil: nothing) as stdin, then closes it.
func (s *Session) SendStdin(r io.Reader) {
	if r != nil {
		_, _ = io.Copy(s, r)
	}
	_ = s.CloseStdin()
}

// Resize changes the terminal's size.
func (s *Session) Resize(rows, cols uint16) error {
	return s.frame(FrameResize, ResizePayload(rows, cols))
}

func (s *Session) frame(typ byte, p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return WriteFrame(s.s, typ, p)
}

// Wait copies output until the command exits, and returns its exit code.
func (s *Session) Wait(stdout, stderr io.Writer) (int, error) { return ReadOutput(s.s, stdout, stderr) }

// Close ends the stream: a command still running is stopped in the silo.
func (s *Session) Close() error {
	s.stop()
	return s.s.Close()
}

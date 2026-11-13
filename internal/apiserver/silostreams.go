package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"

	"kevaso.com/core/api/client"
)

// A silo's terminal and files, on the same exec stream as `kvo exec` (design §10, `kvo ui`). The
// API server picks the command, so neither needs silos/exec:
//
//	POST …/silos/NAME/ssh                  (Upgrade: kevaso-exec)  a login shell on a terminal; create silos/ssh
//	GET  …/silos/NAME/files?op=read|list|stat&path=P              get silos/files
//	POST …/silos/NAME/files?op=write&path=DIR                     create silos/files
//
// Files go through tar and ls in the silo (nothing is installed in it); the client packs and
// unpacks. Each way carries at most client.MaxFileTransfer.

// LoginShell is what `kvo ssh` runs: bash as a login shell if the image has it, else sh.
var LoginShell = []string{"/bin/sh", "-c",
	`if [ -z "$TERM" ] || [ "$TERM" = dumb ]; then export TERM=xterm-256color; fi; ` +
		`if command -v bash >/dev/null 2>&1; then exec bash -l; fi; exec sh -l`}

func (s *Server) siloSSH(w http.ResponseWriter, r *http.Request, ns, name string) {
	if r.Method != http.MethodPost || !strings.EqualFold(r.Header.Get("Upgrade"), "kevaso-exec") {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "want POST with Upgrade: kevaso-exec"))
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var req client.ExecRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, errf(http.StatusBadRequest, "BadRequest", "body: want {\"rows\": R, \"cols\": C}"))
			return
		}
	}
	if len(req.Command) > 0 {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "ssh runs a login shell; run a command with exec"))
		return
	}
	s.siloStream(w, r, ns, name, client.ExecHeader{Command: LoginShell, TTY: true, Rows: req.Rows, Cols: req.Cols}, 0)
}

func (s *Server) siloFiles(w http.ResponseWriter, r *http.Request, ns, name string) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "kevaso-exec") {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "want Upgrade: kevaso-exec"))
		return
	}
	q := r.URL.Query()
	cmd, err := FileCommand(q.Get("op"), q.Get("path"))
	if err == nil && (q.Get("op") == client.FileWrite) != (r.Method == http.MethodPost) {
		err = fmt.Errorf("write with POST, read, list and stat with GET")
	}
	if err != nil {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "%v", err))
		return
	}
	s.siloStream(w, r, ns, name, client.ExecHeader{Command: cmd}, client.MaxFileTransfer)
}

// FileCommand is what runs in the silo for a file operation on p (absolute; cleaned here). Every
// path is an argument of its own, never parsed by a shell, and never starts with "-".
func FileCommand(op, p string) ([]string, error) {
	if !path.IsAbs(p) || strings.ContainsAny(p, "\x00\n") {
		return nil, fmt.Errorf("path %q: want an absolute path in the silo", p)
	}
	p = path.Clean(p)
	dir, base := path.Split(p)
	switch op {
	case client.FileRead:
		if p == "/" {
			return []string{"tar", "-cf", "-", "-C", "/", "."}, nil
		}
		return []string{"tar", "-cf", "-", "-C", dir, "./" + base}, nil
	case client.FileWrite:
		return []string{"tar", "-xf", "-", "-C", p}, nil
	case client.FileList:
		if p != "/" {
			p += "/" // the folder a link points to, not the link
		}
		return []string{"ls", "-lAn", "--", p}, nil
	case client.FileStat:
		return []string{"ls", "-ldn", "--", p}, nil
	}
	return nil, fmt.Errorf("op %q: want read, write, list or stat", op)
}

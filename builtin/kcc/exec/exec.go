// Package exec runs programs on the control-plane host as cert-controllers and as DNS providers,
// so an existing tool (certbot, lego, a script against your DNS host's API) plugs into Kevaso
// without Kevaso knowing it. The operator registers them when starting the control plane:
//
//	kevasod control-plane --cert-controller certbot=/etc/kevaso/kcc/certbot-issue
//	kevasod control-plane --dns-provider cloudflare=/etc/kevaso/dns/cloudflare
//
// Issuers only name them: nothing in the API can make the control plane run a command.
//
// A cert-controller program is run as `PROGRAM issue`, gets the request as JSON on stdin
// ({"issuer", "config", "hosts", "csr"}, csr in PEM) and prints the certificate chain in PEM, leaf
// first, on stdout. It proves control of the hosts however it likes; it never sees the key.
//
// A DNS provider program is run as `PROGRAM present FQDN VALUE` and `PROGRAM cleanup FQDN VALUE`
// (the convention of lego's exec provider), FQDN like _acme-challenge.example.com. with the dot.
//
// Programs get the control plane's environment (where their DNS API credentials can come from)
// and stderr goes to the control plane's log.
package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"strings"
	"time"

	"kevaso.com/core/sdk/kcc"
)

// CertController is a program that issues certificates.
type CertController struct {
	Name    string
	Program string
	Timeout time.Duration // default 10 minutes
	Stderr  io.Writer     // default os.Stderr
}

// Request is what a cert-controller program reads on stdin.
type Request struct {
	Issuer string          `json:"issuer"`
	Config json.RawMessage `json:"config,omitempty"`
	Hosts  []string        `json:"hosts"`
	CSR    string          `json:"csr"` // PEM
}

// Info implements kcc.CertController.
func (c *CertController) Info() kcc.Info {
	return kcc.Info{Name: c.Name, Description: "the program " + c.Program}
}

// Issue implements kcc.CertController.
func (c *CertController) Issue(ctx context.Context, r kcc.Request) ([][]byte, error) {
	in, _ := json.Marshal(Request{Issuer: r.Issuer, Config: r.Config, Hosts: r.Hosts,
		CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: r.CSR}))})
	out, err := run(ctx, c.Timeout, 10*time.Minute, c.Stderr, bytes.NewReader(in), c.Program, "issue")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Name, err)
	}
	var chain [][]byte
	for rest := out; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			chain = append(chain, b.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("%s: printed no PEM certificate", c.Name)
	}
	return chain, nil
}

// DNSProvider is a program that writes and removes TXT records.
type DNSProvider struct {
	Program string
	Timeout time.Duration // default 2 minutes
	Stderr  io.Writer
}

// Present writes the record.
func (p *DNSProvider) Present(ctx context.Context, fqdn, value string) error {
	_, err := run(ctx, p.Timeout, 2*time.Minute, p.Stderr, nil, p.Program, "present", fqdn, value)
	return err
}

// CleanUp removes it.
func (p *DNSProvider) CleanUp(ctx context.Context, fqdn, value string) error {
	_, err := run(ctx, p.Timeout, 2*time.Minute, p.Stderr, nil, p.Program, "cleanup", fqdn, value)
	return err
}

func run(ctx context.Context, timeout, def time.Duration, stderr io.Writer, stdin io.Reader, prog string, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = def
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := osexec.CommandContext(ctx, prog, args...)
	cmd.Stdin = stdin
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = stderr
	cmd.WaitDelay = time.Second // a child left holding stdout open can't hang us past the timeout
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%s %s: timed out after %v", prog, args[0], timeout)
		}
		return nil, fmt.Errorf("%s %s: %w", prog, args[0], err)
	}
	return out.Bytes(), nil
}

// ParseRegistration splits a NAME=PROGRAM flag value.
func ParseRegistration(s string) (name, program string, err error) {
	name, program, ok := strings.Cut(s, "=")
	if !ok || name == "" || program == "" {
		return "", "", fmt.Errorf("%q: want NAME=PROGRAM", s)
	}
	if !strings.HasPrefix(program, "/") {
		return "", "", fmt.Errorf("%q: the program must be an absolute path", s)
	}
	return name, program, nil
}

var _ kcc.CertController = (*CertController)(nil)

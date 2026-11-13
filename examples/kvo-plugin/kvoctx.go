package main

// The kvo plugin contract (ADR 0008), from the plugin's side. A plugin in any language does the
// same three things; this file is all of it in Go, with the standard library only.
//
//  1. Read where the cluster is from the environment kvo sets: KVO_PLUGIN_SERVER, KVO_PLUGIN_CA_FILE
//     (the cluster CA, the only one to trust; empty for a plain-http dev server), KVO_PLUGIN_NAMESPACE.
//  2. Ask kvo for an access token when one is needed: run "$KVO_PLUGIN_KVO" plugin token, which
//     prints {"token": "…", "expiresAt": "…"}. It is short-lived: ask again shortly before
//     expiresAt (or after a 401). Never store it, and never ask for anything longer-lived.
//  3. Call the API with "Authorization: Bearer TOKEN". The plugin can do what the person running
//     it can do (their RBAC), nothing more.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// session is the context kvo started the plugin in.
type session struct {
	Context, Server, Namespace, Kvo string
	http                            *http.Client
}

func fromKvo() (*session, error) {
	s := &session{
		Context:   os.Getenv("KVO_PLUGIN_CONTEXT"),
		Server:    os.Getenv("KVO_PLUGIN_SERVER"),
		Namespace: os.Getenv("KVO_PLUGIN_NAMESPACE"),
		Kvo:       os.Getenv("KVO_PLUGIN_KVO"),
	}
	if s.Server == "" || s.Kvo == "" {
		return nil, errors.New("run me through kvo: kvo whoami")
	}
	s.http = &http.Client{Timeout: 30 * time.Second}
	if caFile := os.Getenv("KVO_PLUGIN_CA_FILE"); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificate", caFile)
		}
		// Trust the cluster's CA only, not the system's.
		s.http.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	return s, nil
}

// token is what `kvo plugin token` prints.
type token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (s *session) token() (token, error) {
	var out, errOut bytes.Buffer
	cmd := exec.Command(s.Kvo, "plugin", "token")
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return token{}, fmt.Errorf("kvo plugin token: %v: %s", err, bytes.TrimSpace(errOut.Bytes()))
	}
	var t token
	return t, json.Unmarshal(out.Bytes(), &t)
}

// get calls GET path on the API with a fresh token and decodes the JSON answer.
func (s *session) get(path string, out any) error {
	t, err := s.token()
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, s.Server+path, nil)
	if err != nil {
		return err
	}
	if t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.Token)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var e struct{ Message string }
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s: %s %s", path, resp.Status, e.Message)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

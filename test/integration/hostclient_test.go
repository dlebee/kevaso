package integration

import (
	"context"
	"net/http"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/controlplane"
)

// hostClient is the client a host's agent uses: a host certificate for name (a worker), enrolled
// with a one-time join token as kvoadm host add and kevasod worker do. An agent on the admin
// socket writes with root's trust, not a host's: since a handoff is ended only by the host it is
// moving from (moves.HostWrite), an agent must write as its host.
func hostClient(t *testing.T, ctx context.Context, admin *client.Client, cp *controlplane.Running, name string) *client.Client {
	t.Helper()
	var tok client.JoinTokenResponse
	if err := admin.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: name, Roles: []string{"worker"}}, &tok); err != nil {
		t.Fatal(err)
	}
	server := "https://" + cp.APIAddr
	anon, err := client.NewTLS(server, cp.CA.PEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := anon.Enroll(ctx, tok.Token, name, "worker")
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.NewTLSEndpoints([]string{server}, cred.CA, cred.Certificate, cred.Key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

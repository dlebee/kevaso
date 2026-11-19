package apiserver_test

import (
	"net/http"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// DELETE of a status path is refused. The object stays.
func TestDeleteOfAStatusPathIsRefused(t *testing.T) {
	c, ctx := setup(t)
	s := newSilo("web")
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+"/apis/kevaso/v1/namespaces/dev/silos/web/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE of a status path: %d, want 405", resp.StatusCode)
	}
	var got v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "web", &got); err != nil {
		t.Fatalf("silo after DELETE of its status: %v", err)
	}
	if err := c.Delete(ctx, "Silo", "dev", "web"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Silo", "dev", "web", &got); !client.IsNotFound(err) {
		t.Fatalf("DELETE of the silo: %v", err)
	}
}

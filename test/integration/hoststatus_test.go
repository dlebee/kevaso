package integration

import (
	"context"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// writeHostStatus fills a host's status and writes it, as its agent would, again from what is
// stored when the host controller wrote it in between (a new host's mesh index): a test that wrote
// once failed now and then with a conflict.
func writeHostStatus(ctx context.Context, t *testing.T, c *client.Client, h *v1.Host, fill func(*v1.Host)) {
	t.Helper()
	for i := 0; ; i++ {
		fill(h)
		err := c.UpdateStatus(ctx, h)
		if err == nil {
			return
		}
		if !client.IsConflict(err) || i > 20 {
			t.Fatal(err)
		}
		if err := c.Get(ctx, "Host", "", h.Name, h); err != nil {
			t.Fatal(err)
		}
	}
}

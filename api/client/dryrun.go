package client

import (
	"context"
	"net/http"

	"kevaso.com/core/api/meta"
)

// DryRunUpdate sends obj as an update with ?dryRun=All: the server checks it as it would a real
// update (defaults, mutation policies, rules, policies, resourceVersion) and answers with what it
// would store, into obj, storing nothing.
func (c *Client) DryRunUpdate(ctx context.Context, obj meta.Object) error {
	p, err := c.objPathFor(ctx, obj, obj.GetObjectMeta().Name, false)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPut, p+"?dryRun=All", obj, obj)
}

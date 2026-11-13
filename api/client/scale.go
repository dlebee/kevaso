package client

import (
	"context"
	"net/http"

	v1 "kevaso.com/core/api/v1"
)

// GetScale reads a defined object's scale subresource (kind: any of its names).
func (c *Client) GetScale(ctx context.Context, kind, namespace, name string) (*v1.Scale, error) {
	p, err := c.pathFor(ctx, kind, namespace, name)
	if err != nil {
		return nil, err
	}
	var sc v1.Scale
	return &sc, c.do(ctx, http.MethodGet, p+"/scale", nil, &sc)
}

// UpdateScale sets a defined object's wanted replicas; sc carries the count and, to refuse a
// stale write, the resourceVersion it was read at (empty: whatever is stored now).
func (c *Client) UpdateScale(ctx context.Context, kind string, sc *v1.Scale) error {
	p, err := c.pathFor(ctx, kind, sc.Namespace, sc.Name)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPut, p+"/scale", sc, sc)
}

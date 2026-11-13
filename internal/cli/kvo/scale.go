package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"

	"kevaso.com/core/api/client"
)

// scaleDefined: kvo scale KIND NAME --replicas N, for a defined kind whose definition has the
// scale subresource (ADR 0005 §10b).
func scaleDefined(ctx context.Context, c *client.Client, o opts, stdout io.Writer) error {
	r, err := c.Resolve(ctx, o.args[0])
	if err != nil {
		return fmt.Errorf("scale works on silosets and on defined kinds with the scale subresource: %w", err)
	}
	if r.BuiltIn || !r.Scale {
		return fmt.Errorf("%s has no scale subresource (scale works on silosets and on defined kinds whose definition declares subresources.scale)", r.Resource)
	}
	if o.sets.instances < 0 {
		return errors.New("--replicas can't be negative")
	}
	sc, err := c.GetScale(ctx, r.Resource, defaultNS(o), o.args[1])
	if err != nil {
		return err
	}
	sc.Spec.Replicas = int64(o.sets.instances)
	if err := c.UpdateScale(ctx, r.Resource, sc); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "%s/%s scaled to %d\n", r.Resource, sc.Name, sc.Spec.Replicas)
	return nil
}

package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// PathAPIResources lists every kind the server serves, built-in and defined (ADR 0005).
const PathAPIResources = "/apis"

// Resources asks the server for every kind it serves, and remembers the answer for Resolve.
func (c *Client) Resources(ctx context.Context) ([]v1.APIResource, error) {
	var l v1.APIResourceList
	if err := c.do(ctx, http.MethodGet, PathAPIResources, nil, &l); err != nil {
		return nil, err
	}
	c.kindsMu.Lock()
	c.kinds = l.Resources
	c.kindsMu.Unlock()
	return l.Resources, nil
}

// Resolve finds a kind by any of its names: for built-ins the kind or plural (Silo, silos); for
// defined kinds PLURAL.GROUP (databases.acme.dev), or, when only one group uses it, the kind,
// plural, singular or a short name. It asks the server only for kinds it doesn't know yet.
func (c *Client) Resolve(ctx context.Context, name string) (v1.APIResource, error) {
	if k, ok := v1.Lookup(name); ok {
		return v1.BuiltinResource(k), nil
	}
	return c.resolve(ctx, func(r v1.APIResource) int { return nameMatch(r, name) }, name)
}

// ResolveObject finds the kind of an object from its apiVersion and kind.
func (c *Client) ResolveObject(ctx context.Context, apiVersion, kind string) (v1.APIResource, error) {
	if apiVersion == v1.APIVersion {
		k, ok := v1.Lookup(kind)
		if !ok || k.Kind != kind {
			return v1.APIResource{}, fmt.Errorf("unknown kind %s %s", apiVersion, kind)
		}
		return v1.BuiltinResource(k), nil
	}
	return c.resolve(ctx, func(r v1.APIResource) int {
		if !r.BuiltIn && r.APIVersion() == apiVersion && r.Kind == kind {
			return 2
		}
		return 0
	}, apiVersion+" "+kind)
}

// nameMatch: 2 for the exact resource, 1 for another of its names, 0 for none.
func nameMatch(r v1.APIResource, name string) int {
	if r.BuiltIn {
		return 0
	}
	if r.Resource == name {
		return 2
	}
	l := strings.ToLower(name)
	if strings.EqualFold(r.Kind, name) || r.Plural == l || r.Singular == l {
		return 1
	}
	for _, s := range r.ShortNames {
		if s == l {
			return 1
		}
	}
	return 0
}

func (c *Client) resolve(ctx context.Context, match func(v1.APIResource) int, what string) (v1.APIResource, error) {
	for attempt := 0; attempt < 2; attempt++ {
		c.kindsMu.Lock()
		known := c.kinds
		c.kindsMu.Unlock()
		if known == nil || attempt == 1 {
			var err error
			if known, err = c.Resources(ctx); err != nil {
				return v1.APIResource{}, err
			}
		}
		var best []v1.APIResource
		score := 0
		for _, r := range known {
			switch m := match(r); {
			case m > score:
				best, score = []v1.APIResource{r}, m
			case m == score && m > 0:
				best = append(best, r)
			}
		}
		switch {
		case len(best) == 1:
			return best[0], nil
		case len(best) > 1:
			var names []string
			for _, r := range best {
				names = append(names, r.Resource)
			}
			return v1.APIResource{}, fmt.Errorf("%q could be %s: say which", what, strings.Join(names, " or "))
		}
	}
	return v1.APIResource{}, fmt.Errorf("unknown kind %q", what)
}

// pathFor is Path for any kind, built-in or defined.
func (c *Client) pathFor(ctx context.Context, kind, namespace, name string) (string, error) {
	if _, ok := v1.Lookup(kind); ok {
		return Path(kind, namespace, name)
	}
	r, err := c.Resolve(ctx, kind)
	if err != nil {
		return "", err
	}
	return r.PathFor(namespace, name), nil
}

// objPathFor is the path of an object (name "": its collection), built-in or defined.
func (c *Client) objPathFor(ctx context.Context, obj meta.Object, name string, status bool) (string, error) {
	tm, m := obj.GetTypeMeta(), obj.GetObjectMeta()
	var p string
	if tm.APIVersion == "" || tm.APIVersion == v1.APIVersion {
		var err error
		if p, err = Path(tm.Kind, m.Namespace, name); err != nil {
			return "", err
		}
	} else {
		r, err := c.ResolveObject(ctx, tm.APIVersion, tm.Kind)
		if err != nil {
			return "", err
		}
		p = r.PathFor(m.Namespace, name)
	}
	if status {
		p += "/status"
	}
	return p, nil
}

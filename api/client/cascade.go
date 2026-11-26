package client

import (
	"context"
	"net/http"
	"net/url"
)

// Deleting a namespace with what is in it (networking v2, "Deleting"). A namespace that holds
// anything is deleted only when the delete asks for the cascade: DELETE
// /api/v1/namespaces/NAME?cascade=true. Without it the API refuses, as it always has.
//
// With ?dryRun=All as well the API deletes nothing and answers with a NamespacePlan: what the
// namespace holds, in the order it would go, or the refusal (403: things the caller may not
// delete, each named; 409: the namespace is named from outside). Passing the plan's ID back as
// ?plan=ID makes the real delete refuse if the namespace holds anything else by then, so a yes is
// for what was shown.
//
// The real delete marks the namespace (finalizer CascadeFinalizer) and answers 202; kevasod then
// deletes what is in it, in stages, and the namespace last. Its annotations say where it is
// (AnnotationCascadeStep) and, when a step failed, why (AnnotationCascadeFailed): the namespace
// stays Terminating and the same delete, run again, resumes.

// CascadeFinalizer holds a namespace whose contents kevasod is deleting.
const CascadeFinalizer = "kevaso.com/namespace-cascade"

// Annotations kevasod keeps on a namespace it is deleting with what is in it.
const (
	AnnotationCascadeBy     = "kevaso.com/cascade-by"     // who asked, and when
	AnnotationCascadeStep   = "kevaso.com/cascade-step"   // the step it is on and what it waits on
	AnnotationCascadeSince  = "kevaso.com/cascade-since"  // when that step began waiting (RFC 3339)
	AnnotationCascadeFailed = "kevaso.com/cascade-failed" // why a step stopped; set until a rerun
	AnnotationCascadeRetry  = "kevaso.com/cascade-retry"  // a rerun's time: wakes kevasod
)

// CascadeItem is one object a namespace holds.
type CascadeItem struct {
	// Kind is what the API stores it under: a built-in kind's name (Silo), or a defined kind's
	// resource (PLURAL.GROUP). Delete takes it as it is.
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	UID   string `json:"uid,omitempty"`
	Disks int    `json:"disks,omitempty"` // a silo's volumes
	Stage int    `json:"stage"`           // the step that deletes it (0 first)
	// Deleting: it is already being deleted (waiting on its finalizers).
	Deleting bool `json:"deleting,omitempty"`
}

// NamespacePlan is a dry-run cascade's answer.
type NamespacePlan struct {
	Namespace string        `json:"namespace"`
	Items     []CascadeItem `json:"items"`
	Summary   string        `json:"summary"` // "3 silos (2 with disks), 2 kept IPs, 4 secrets"
	ID        string        `json:"id"`      // pass back as ?plan= so the delete is for what was shown
	Stages    []string      `json:"stages"`  // the steps, in order
}

// DeleteOptions are a namespace delete's.
type DeleteOptions struct {
	Cascade bool   // delete what is in it too
	DryRun  bool   // answer with the plan; delete nothing
	Plan    string // NamespacePlan.ID: refuse if the namespace holds anything else now
}

// PlanNamespaceDelete asks what deleting namespace name with what is in it would delete.
func (c *Client) PlanNamespaceDelete(ctx context.Context, name string) (*NamespacePlan, error) {
	path, err := namespacePath(name, DeleteOptions{Cascade: true, DryRun: true})
	if err != nil {
		return nil, err
	}
	var p NamespacePlan
	if err := c.do(ctx, http.MethodDelete, path, nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// DeleteNamespace deletes namespace name: with opts.Cascade, with what is in it.
func (c *Client) DeleteNamespace(ctx context.Context, name string, opts DeleteOptions) error {
	path, err := namespacePath(name, opts)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

func namespacePath(name string, opts DeleteOptions) (string, error) {
	q := url.Values{}
	if opts.Cascade {
		q.Set("cascade", "true")
	}
	if opts.DryRun {
		q.Set("dryRun", "All")
	}
	if opts.Plan != "" {
		q.Set("plan", opts.Plan)
	}
	p, err := Path("Namespace", "", name)
	if err != nil {
		return "", err
	}
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	return p, nil
}

package kvo

import (
	"context"
	"encoding/json"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// wouldStore reports whether applying obj would leave the stored object cur as it is. The server
// answers that with a dry run (it fills in its defaults and runs mutation policies as a real write
// would), so a manifest that leaves out a defaulted field is still "unchanged". A secret whose
// manifest carries a value is always written: the value is never in what's stored, so there's
// nothing to compare it with.
func wouldStore(ctx context.Context, c *client.Client, obj, cur meta.Object) (bool, error) {
	if sec, ok := obj.(*v1.Secret); ok && sec.Spec.Value != nil {
		return false, nil
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return false, err
	}
	trial, _, err := v1.Decode(b) // a copy: the dry run's answer replaces it
	if err != nil {
		return false, err
	}
	if err := c.DryRunUpdate(ctx, trial); err != nil {
		return false, err
	}
	return sameDeclared(trial, cur)
}

// sameDeclared reports whether two objects agree on what a manifest declares: every top-level field
// but status (spec, a role's rules, a binding's subjects, a defined kind's fields) and the
// user-owned metadata (labels, annotations, finalizers, owners). System fields are ignored.
func sameDeclared(a, b meta.Object) (bool, error) {
	x, err := declaredPart(a)
	if err != nil {
		return false, err
	}
	y, err := declaredPart(b)
	if err != nil {
		return false, err
	}
	return x == y, nil
}

func declaredPart(obj meta.Object) (string, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return "", err
	}
	md, _ := m["metadata"].(map[string]any)
	keep := map[string]any{}
	for _, f := range []string{"labels", "annotations", "finalizers", "ownerReferences"} {
		if v, ok := md[f]; ok {
			keep[f] = v
		}
	}
	delete(m, "status")
	m["metadata"] = keep
	out, err := json.Marshal(m) // map keys are sorted: the same object is the same string
	return string(out), err
}

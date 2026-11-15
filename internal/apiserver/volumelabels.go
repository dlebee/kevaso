package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/provider"
)

// Names too long for a provider's label are refused, never cut (design §0.8, audit K-035): two
// volumes must never map to one cloud resource. The label is provider.VolumeLabel's: it keeps at
// most 26 characters of kvo-NAMESPACE-SILO-VOLUME, then -UID[:5]. Admission refuses a silo (or a
// SiloSet's instances) whose volume on a plugin's storage class would have the first part cut,
// asking the same function, which refuses (an error) instead of cutting.

// volumeLabelCut reports whether VolumeLabel would cut the readable part of the label of volume
// of silo, and what that part would be uncut.
func volumeLabelCut(namespace, silo, volume string) (uncut string, cut bool) {
	uncut = "kvo-" + namespace + "-" + silo + "-" + volume
	_, err := provider.VolumeLabel(&v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: namespace, Name: silo, UID: "uuuuuuuu"}}, volume)
	return uncut, err != nil
}

// checkVolumeLabels refuses a new or changed set of plugin volumes whose label would be cut.
func (s *Server) checkVolumeLabels(ctx context.Context, t target, obj meta.Object) error {
	if t.status {
		return nil
	}
	var silo *v1.Silo
	var prev *v1.Silo
	switch o := obj.(type) {
	case *v1.Silo:
		silo = o
		prev, _ = s.stored(ctx, t).(*v1.Silo)
	case *v1.SiloSet:
		// The longest instance name it will have (-N with N up to instances plus standby).
		silo = &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: o.Namespace, Name: v1.InstanceName(o.Name, o.Spec.Instances+o.Spec.Standby)}, Spec: o.InstanceSpec()}
		if p, ok := s.stored(ctx, t).(*v1.SiloSet); ok {
			prev = &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: p.Namespace, Name: silo.Name}, Spec: p.InstanceSpec()}
		}
	default:
		return nil
	}
	had := map[string]bool{}
	if prev != nil {
		for _, v := range v1.PluginVolumes(prev) {
			had[v.Name] = true
		}
	}
	var problems []string
	for _, v := range v1.PluginVolumes(silo) {
		if had[v.Name] {
			continue
		}
		if uncut, cut := volumeLabelCut(silo.Namespace, silo.Name, v.Name); cut {
			problems = append(problems, fmt.Sprintf("volume %s: the provider's label %s is %d characters and the label keeps %d, so volumes would share one: shorten the namespace, the silo's or the volume's name by %d",
				v.Name, uncut, len(uncut), maxLabelBody, len(uncut)-maxLabelBody))
		}
	}
	if len(problems) > 0 {
		return errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %s", t.kind.Kind, obj.GetObjectMeta().Name, strings.Join(problems, "; "))
	}
	return nil
}

// maxLabelBody is how much of kvo-NAMESPACE-SILO-VOLUME VolumeLabel keeps (its limit of 32
// characters less -UID[:5]); a message only: the cut itself is asked of VolumeLabel.
const maxLabelBody = provider.LabelLimit

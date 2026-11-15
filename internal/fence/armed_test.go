package fence

import (
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
)

func TestArmedIsForThisHostThisAfterThisGeneration(t *testing.T) {
	s := &v1.Silo{}
	s.Generation = 4
	s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
	s.Status.Host = "hv1"
	s.Status.Conditions = append(s.Status.Conditions, ArmedCondition("hv1", 45*time.Second, 4))
	if !Armed(s) {
		t.Fatal("armed for hv1, 45s, generation 4: not seen as armed")
	}
	for name, mod := range map[string]func(*v1.Silo){
		"moved to hv2":        func(s *v1.Silo) { s.Status.Host = "hv2" },
		"after changed":       func(s *v1.Silo) { s.Spec.Availability.After = "2m" },
		"a newer generation":  func(s *v1.Silo) { s.Generation = 5 },
		"no longer opted in":  func(s *v1.Silo) { s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = "", "" },
		"the condition False": func(s *v1.Silo) { s.Status.Conditions[0].Status = "False" },
		"another reason":      func(s *v1.Silo) { s.Status.Conditions[0].Reason = "Something" },
		"no condition at all": func(s *v1.Silo) { s.Status.Conditions = nil },
	} {
		c := *s
		c.Status.Conditions = append(c.Status.Conditions[:0:0], s.Status.Conditions...)
		mod(&c)
		if Armed(&c) {
			t.Errorf("%s: still armed", name)
		}
	}
}

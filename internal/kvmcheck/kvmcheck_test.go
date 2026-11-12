package kvmcheck

import "testing"

func TestVerify(t *testing.T) {
	for _, tc := range []struct {
		r  Result
		ok bool
	}{
		{Result{APIVersion: 12, CreatedVM: true}, true},
		{Result{APIVersion: 12, CreatedVM: false}, false},
		{Result{APIVersion: 11, CreatedVM: true}, false},
		{Result{}, false},
	} {
		if err := tc.r.Verify(); (err == nil) != tc.ok {
			t.Errorf("%+v.Verify() = %v, want ok=%v", tc.r, err, tc.ok)
		}
	}
}

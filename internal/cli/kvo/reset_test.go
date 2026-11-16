package kvo

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// A host writes a silo's status between kvo reset's read and its write. The first write
// conflicts; reset reads the silo again and applies the same reset.
func TestResetSiloRetriesOnceWhenTheWriteConflicts(t *testing.T) {
	const path = "/apis/kevaso/v1/namespaces/resetonce2/silos/vm"
	version := "238"
	var gets, puts int
	var resets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			gets++
			silo := v1.Silo{Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", VM: &v1.VMSource{Image: "ubuntu-24.04"}}}
			silo.APIVersion, silo.Kind = v1.APIVersion, "Silo"
			silo.Name, silo.Namespace, silo.ResourceVersion = "vm", "resetonce2", version
			_ = json.NewEncoder(w).Encode(silo)
		case http.MethodPut:
			var got v1.Silo
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("put: %v", err)
			}
			puts++
			resets = append(resets, got.Spec.Reset)
			if puts == 1 {
				version = "258"
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"code": 409, "reason": "Conflict",
					"message": "Silo/resetonce2/vm at 258, expected 238: conflict: the object was modified",
				})
				return
			}
			if got.ResourceVersion != version {
				t.Errorf("put %d at %s, stored %s", puts, got.ResourceVersion, version)
			}
			got.ResourceVersion = "259"
			_ = json.NewEncoder(w).Encode(got)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("KVO_SERVER", srv.URL)

	var out, errb bytes.Buffer
	code := Run(context.Background(), []string{"reset", "silo", "vm", "-n", "resetonce2"}, strings.NewReader(""), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "silo/vm: resetting onto ubuntu-24.04") {
		t.Fatalf("reset: %d %q %q", code, out.String(), errb.String())
	}
	if gets != 2 || puts != 2 {
		t.Fatalf("gets %d puts %d: reset must re-read after the conflict", gets, puts)
	}
	if resets[0] == "" || resets[0] != resets[1] {
		t.Fatalf("resets %q: the same change, applied again", resets)
	}
}

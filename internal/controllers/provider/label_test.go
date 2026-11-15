package provider_test

import (
	"errors"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/provider"
)

// K-035 (brainstorm §0.8): a name too long for a provider's label is refused, never cut. Before,
// kvo-production-payments-db-data and kvo-production-payments-db-logs were both cut to
// kvo-production-payments-d-UIDXX: one label for two volumes of the same silo.
func TestK035AVolumeLabelIsRefusedNotCut(t *testing.T) {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "production", Name: "payments-db", UID: "0123456789"}}
	labels := map[string]bool{}
	for _, vol := range []string{"data", "logs"} {
		l, err := provider.VolumeLabel(s, vol)
		if err == nil {
			if labels[l] {
				t.Fatalf("two volumes got the label %s", l)
			}
			labels[l] = true
			t.Fatalf("a %d-character name was given the label %q", len("kvo-production-payments-db-"+vol), l)
		}
		if !errors.Is(err, provider.ErrLabelTooLong) || !strings.Contains(err.Error(), "26") || !strings.Contains(err.Error(), "kvo-production-payments-db-"+vol) {
			t.Fatalf("refused without the limit and the name: %v", err)
		}
	}
	// Up to the limit: the whole name, then the UID's first five characters.
	ok := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "web", UID: "abcdef123"}}
	l, err := provider.VolumeLabel(ok, "data")
	if err != nil || l != "kvo-dev-web-data-abcde" {
		t.Fatalf("%q %v", l, err)
	}
	exact := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "ns", Name: "silo-name-12", UID: "abcdef123"}}
	if l, err := provider.VolumeLabel(exact, "vol-12"); err != nil || len(l) != provider.LabelLimit+6 { // kvo-ns-silo-name-12-vol-12: 26
		t.Fatalf("26 characters: %q %v", l, err)
	}
	if _, err := provider.VolumeLabel(exact, "vol-123"); err == nil {
		t.Fatal("27 characters accepted")
	}
}

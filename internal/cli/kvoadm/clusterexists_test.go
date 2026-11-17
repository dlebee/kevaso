package kvoadm

import "testing"

// kvoadm init on a machine that already holds the cluster's data (its volume moved over) says so,
// and doesn't claim it made a cluster: create-cluster answers the record it found.
func TestClusterExists(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want bool
	}{
		{`{"cluster":"home","id":"ab","state":"new","created":"2026-11-17T21:00:00Z"}`, false},
		{"some log line\n" + `{"cluster":"home","id":"ab","state":"initialized","created":"2026-11-17T21:00:00Z"}` + "\n", true},
		{`{"cluster":"home","id":"ab","state":"restored"}`, true},
		{"", false},
		{"not json", false},
	} {
		if got := clusterExists([]byte(tc.out)); got != tc.want {
			t.Errorf("%q: %v, want %v", tc.out, got, tc.want)
		}
	}
}

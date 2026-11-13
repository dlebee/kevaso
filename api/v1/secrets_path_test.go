package v1

import "testing"

// A file secret's path reaches an engine's mount argument, which splits on commas: only a clean
// absolute path of plain characters under /run/ is a path (K-001).
func TestContainerFileProblemRefusesAnythingButAPlainPath(t *testing.T) {
	for _, p := range []string{
		"/run/s,src=/,dst=/run/q/f", "/run/s/a,b", "/run/s/a:b", "/run/s/a b", "/run/s/a\nb", "/run/s/a=b",
		`/run/s/a"b`, "/run/s/a'b", "/run/s/$x", "/run/s/a;b", "/run/s/./a", "/run//s/a", "/run/s/a/", "/run/s/../a",
		"/run", "/run/a", "relative/run/x", "",
	} {
		if ContainerFileProblem(p) == "" {
			t.Errorf("%q accepted", p)
		}
	}
	for _, p := range []string{"/run/secrets/tls.pem", "/run/secrets/a/b-c_d.1"} {
		if why := ContainerFileProblem(p); why != "" {
			t.Errorf("%q refused: %s", p, why)
		}
	}
}

func TestCleanMountPath(t *testing.T) {
	for _, p := range []string{"/data:rw", "/data,x", "/a:/b", "/", "/data/", "/a/../b", "/a b", "data", "", "/data:ro"} {
		if CleanMountPath(p) {
			t.Errorf("%q accepted", p)
		}
	}
	for _, p := range []string{"/data", "/var/lib/db-1/x_y.z"} {
		if !CleanMountPath(p) {
			t.Errorf("%q refused", p)
		}
	}
}

package container

import (
	"strings"
	"testing"
)

func TestContainerLogsAreCapped(t *testing.T) {
	if got := strings.Join(containerLogArgs(), " "); got != "--log-driver json-file --log-opt max-size=10m --log-opt max-file=3" {
		t.Fatalf("log args: %s", got)
	}
	s := state{ID: silo, Image: "ubuntu-24.04"}
	args, err := (&Runtime{}).runArgs(s, NamesFor(s.ID).Main)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	if !strings.Contains(got, "--log-driver json-file --log-opt max-size=10m --log-opt max-file=3") {
		t.Fatalf("main container log is not capped: %s", got)
	}
}

package budget

import (
	"strings"
	"testing"
)

const stream = `{"Action":"run","Test":"TestA"}
{"Action":"pass","Test":"TestA"}
{"Action":"run","Test":"TestB"}
{"Action":"skip","Test":"TestB"}
{"Action":"fail","Test":"TestC"}
{"Action":"pass","Test":"TestD/sub"}
{"Action":"pass","Package":"p"}
`

func TestAnExpectedTestThatSkipsFailsTheBudget(t *testing.T) {
	got := Check(strings.NewReader(stream), []string{"TestA", "TestB"})
	if len(got) != 1 || !strings.Contains(got[0], "TestB reported SKIP") {
		t.Fatalf("got %q", got)
	}
}

func TestFailedMissingAndPassingTests(t *testing.T) {
	got := Check(strings.NewReader(stream), []string{"TestA", "TestC", "TestD/sub", "TestGone"})
	if len(got) != 2 || !strings.Contains(got[0], "TestC reported FAIL") || !strings.Contains(got[1], "TestGone never ran") {
		t.Fatalf("got %q", got)
	}
}

func TestAnEmptyListChecksNothingAndSaysSo(t *testing.T) {
	if got := Check(strings.NewReader(stream), nil); len(got) != 1 {
		t.Fatalf("got %q", got)
	}
}

func TestExpectedIgnoresCommentsAndBlanks(t *testing.T) {
	got, err := Expected(strings.NewReader("# the e2e job\n\nTestA # why\n  TestB  \n"))
	if err != nil || len(got) != 2 || got[0] != "TestA" || got[1] != "TestB" {
		t.Fatalf("%q %v", got, err)
	}
}

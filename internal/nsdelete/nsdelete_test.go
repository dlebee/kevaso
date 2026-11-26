package nsdelete

import (
	"slices"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

func TestSummaryReadsInTheOrderThingsGo(t *testing.T) {
	items := []client.CascadeItem{
		{Kind: "Secret", Name: "a"}, {Kind: "Secret", Name: "b"}, {Kind: "Secret", Name: "c"}, {Kind: "Secret", Name: "d"},
		{Kind: "IP", Name: "edge-0"}, {Kind: "IP", Name: "edge-1"},
		{Kind: "Silo", Name: "db", Disks: 1}, {Kind: "Silo", Name: "web"}, {Kind: "Silo", Name: "cache", Disks: 2},
	}
	if got, want := Summary(items), "3 silos (2 with disks), 2 kept IPs, 4 secrets"; got != want {
		t.Fatalf("summary %q, want %q", got, want)
	}
	if got, want := Summary([]client.CascadeItem{{Kind: "Silo", Name: "x"}, {Kind: "widgets.example.com", Name: "w"}}), "1 silo, 1 widgets.example.com"; got != want {
		t.Fatalf("summary %q, want %q", got, want)
	}
	if got := Summary(nil); got != "" {
		t.Fatalf("nothing: %q", got)
	}
	if got, want := Describe([]client.CascadeItem{{Kind: "Secret", Name: "d"}, {Kind: "Secret", Name: "a"}, {Kind: "Secret", Name: "c"}, {Kind: "Secret", Name: "b"}}),
		"4 secrets (a, b, c, …)"; got != want {
		t.Fatalf("describe %q, want %q", got, want)
	}
}

// Silos and sets first, then balancers, then IPs, then the rest (defined kinds among them), and
// secrets and access last.
func TestOrder(t *testing.T) {
	items := []client.CascadeItem{
		{Kind: "Secret", Name: "s"}, {Kind: "RoleBinding", Name: "rb"}, {Kind: "widgets.example.com", Name: "w"},
		{Kind: "IP", Name: "ip"}, {Kind: "IPSet", Name: "set"}, {Kind: "Service", Name: "svc"}, {Kind: "Certificate", Name: "cert"},
		{Kind: "Silo", Name: "b"}, {Kind: "Silo", Name: "a"}, {Kind: "SiloSet", Name: "ss"}, {Kind: "Ingress", Name: "ing"},
	}
	Sort(items)
	var got []string
	for _, it := range items {
		got = append(got, it.Kind+"/"+it.Name)
	}
	want := []string{"SiloSet/ss", "Silo/a", "Silo/b", "Service/svc", "Ingress/ing", "IPSet/set", "IP/ip",
		"Certificate/cert", "widgets.example.com/w", "Secret/s", "RoleBinding/rb"}
	if !slices.Equal(got, want) {
		t.Fatalf("order\n got %v\nwant %v", got, want)
	}
	for i := 1; i < len(items); i++ {
		if items[i].Stage < items[i-1].Stage {
			t.Fatalf("stage goes back at %v", items[i])
		}
	}
	st, now := Next(items)
	if st != 0 || len(now) != 3 {
		t.Fatalf("next: stage %d, %v", st, now)
	}
	if st, _ := Next(nil); st != -1 {
		t.Fatalf("next of nothing: %d", st)
	}
}

// Every namespaced built-in kind has a step: the ones the order cares about where it says, the
// rest in "the rest". A kind added later (IPSet now, others after) lands there without a line.
func TestEveryNamespacedKindHasAStep(t *testing.T) {
	named := map[string]bool{}
	for _, s := range Stages {
		for _, k := range s.Kinds {
			named[k] = true
		}
	}
	for _, k := range v1.Kinds() {
		if k.Scope != v1.Namespaced {
			continue
		}
		st, _ := StageOf(k.Kind)
		if !named[k.Kind] && Stages[st].Kinds != nil {
			t.Errorf("%s is in step %q", k.Kind, Stages[st].Name)
		}
	}
	if st, _ := StageOf("Silo"); st != 0 {
		t.Errorf("silos are step %d", st)
	}
	if st, _ := StageOf("Secret"); st != len(Stages)-1 {
		t.Errorf("secrets are step %d", st)
	}
}

func TestPlanIDIsForTheseObjects(t *testing.T) {
	a := []client.CascadeItem{{Kind: "Silo", Name: "a", UID: "1"}, {Kind: "Secret", Name: "s", UID: "2"}}
	b := []client.CascadeItem{{Kind: "Secret", Name: "s", UID: "2"}, {Kind: "Silo", Name: "a", UID: "1"}}
	if PlanID(a) != PlanID(b) {
		t.Fatal("the same objects in another order give another ID")
	}
	again := []client.CascadeItem{{Kind: "Silo", Name: "a", UID: "3"}, {Kind: "Secret", Name: "s", UID: "2"}}
	if PlanID(a) == PlanID(again) {
		t.Fatal("a silo made again under its name gives the same ID")
	}
	if PlanID(a) == PlanID(a[:1]) {
		t.Fatal("one fewer object gives the same ID")
	}
	p := Plan("web3", b)
	if p.Items[0].Kind != "Silo" || p.Summary != "1 silo, 1 secret" || len(p.Stages) != len(Stages) {
		t.Fatalf("plan %+v", p)
	}
	if empty := Plan("web3", nil); empty.Items == nil || empty.Summary != "" {
		t.Fatalf("empty plan %+v", empty)
	}
}

func TestProgressString(t *testing.T) {
	p := Progress{Stage: 0, Left: []client.CascadeItem{{Kind: "Silo", Name: "b"}, {Kind: "Silo", Name: "a"}}}
	if got, want := p.String(), "step 1/5, stop silos: waiting on 2 silos (a, b)"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	p = Progress{Stage: 2, Left: []client.CascadeItem{{Kind: "IP", Name: "edge"}}, Refused: []string{"kept IP edge: held"}}
	if got, want := p.String(), "step 3/5, release IPs: waiting on 1 kept IP (edge); refused for now: kept IP edge: held"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}

package mesh

import (
	"reflect"
	"testing"
)

func TestRoutePlan(t *testing.T) {
	add, del := routePlan(nil, []string{"10.63.0.0/16", "10.64.1.0/24"})
	if !reflect.DeepEqual(add, []string{"10.63.0.0/16", "10.64.1.0/24"}) || len(del) != 0 {
		t.Fatalf("%v %v", add, del)
	}
	add, del = routePlan([]string{"10.63.0.0/16", "10.64.1.0/24"}, []string{"10.63.0.0/16", "10.64.2.0/24"})
	if !reflect.DeepEqual(add, []string{"10.64.2.0/24"}) || !reflect.DeepEqual(del, []string{"10.64.1.0/24"}) {
		t.Fatalf("%v %v", add, del)
	}
	add, del = routePlan([]string{"a"}, []string{"a"})
	if len(add)+len(del) != 0 {
		t.Fatalf("nothing changes: %v %v", add, del)
	}
}

func TestAddressHelpers(t *testing.T) {
	if n, err := networkOf("10.63.0.3/16"); err != nil || n != "10.63.0.0/16" {
		t.Fatal(n, err)
	}
	if h, err := hostOf("10.63.0.3/16"); err != nil || h != "10.63.0.3" {
		t.Fatal(h, err)
	}
	if _, err := hostOf("nope"); err == nil {
		t.Fatal("accepted")
	}
}

func TestIfconfigAndRouteArgs(t *testing.T) {
	got := ifconfigArgs("utun7", "10.63.0.3", 1380)
	want := [][]string{
		{"ifconfig", "utun7", "inet", "10.63.0.3/32", "10.63.0.3", "alias"},
		{"ifconfig", "utun7", "mtu", "1380"},
		{"ifconfig", "utun7", "up"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	if r := routeArgs("add", "10.63.0.0/16", "utun7"); !reflect.DeepEqual(r, []string{"route", "-q", "-n", "add", "-inet", "10.63.0.0/16", "-interface", "utun7"}) {
		t.Fatalf("%v", r)
	}
	if len(ifconfigArgs("utun7", "10.0.0.1", 0)) != 2 {
		t.Fatal("no mtu step when none is wanted")
	}
}

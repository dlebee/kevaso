package service_test

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/service"
)

func silo(name, host, addr string, labels map[string]string, ready bool) *v1.Silo {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3", Labels: labels},
		Spec:   v1.SiloSpec{Service: &v1.SiloService{Ports: []v1.ServicePort{{Name: "rpc", Port: 8546}}}},
		Status: v1.SiloStatus{Host: host, Address: addr}}
	s.Status.Phase = "Starting"
	if ready {
		s.Status.Phase = "Running"
		meta.SetCondition(&s.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue}, time.Now())
	}
	return s
}

func TestEndpoints(t *testing.T) {
	svc := &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3"},
		Spec: v1.ServiceSpec{Selector: map[string]string{"app": "rpc"},
			Ports: []v1.ServicePortSpec{{Name: "rpc", Port: 8545, TargetPort: "rpc"}, {Name: "metrics", Port: 9100}}}}
	app := map[string]string{"app": "rpc"}
	standby := map[string]string{"app": "rpc", v1.LabelStandby: "true"}
	other := silo("b", "w1", "10.64.1.3", app, true)
	other.Namespace = "elsewhere"
	eps := service.Endpoints(svc, []*v1.Silo{
		silo("c", "w2", "10.64.2.2", app, true),
		silo("a", "w1", "10.64.1.2", app, true),
		silo("d", "w1", "10.64.1.4", app, false),                           // not running yet
		silo("e", "w1", "10.64.1.5", standby, true),                        // standby
		silo("f", "w1", "10.64.1.6", map[string]string{"app": "db"}, true), // not selected
		other, // other namespace
	})
	if len(eps) != 2 || eps[0].Silo != "a" || eps[1].Silo != "c" || eps[0].Host != "w1" {
		t.Fatalf("endpoints: %+v", eps)
	}
	// rpc → the silo's named port (8546); metrics → the same number.
	if p := eps[0].Ports; len(p) != 2 || p[0].NodePort != 8546 || p[1].NodePort != 9100 {
		t.Fatalf("ports: %+v", p)
	}
}

func TestAddresses(t *testing.T) {
	a := &v1.Service{ObjectMeta: meta.ObjectMeta{UID: "a"}, Status: v1.ServiceStatus{ClusterIP: "10.65.0.1"}}
	b := &v1.Service{ObjectMeta: meta.ObjectMeta{UID: "b"}, Spec: v1.ServiceSpec{Type: v1.ServiceLoadBalancer,
		Ports: []v1.ServicePortSpec{{Name: "x", Port: 1}, {Name: "y", Port: 2}}}}
	ip, err := service.ClusterIP(b, []*v1.Service{a, b})
	if err != nil || ip != "10.65.0.2" {
		t.Fatalf("cluster IP: %s %v", ip, err)
	}
	b.Status.ClusterIP = ip
	if again, _ := service.ClusterIP(b, []*v1.Service{a, b}); again != ip {
		t.Fatal("cluster IP not kept")
	}
	nps, err := service.NodePorts(b, []*v1.Service{a, b})
	if err != nil || len(nps) != 2 || nps[0].NodePort != v1.NodePortSiloMax+1 || nps[1].NodePort != v1.NodePortSiloMax+2 {
		t.Fatalf("node ports: %+v %v", nps, err)
	}
	if nps, _ := service.NodePorts(a, []*v1.Service{a, b}); nps != nil {
		t.Fatal("a ClusterIP service got node ports")
	}
}

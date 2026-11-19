package provider

import (
	"context"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestAnUnsettledSiloDoesNotAttach(t *testing.T) {
	c := &Volumes{Gate: &v1.RestoreGate{Spec: v1.RestoreGateSpec{
		History: "h2", Started: time.Now().Add(time.Hour), NoHostsAdded: true,
	}}}
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev", UID: "u1"}}
	vs, _, err := c.ensure(context.Background(), s, nil, v1.Volume{Name: "data", Class: "linode", MountPath: "/data"}, v1.VolumeStatus{})
	if err != nil || vs.Message != "waiting until the restored history settles this silo" {
		t.Fatalf("%+v %v", vs, err)
	}
}

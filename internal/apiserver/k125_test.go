package apiserver_test

import (
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/pki"
)

// K-125: a create stores no status, for a built-in kind and for a plugin-defined kind. A namespace
// admin who may create the object gets it back with empty status. Status is written only through
// the status subresource, and that subresource's writer rules are unchanged: the namespace admin
// is refused, the admin socket is allowed, a worker writes a silo's status only while the silo is
// placed on it and never places it, and a spec write leaves the stored status as it was.
func TestK125CreateStoresNoCallerStatus(t *testing.T) {
	e := setupAuth(t)
	if err := e.admin.Create(e.ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "ada", Namespace: "dev"},
		RoleRef:    v1.RoleRef{Kind: "ClusterRole", Name: "admin"},
		Subjects:   []v1.Subject{{Kind: "User", Name: "ada"}}}); err != nil {
		t.Fatal(err)
	}
	id := pki.Identity{Type: "user", Name: "ada", Role: "member"}
	key, csr, err := pki.NewKeyAndCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := e.ca.SignCSR(csr, id, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ada := e.tlsClient(t, &client.Credentials{Certificate: cert, Key: key})

	ip := &v1.IP{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IP"},
		ObjectMeta: meta.ObjectMeta{Name: "pub", Namespace: "dev"},
		Spec:       v1.IPSpec{Class: v1.LBIPPool},
		Status:     v1.IPStatus{Address: "203.0.113.50", Handle: "res-1"}}
	if err := ada.Create(e.ctx, ip); err != nil {
		t.Fatal(err)
	}
	var gotIP v1.IP
	if err := e.admin.Get(e.ctx, "IP", "dev", "pub", &gotIP); err != nil {
		t.Fatal(err)
	}
	if gotIP.Status.Address != "" || gotIP.Status.Handle != "" {
		t.Fatalf("a namespace admin's created IP has status %+v", gotIP.Status)
	}

	silo := newSilo("web")
	silo.Status = v1.SiloStatus{
		Host:    "hv9",
		SiloIP:  "10.64.9.9",
		Volumes: []v1.VolumeStatus{{Name: "data", Class: "local", AttachedTo: "hv9", Device: "/dev/vdb"}},
		Image:   &v1.SiloImage{From: "ubuntu-24.04", Ref: "disk://ubuntu-24.04"},
	}
	if err := ada.Create(e.ctx, silo); err != nil {
		t.Fatal(err)
	}
	var gotSilo v1.Silo
	if err := e.admin.Get(e.ctx, "Silo", "dev", "web", &gotSilo); err != nil {
		t.Fatal(err)
	}
	if gotSilo.Status.Host != "" || gotSilo.Status.SiloIP != "" || len(gotSilo.Status.Volumes) != 0 || gotSilo.Status.Image != nil {
		t.Fatalf("a namespace admin's created Silo has status %+v", gotSilo.Status)
	}

	if err := e.admin.Create(e.ctx, dbDefinition(t, dbSchema)); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, &v1.Role{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Role"},
		ObjectMeta: meta.ObjectMeta{Name: "db-editor", Namespace: "dev"},
		Rules:      []v1.PolicyRule{{Verbs: []string{"get", "list", "watch", "create", "update", "delete"}, Resources: []string{"databases.acme.dev"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "ada-db", Namespace: "dev"},
		RoleRef:    v1.RoleRef{Kind: "Role", Name: "db-editor"},
		Subjects:   []v1.Subject{{Kind: "User", Name: "ada"}}}); err != nil {
		t.Fatal(err)
	}
	db := db("main", map[string]any{"engine": "postgres"})
	db.Fields["status"] = map[string]any{"phase": "Faked", "endpoint": "db.internal:5432"}
	if err := ada.Create(e.ctx, db); err != nil {
		t.Fatal(err)
	}
	var gotDB v1.Unstructured
	if err := e.admin.Get(e.ctx, "databases.acme.dev", "dev", "main", &gotDB); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotDB.Get("status"); ok {
		t.Fatalf("a namespace admin's created Database has status %v", gotDB.Fields["status"])
	}

	// The status subresource's writer rules: the namespace admin is refused; the admin socket writes it.
	if err := ada.UpdateStatus(e.ctx, &gotIP); code(err) != 403 {
		t.Fatalf("namespace admin writing an IP's status: %v, want 403", err)
	}
	if err := ada.UpdateStatus(e.ctx, &gotSilo); code(err) != 403 {
		t.Fatalf("namespace admin writing a Silo's status: %v, want 403", err)
	}
	if err := ada.UpdateStatus(e.ctx, &gotDB); code(err) != 403 {
		t.Fatalf("namespace admin writing a Database's status: %v, want 403", err)
	}
	gotIP.Status = v1.IPStatus{Address: "203.0.113.50", Handle: "res-1"}
	if err := e.admin.UpdateStatus(e.ctx, &gotIP); err != nil || gotIP.Status.Address != "203.0.113.50" || gotIP.Status.Handle != "res-1" {
		t.Fatalf("admin socket writing the IP's status: %+v %v", gotIP.Status, err)
	}
	gotSilo.Status = v1.SiloStatus{
		Host:    "hv1",
		SiloIP:  "10.64.1.2",
		Volumes: []v1.VolumeStatus{{Name: "data", Class: "local", AttachedTo: "hv1", Device: "/dev/vdb"}},
		Image:   &v1.SiloImage{From: "ubuntu-24.04", Ref: "disk://ubuntu-24.04"},
	}
	if err := e.admin.UpdateStatus(e.ctx, &gotSilo); err != nil {
		t.Fatal(err)
	}
	gotDB.Fields["status"] = map[string]any{"phase": "Ready"}
	if err := e.admin.UpdateStatus(e.ctx, &gotDB); err != nil || gotDB.GetString("status", "phase") != "Ready" {
		t.Fatalf("admin socket writing the Database's status: %v %v", gotDB.Fields["status"], err)
	}

	// A spec write keeps the stored status, whatever status the body carries.
	if err := ada.Get(e.ctx, "Silo", "dev", "web", &gotSilo); err != nil {
		t.Fatal(err)
	}
	gotSilo.Spec.Resources.CPU = 4
	gotSilo.Status = v1.SiloStatus{}
	if err := ada.Update(e.ctx, &gotSilo); err != nil {
		t.Fatal(err)
	}
	if gotSilo.Spec.Resources.CPU != 4 || gotSilo.Status.Host != "hv1" || gotSilo.Status.SiloIP != "10.64.1.2" ||
		len(gotSilo.Status.Volumes) != 1 || gotSilo.Status.Volumes[0].AttachedTo != "hv1" || gotSilo.Status.Volumes[0].Device != "/dev/vdb" ||
		gotSilo.Status.Image == nil || gotSilo.Status.Image.Ref != "disk://ubuntu-24.04" {
		t.Fatalf("spec write: cpu %v status %+v", gotSilo.Spec.Resources.CPU, gotSilo.Status)
	}
	if err := ada.Get(e.ctx, "IP", "dev", "pub", &gotIP); err != nil {
		t.Fatal(err)
	}
	gotIP.Labels = map[string]string{"team": "web"}
	gotIP.Status = v1.IPStatus{}
	if err := ada.Update(e.ctx, &gotIP); err != nil {
		t.Fatal(err)
	}
	if gotIP.Labels["team"] != "web" || gotIP.Status.Address != "203.0.113.50" || gotIP.Status.Handle != "res-1" {
		t.Fatalf("spec write of the IP: labels %v status %+v", gotIP.Labels, gotIP.Status)
	}
	if err := ada.Get(e.ctx, "databases.acme.dev", "dev", "main", &gotDB); err != nil {
		t.Fatal(err)
	}
	gotDB.Set("10Gi", "spec", "size")
	gotDB.Fields["status"] = map[string]any{"phase": "Faked"}
	if err := ada.Update(e.ctx, &gotDB); err != nil {
		t.Fatal(err)
	}
	if gotDB.GetString("spec", "size") != "10Gi" || gotDB.GetString("status", "phase") != "Ready" {
		t.Fatalf("spec write of the Database: spec %v status %v", gotDB.Fields["spec"], gotDB.Fields["status"])
	}

	// A worker writes the silo's status only as the host it is placed on, and never an IP's.
	if err := e.admin.Create(e.ctx, host("hv1")); err != nil {
		t.Fatal(err)
	}
	tok, err := e.tokens.Create(e.ctx, "hv1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv1", "worker")
	if err != nil {
		t.Fatal(err)
	}
	worker := e.tlsClient(t, &cred)
	var wSilo v1.Silo
	if err := worker.Get(e.ctx, "Silo", "dev", "web", &wSilo); err != nil {
		t.Fatal(err)
	}
	wSilo.Status.Phase = "Running"
	if err := worker.UpdateStatus(e.ctx, &wSilo); err != nil || wSilo.Status.Phase != "Running" || wSilo.Status.Host != "hv1" {
		t.Fatalf("the silo's host writing its phase: %+v %v", wSilo.Status, err)
	}
	wSilo.Status.Host = "hv2"
	if err := worker.UpdateStatus(e.ctx, &wSilo); code(err) != 403 {
		t.Fatalf("the silo's host placing it: %v, want 403", err)
	}
	if err := e.admin.Get(e.ctx, "Silo", "dev", "web", &gotSilo); err != nil || gotSilo.Status.Host != "hv1" || gotSilo.Status.Phase != "Running" {
		t.Fatalf("after the refused placement: %+v %v", gotSilo.Status, err)
	}
	var wIP v1.IP
	if err := worker.Get(e.ctx, "IP", "dev", "pub", &wIP); err != nil {
		t.Fatal(err)
	}
	wIP.Status.Address = "198.51.100.9"
	if err := worker.UpdateStatus(e.ctx, &wIP); code(err) != 403 {
		t.Fatalf("a worker writing an IP's status: %v, want 403", err)
	}
	if err := e.admin.Get(e.ctx, "IP", "dev", "pub", &gotIP); err != nil || gotIP.Status.Address != "203.0.113.50" || gotIP.Status.Handle != "res-1" {
		t.Fatalf("IP status after the worker's write: %+v %v", gotIP.Status, err)
	}
}

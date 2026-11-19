package kvoadm

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/pki"
)

type scriptedRun struct{ out []byte }

func (s scriptedRun) Run(context.Context, string, []byte) ([]byte, error) { return s.out, nil }

func TestSignUserOverSSHRefusesAnotherIdentity(t *testing.T) {
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := pki.Identity{Type: "user", Name: "mallory", Role: "cluster-admin"}
	_, csr, err := pki.NewKeyAndCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.SignCSR(csr, id, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(struct {
		Certificate string
		CA          string
	}{string(cert), string(ca.PEM)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := signUserOverSSH(context.Background(), scriptedRun{body}, "ada"); err == nil || !strings.Contains(err.Error(), "not user ada") {
		t.Fatalf("certificate for mallory: %v", err)
	}
}

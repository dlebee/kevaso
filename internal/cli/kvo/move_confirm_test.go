package kvo

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
)

type forbidMove struct{ msg string }

func (f forbidMove) Call(context.Context, string, string, any, any) error {
	m := f.msg
	if m == "" {
		m = "no"
	}
	return &client.Error{Code: http.StatusForbidden, Reason: "Forbidden", Message: m}
}

func TestConfirmFencedExplainsThePermission(t *testing.T) {
	err := move(context.Background(), forbidMove{}, opts{args: []string{"silo", "web"}, namespace: "shop", moveTo: "hv2", confirmFenced: true}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "hosts/confirm-off") || !strings.Contains(err.Error(), "cluster-admin") || !strings.Contains(err.Error(), "silos/move") {
		t.Fatalf("kvo move --confirm-fenced: %v", err)
	}
	err = move(context.Background(), forbidMove{}, opts{args: []string{"silo", "web"}, namespace: "shop", moveTo: "hv2", insist: true}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "hosts/confirm-off") {
		t.Fatalf("kvo move --insist: %v", err)
	}
}

// The server's 403 already explains the permission (apiserver's confirmOffDenied): kvo says it
// once, not twice.
func TestConfirmFencedExplainsItOnce(t *testing.T) {
	srv := "saying the old copy is off (--confirm-fenced, and --insist with it) needs create on hosts/confirm-off. That permission is cluster-scoped and only cluster-admin has it by default. editor and admin keep plain moves (create on silos/move)"
	err := move(context.Background(), forbidMove{msg: srv}, opts{args: []string{"silo", "web"}, namespace: "shop", moveTo: "hv2", confirmFenced: true}, io.Discard)
	if err == nil || strings.Count(err.Error(), "hosts/confirm-off") != 1 {
		t.Fatalf("kvo move --confirm-fenced: want the explanation once, got: %v", err)
	}
}

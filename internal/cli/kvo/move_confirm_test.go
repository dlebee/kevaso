package kvo

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
)

type forbidMove struct{}

func (forbidMove) Call(context.Context, string, string, any, any) error {
	return &client.Error{Code: http.StatusForbidden, Reason: "Forbidden", Message: "no"}
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

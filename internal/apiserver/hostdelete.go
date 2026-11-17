package apiserver

import (
	"context"
	"net/http"

	v1 "kevaso.com/core/api/v1"
)

// guardHostDelete refuses to delete a Host that still has silos placed on it or moving from it
// unless the request carries ?confirmOff=true. That flag is the person's confirmation the
// machine is off or wiped, the same fact as kvo move --confirm-fenced. A Host with no such silo
// deletes as before.
func (s *Server) guardHostDelete(ctx context.Context, r *http.Request, name string) error {
	silos, err := listAs[*v1.Silo](ctx, s.store, "Silo")
	if err != nil {
		return err
	}
	n := 0
	for _, silo := range silos {
		if silo.Status.Host == name || silo.Status.MovingFrom == name {
			n++
		}
	}
	if n > 0 && r.URL.Query().Get("confirmOff") != "true" { // deleting a host that still has silos needs ?confirmOff=true
		return errf(http.StatusConflict, "Conflict",
			"host %s still has %d silo(s) placed on it or moving from it: not deleted. Confirm the machine is off or wiped with ?confirmOff=true", name, n)
	}
	return nil
}

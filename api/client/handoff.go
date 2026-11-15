package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	v1 "kevaso.com/core/api/v1"
)

// ErrHandoffUnderWay: the silo is already moving off a host that hasn't let go (its
// status.movingFrom is set). Starting another handoff would overwrite it, and the next host could
// start the silo while the first still runs it (K-070). The same rule as moves.Begin in core
// (movingFrom naming the silo's own host is no handoff).
var ErrHandoffUnderWay = errors.New("a move is already under way")

// StartHandoff writes the status that starts moving silo s off its host (kvoadm host drain, or
// any status write that sets movingFrom), as a conditional write: it reads the silo afresh,
// refuses it while a handoff is under way (ErrHandoffUnderWay) or when another silo now has the
// name (a Conflict), asks next for the status from what it read, and writes at the version it
// read. A write that conflicts (the silo changed in between) is read and judged again, a few
// times. It returns the silo as stored.
func (c *Client) StartHandoff(ctx context.Context, s *v1.Silo, next func(cur *v1.Silo) (v1.SiloStatus, error)) (*v1.Silo, error) {
	var err error
	for range 5 {
		var cur v1.Silo
		if err = c.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
			return nil, err
		}
		if s.UID != "" && cur.UID != s.UID {
			return nil, &Error{Code: http.StatusConflict, Reason: "Conflict",
				Message: fmt.Sprintf("silo %s/%s is another object now (uid %s, not %s)", s.Namespace, s.Name, cur.UID, s.UID)}
		}
		if cur.Status.MovingFrom != "" && cur.Status.MovingFrom != cur.Status.Host {
			return nil, fmt.Errorf("silo %s/%s: %w (from %s, which hasn't let go)", s.Namespace, s.Name, ErrHandoffUnderWay, cur.Status.MovingFrom)
		}
		st, nerr := next(&cur)
		if nerr != nil {
			return nil, nerr
		}
		cur.Status = st
		if err = c.UpdateStatus(ctx, &cur); err == nil {
			return &cur, nil
		}
		if !IsConflict(err) {
			return nil, err
		}
	}
	return nil, err
}

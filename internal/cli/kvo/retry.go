package kvo

import "kevaso.com/core/api/client"

// retryUpdate runs update, and when that reports a conflict runs it again, five times
// at most. update reads the object again and applies the same change, as a Kubernetes
// client's RetryOnConflict does. A host writes status often; a read-modify-write that
// keeps the version it first read loses to that. The last conflict is returned when
// every try lost.
func retryUpdate(update func() error) error {
	var err error
	for range 5 {
		err = update()
		if !client.IsConflict(err) {
			return err
		}
	}
	return err
}

package store_test

import (
	"testing"

	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/store/storetest"
)

func TestMemory(t *testing.T) {
	storetest.Run(t, func(t *testing.T, keep int) store.Store { return store.NewMemory(keep) })
}

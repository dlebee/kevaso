package fake_test

import (
	"testing"

	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
	"kevaso.com/core/sdk/kri/kritest"
)

// The fake passes the same suite as real runtimes.
func TestFakeConformance(t *testing.T) {
	kritest.Run(t, func(*testing.T) kri.Runtime { return fake.New() }, kritest.Options{Image: "test"})
}

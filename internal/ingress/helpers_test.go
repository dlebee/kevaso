package ingress

import (
	kicdrivers "kevaso.com/core/builtin/kic"
	"kevaso.com/core/sdk/kic"
)

func builtins() kic.Registry { return kicdrivers.Builtin() }

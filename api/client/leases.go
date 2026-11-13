package client

import v1 "kevaso.com/core/api/v1"

// LeaseAnswer is the answer to POST …/silos/NAME/open and …/close (design §7.2d): the port's lease
// as it now is, and whether the time asked was cut to the silo's max.
type LeaseAnswer struct {
	Lease   v1.Lease `json:"lease"`
	Clamped bool     `json:"clamped,omitempty"`
}

package client

import (
	"context"
	"net/http"
)

// PathSystemNodeJoin is where a new system node joins the store (kvoadm host add --install
// control-plane gave it a one-time token with the role "system-node").
const PathSystemNodeJoin = "/join/system-node"

// SystemNodeJoinRequest is a new system node asking to join. Recipient is the public half of a
// key it made for this one answer: the cluster's identity comes back sealed to it, so nothing on the
// way (kvoadm included) can read it.
type SystemNodeJoinRequest struct {
	Token     string `json:"token"`
	Host      string `json:"host"`
	Recipient []byte `json:"recipient"`
}

// SystemNodeJoinResponse is what it starts its etcd member with.
type SystemNodeJoinResponse struct {
	Cluster        string            `json:"cluster"`        // the cluster's name
	PeerURL        string            `json:"peerURL"`        // the URL its member must advertise
	InitialCluster map[string]string `json:"initialCluster"` // every member's name → peer URL, itself included
	Bundle         []byte            `json:"bundle"`         // the identity files, sealed to Recipient
}

// JoinSystemNode asks the control plane at c (a client from NewTLS with the pinned CA, no
// certificate needed) to take this host into the store.
func (c *Client) JoinSystemNode(ctx context.Context, req SystemNodeJoinRequest) (SystemNodeJoinResponse, error) {
	var resp SystemNodeJoinResponse
	err := c.do(ctx, http.MethodPost, PathSystemNodeJoin, req, &resp)
	return resp, err
}

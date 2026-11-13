package etcd

import (
	"time"

	v1 "kevaso.com/core/api/v1"
)

// Judge sets each member's health for NextStep (pure):
//   - a voter is healthy while its Host heartbeats: lastHeartbeat within lease of now (a full system
//     node heartbeats through its API, a light node writes its own into the store);
//   - a learner is healthy once it has started (it has a name): its Host can't heartbeat yet, since
//     a learner serves no reads. Whether it has caught up is etcd's call: it refuses the promotion
//     until then, and the controller asks again next round.
func Judge(members []Member, hosts []v1.Host, now time.Time, lease time.Duration) []Member {
	beat := map[string]time.Time{}
	for _, h := range hosts {
		if h.Status.LastHeartbeat != nil {
			beat[h.Name] = *h.Status.LastHeartbeat
		}
	}
	out := make([]Member, len(members))
	for i, m := range members {
		switch {
		case m.Name == "":
			m.Healthy = false
		case m.Learner:
			m.Healthy = true
		default:
			t, ok := beat[m.Name]
			m.Healthy = ok && now.Sub(t) <= lease
		}
		out[i] = m
	}
	return out
}

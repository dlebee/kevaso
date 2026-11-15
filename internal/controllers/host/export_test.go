package host

import "time"

// ContactAt is when c last saw host's heartbeat change (zero: never), for tests.
func ContactAt(c *Contacts, host string) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last[host].at
}

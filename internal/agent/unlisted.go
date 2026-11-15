package agent

import (
	"context"
	"errors"
	"fmt"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kri"
)

// stopUnlisted is removeEverywhere's look at what no runtime listed (K-105). A runtime's List
// skips a silo whose state file it can't read, while that silo may still run: Status, Kill and
// Stop find it by its name. So each copy of k this host may hold that no runtime listed (the
// cached silo, and any whose delete was seen here) is asked for by name. A runtime that holds one
// that isn't this host's to run now (placed elsewhere, handed off, being deleted, gone or
// replaced) has it stopped, Status confirming, and kept with all it holds: nothing a runtime can't
// read is handed to its Delete, which would remove nothing and forget it. It is listed on the Host
// (KeptSilos). An error, or a copy that still runs, is returned: the caller then releases nothing
// (a handoff waits) and looks again.
func (a *Agent) stopUnlisted(ctx context.Context, k engine.Key, s *v1.Silo, listed map[string]bool) error {
	var ids []kri.ID
	if s != nil && !listed[s.UID] {
		ids = append(ids, idOf(s))
	}
	a.seenIDs.Range(func(_, v any) bool {
		if id := v.(kri.ID); id.Namespace == k.Namespace && id.Name == k.Name && !listed[id.UID] && (s == nil || id.UID != s.UID) {
			ids = append(ids, id)
		}
		return true
	})
	for _, id := range ids {
		ours := s != nil && id.UID == s.UID && s.Status.Host == a.HostName && s.DeletionTimestamp == nil
		if (s == nil || id.UID != s.UID) && !a.seenHere(id.UID) {
			continue // a delete seen under another history: kept as it is, as a listed copy would be
		}
		for rtName, rt := range a.Runtimes {
			st, err := rt.Status(ctx, id)
			if err != nil {
				return fmt.Errorf("%s on %s: can't say whether it runs here (%w): nothing is released", id, rt.Info().Name, err)
			}
			if st.State == kri.Absent || ours {
				continue // nothing of it there, or this host's to run (its runtime reports its state)
			}
			if _, why, err := a.mayRemove(ctx, id); err != nil {
				return err
			} else if why == "" {
				continue // the store places it here again: the cache was behind
			}
			if st.State == kri.Running {
				a.log("%s on %s: its runtime doesn't list it (%s), and it runs: stopping it", id, rt.Info().Name, firstLineOf(st.Message))
				if err := stopByName(ctx, rt, id); err != nil {
					return fmt.Errorf("%s on %s: stopping a copy its runtime doesn't list: %w", id, rt.Info().Name, err)
				}
				if st, err = rt.Status(ctx, id); err != nil {
					return fmt.Errorf("%s on %s: can't say whether it still runs (%w): nothing is released", id, rt.Info().Name, err)
				}
				if st.State == kri.Running {
					return fmt.Errorf("%s on %s: still runs after its stop: nothing is released", id, rt.Info().Name)
				}
			}
			c := keptCopy{runtime: rtName, id: id, unlisted: true,
				name: keptName(id, rt.Info().Name+", stopped, unlisted: "+firstLineOf(st.Message))}
			if _, logged := a.keptNoted.LoadOrStore(id.UID, c); !logged {
				a.log("keeping %s on %s, stopped, with all it holds: its runtime doesn't list it (%s); restore its state file, or remove it by hand",
					id, rt.Info().Name, firstLineOf(st.Message))
			}
		}
	}
	return nil
}

// stopByName ends everything of a silo its runtime may not be able to read: a kill where the
// runtime has one (cloud-hypervisor's Stop needs the state file; its Kill finds the VMM by its
// unit), else a stop.
func stopByName(ctx context.Context, rt kri.Runtime, id kri.ID) error {
	var err error
	if k, ok := rt.(kri.Killer); ok {
		err = k.Kill(ctx, id)
	} else {
		err = rt.Stop(ctx, id)
	}
	if errors.Is(err, kri.ErrNotFound) {
		return nil
	}
	return err
}

// unreadableStates is a runtime that names the state files it can't read (K-105): a silo behind
// one isn't in its List and may still run. The agent lists them on the Host (KeptSilos), so
// nothing that may run here is invisible.
type unreadableStates interface {
	Unreadable(ctx context.Context) []string
}

// unreadableKept is what the runtimes say they can't read, as it is listed on the Host.
func (a *Agent) unreadableKept(ctx context.Context) []string {
	var out []string
	for _, rt := range a.Runtimes {
		u, ok := rt.(unreadableStates)
		if !ok {
			continue
		}
		for _, p := range u.Unreadable(ctx) {
			out = append(out, p+" ("+rt.Info().Name+": its state can't be read, so its silo, which may run, is not listed; restore the file or remove that silo by hand)")
		}
	}
	return out
}

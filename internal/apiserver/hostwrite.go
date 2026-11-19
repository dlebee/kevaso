package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/mesh"
	"kevaso.com/core/internal/store"
)

// What a worker may write in its own Host's status, and what bounds it (review batch 3; the
// control plane's own fields, provider and the mesh addresses, are kept as stored in update):
//
//	lastHeartbeat   every write is the worker saying it is alive; the time is the server's on
//	                receipt (a stamp far in the future would keep the host from ever being lost),
//	                and never the one stored (K-106: else the write is no contact); a held
//	                worker's beat (Ready reason WorkerHeld) is no contact: stamp and Ready kept
//	                as stored (K-108)
//	controlPlane    the control plane's own (a system node's API URL every agent dials, the cluster's
//	                DNS suffix): kept as stored
//	network keys    the host's: published once; a different key for a host that has one is a
//	                re-key, which is a new join, not a status write (403)
//	allocatable,    the host's to report; a large step (more than double, or half, or a mount class
//	mountClasses    added after its first report) is recorded in the ReportedChange condition,
//	                which only the control plane writes. The scheduler trusting them is the owner's
//	                design question.
//	version, conditions, runtimes: the host's to report.
//
// And on a silo placed on it (moves.HostWrite for the rest): siloIP inside the subnet the control
// plane assigned the host, or on the default network. A host with no subnet yet, and a host that
// is not in the store, may use only that default network (siloIPInSubnet); phase is the host's
// to report.
const CondReportedChange = "ReportedChange"

func boundHostWrite(oh v1.HostStatus, nh *v1.HostStatus, host string, now time.Time) error {
	// Every status write a host makes of its own Host is a heartbeat, whatever it sent: stamped on
	// receipt, never with the stamp stored, so the control plane counts it as a contact (K-106);
	// unless the beat says its worker is held (Ready reason WorkerHeld): no contact, its stamp and
	// Ready kept as stored, as its fence counts none (K-108).
	hostctl.Beat(oh, nh, now)
	nh.ControlPlane = oh.ControlPlane
	if oh.Network.PublicKey != "" && nh.Network.PublicKey != oh.Network.PublicKey {
		return errf(http.StatusForbidden, "Forbidden", "%s may not change its published mesh key: a new key is a new join (kvoadm host remove %s, then add it again)", host, host)
	}
	if oh.Network.InnerPublicKey != "" && nh.Network.InnerPublicKey != oh.Network.InnerPublicKey {
		return errf(http.StatusForbidden, "Forbidden", "%s may not change its published inner mesh key: a new key is a new join (kvoadm host remove %s, then add it again)", host, host)
	}
	// The record of a large step is the control plane's: the worker's copy of it is ignored.
	nh.Conditions = slices.DeleteFunc(slices.Clone(nh.Conditions), func(c meta.Condition) bool { return c.Type == CondReportedChange })
	if c := meta.FindCondition(oh.Conditions, CondReportedChange); c != nil {
		nh.Conditions = append(nh.Conditions, *c)
	}
	if steps := largeSteps(oh, *nh); len(steps) > 0 {
		meta.SetCondition(&nh.Conditions, meta.Condition{Type: CondReportedChange, Status: meta.ConditionTrue, Reason: "LargeStep",
			Message: host + " reported " + strings.Join(steps, "; ") + " (the scheduler places silos by what a host reports)"}, now.UTC().Truncate(time.Second))
	}
	return nil
}

// largeSteps says what changed by a large step in what the host offers, after its first report.
func largeSteps(oh, nh v1.HostStatus) []string {
	var out []string
	if oh.Allocatable == (v1.Resources{}) {
		return nil // its first report
	}
	far := func(a, b float64) bool { return a > 0 && (b > 2*a || b < a/2) }
	if far(float64(oh.Allocatable.CPU), float64(nh.Allocatable.CPU)) {
		out = append(out, fmt.Sprintf("allocatable cpu %d → %d", oh.Allocatable.CPU, nh.Allocatable.CPU))
	}
	om, oerr := v1.ParseBytes(oh.Allocatable.Memory)
	nm, nerr := v1.ParseBytes(nh.Allocatable.Memory)
	if oerr == nil && nerr == nil && far(float64(om), float64(nm)) {
		out = append(out, fmt.Sprintf("allocatable memory %s → %s", oh.Allocatable.Memory, nh.Allocatable.Memory))
	}
	var added []string
	for _, c := range nh.MountClasses {
		if !slices.Contains(oh.MountClasses, c) {
			added = append(added, c)
		}
	}
	if len(added) > 0 {
		out = append(out, "mount classes added: "+strings.Join(added, ", "))
	}
	return out
}

// siloIPInSubnet: a host gives a silo placed on it an address inside the subnet the control plane
// assigned it, or on the default network (mesh.Addresses(0)). A worker that is not on the mesh
// addresses silos there even after this host has a subnet: that network is the same on every such
// host, and an address on it is only ever routed on that host. A host with no subnet yet, and a
// host that is not in the store, may use only that default network. A subnet that does not parse
// refuses the address. An address outside both ranges is refused.
func (s *Server) siloIPInSubnet(ctx context.Context, old, next v1.SiloStatus, host string) error {
	if next.SiloIP == "" || next.SiloIP == old.SiloIP {
		return nil
	}
	ip, err := netip.ParseAddr(next.SiloIP)
	if err != nil {
		return errf(http.StatusForbidden, "Forbidden", "%s may not give a silo the address %q", host, next.SiloIP)
	}
	_, defSubnet, _ := mesh.Addresses(0)
	defaultNet := netip.MustParsePrefix(defSubnet)
	inDefault := defaultNet.Contains(ip)
	o, err := s.store.Get(ctx, store.Key{Kind: "Host", Name: host})
	if errors.Is(err, store.ErrNotFound) { // a missing host has no subnet
		if !inDefault { // a missing host has no subnet: only the default network
			return errf(http.StatusForbidden, "Forbidden", "%s has no subnet: an address only in the default %s, not %s", host, defSubnet, next.SiloIP)
		}
		return nil
	}
	if err != nil {
		return err
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return err
	}
	subnet := obj.(*v1.Host).Status.Network.SiloSubnet
	if subnet == "" { // a host without a subnet yet: only the default network
		if !inDefault { // a host with no subnet yet: only the default network
			return errf(http.StatusForbidden, "Forbidden", "%s has no subnet: an address only in the default %s, not %s", host, defSubnet, next.SiloIP)
		}
		return nil
	}
	p, err := netip.ParsePrefix(subnet)
	if err != nil { // a subnet that does not parse
		return errf(http.StatusForbidden, "Forbidden", "%s may give a silo an address only in its subnet %s, not %s", host, subnet, next.SiloIP)
	}
	if !p.Contains(ip) && !inDefault { // the address is in this host's subnet, or on the default network
		return errf(http.StatusForbidden, "Forbidden", "%s may give a silo an address only in its subnet %s (or the default %s), not %s", host, subnet, defSubnet, next.SiloIP)
	}
	return nil
}

// hostDeleted reports whether the Host object is gone. An error reading it is not deleted.
// A host that still exists and is only lost is not deleted (hostGone covers that).
func (s *Server) hostDeleted(ctx context.Context, host string) bool {
	_, err := s.store.Get(ctx, store.Key{Kind: "Host", Name: host})
	return errors.Is(err, store.ErrNotFound)
}

// hostGone reports whether host is lost (its Ready HostLost) or no longer a Host. An error reading
// it is not gone.
func (s *Server) hostGone(ctx context.Context, host string) bool {
	o, err := s.store.Get(ctx, store.Key{Kind: "Host", Name: host})
	if errors.Is(err, store.ErrNotFound) {
		return true
	}
	if err != nil {
		return false
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		return false
	}
	lost, _ := hostctl.Lost(obj.(*v1.Host))
	return lost
}

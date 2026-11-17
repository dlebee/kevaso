# Deleting a host

Deleting a Host is a person's confirmation that the machine is off or wiped, the same fact as
`kvo move --confirm-fenced`. Two rules stay in force. A silo never runs on two hosts (rule 1).
Nothing deletes a volume's data because a Host was deleted (rule 2): a local volume on that
machine is simply no longer reachable.

## Confirming the delete

`DELETE /apis/kevaso/v1/hosts/NAME` counts silos with `status.host` or `status.movingFrom` equal
to that name. None: the delete proceeds as before. One or more, and the request does not carry
`?confirmOff=true`: 409, the count, and that query parameter. The flag is the confirmation.

`kvo delete host NAME --confirm-off` sends it. `kvoadm host remove NAME` lists which silos will
be started on another host and which will stay unschedulable, asks `Is NAME off or wiped? [y/N]`,
and deletes with the flag. `--confirm-off` skips the question for a script. `RemovalCheck` and the
rest of `RemoveSystemNode` are unchanged: a system node is still refused when removing it would
lose the store's majority or the last API. A worker host is no longer refused merely because a
silo is on it.

Deleting a Host stays cluster-admin only. The built-in roles give `delete` on `hosts` to
`cluster-admin` and to nobody else (`internal/rbac/builtin.go`).

## Silos

The silo controller, when `status.host` names a Host object that is gone:

- Movable, meaning what `kvo move --confirm-fenced` would allow for a lost host today. `onHostLoss:
  Move` and every disk and volume can attach elsewhere: placed elsewhere with its data, the same
  status change as the confirmed move. `onHostLoss: Recreate` and `moves.CheckPolicy` allows it
  (no host-local volume left behind): placed elsewhere as a fresh copy. The scheduler picks the
  host. `internal/moves.PlaceAfterHostDelete` is that decision.
- Not movable (`onHostLoss: Wait`, a microVM whose root disk is local and was not opted into
  Recreate, a local volume): it stays in the store. `status.host` is left naming the deleted host,
  so nothing else is chosen and `kvo move` can still see where it was. Condition
  `Unschedulable=True`, reason `HostDeleted`. The message names the host, says a local volume or
  disk there is no longer reachable and was not deleted, and names the two ways out:
  `kvo move silo NAME -n NS --to HOST --recreate`, or delete the silo. Re-adding a machine with
  the same name does not clear this. `moves.MayStart` refuses that host, so its agent does not
  start the silo. A move clears the condition (`moves.Apply`).
- A silo whose `status.movingFrom` names the deleted host ends its handoff immediately. The
  destination starts it. `EndsDeletedHandoff` is what the API allows the silo controller to write:
  only `movingFrom` cleared, the silo staying on its destination. A host that still exists but is
  lost is unchanged (`EndsLostHandoff` still wants the fence). An inbound handoff whose
  destination was deleted is re-placed, the handoff kept, which is the lost-destination path: that
  host never started the silo.

The volume controller may detach a volume whose host object is gone, the same as a lost host
(`ForceRelease`, and `lostNow` already treats a missing Host as lost). It does not delete one.
`remove` runs only when the volume is no longer in the spec, or the silo is being deleted.

## Certificates

`pki.SignCSR` sets `NotBefore` to `now` minus one minute, and an x509 time is a whole second. A
certificate issued in that minute would have `NotBefore` earlier than the removal, so a plain
comparison would refuse the new certificate too. Comparing serials alone would need a log of every
certificate ever issued, which this cluster does not keep.

What is stored, under the internal kind `HostRemoval` (not an API kind, same idea as `JoinToken`),
is the host name and the removal time, truncated to a second. It is in the same store as every
other object, so it survives a restart and is what every control-plane member reads.

`auth.go` refuses a host certificate whose `NotBefore` is earlier than that time, or whose serial
is not one recorded after the removal, with 401 `host NAME was removed from the cluster; join it
again with kvoadm host add`. The serial list is empty at removal, so every certificate already
issued fails closed even if two members' clocks disagree by more than the backdate. Enrollment,
when a removal record exists, asks `SignCSRNotBefore` for a `NotBefore` at least one second after
the stored time, then records that certificate's serial before returning it. `kvoadm host add` of
the same name therefore works. Another host has no record and is unaffected. A later delete
replaces the record, which drops the serials, so the previous re-join is refused too.

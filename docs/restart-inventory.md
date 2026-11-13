# Restart inventory

What a host or the control plane holds outside the store, and what puts it back after:

- (a) `systemctl restart kevasod`
- (b) kevasod killed (SIGKILL) mid-operation
- (c) a host reboot: tmpfs and kernel state gone, `/var/lib` kept
- (d) a system node losing leadership and getting it back

Each row also says whether a test proves it. Rows marked **R-n** were findings. Their status is in the list at the end.

This is a working document for maintainers. It was filled in by reading the code on `phase/restart-audit` (cut from `56bce1f`). "Undetermined" means the code here can't answer it.

## Boot and start order (worker host)

Nothing of a silo comes back on its own before kevasod:

- VMM units and virtiofsd units have no `[Install]` section and use `Restart=no`.
- Containers are run with no `--restart`, so Docker starts nothing at boot. `live-restore` only keeps them up across a dockerd restart.
- The OpenShell gateway unit is `WantedBy=multi-user.target`. Whether it brings its sandboxes back by itself is undetermined (OpenShell's own behaviour).

`kevasod` (`internal/worker/worker.go` Run) starts in this order:

1. It waits until the API returns its Host. Until then nothing below runs, and the old kernel state stays in place.
2. It loads the egress CA.
3. It runs every runtime's Install. Install sets up the bridge, `ip_forward` and the **baseline** firewall. The baseline is default deny with no silo rules, and it is now loaded only when there is no ruleset (R-1). Then Install sets up storage.
4. The first bridge runtime to finish starts `RunNetwork`. Its first full ruleset waits for every informer (R-2).
5. The runtime is marked Ready, and the agent starts its silos, gated by RuntimeReady. The agent reconciles nothing before its Grant and Secret caches have synced (R-4).

After a reboot every silo therefore starts default-denied, and gets its own rules on the network loop's next pass.

## Network (worker)

| State | Where | (a) / (b) | (c) | Test |
|---|---|---|---|---|
| Bridge `kvbr0`, its gateway address, `ip_forward`, `nf_conntrack_bridge` | kernel | stay; Install is idempotent | Install remakes them before Ready | cloudhypervisor `TestSetNetworkAndFirewall` (commands only) |
| Silo ruleset `inet kevaso` and `bridge kevaso` | kernel nftables | stays. Each `nft -f` is one transaction (delete and add). Install used to replace it with the baseline (R-1) | baseline at Install, full rules on the first RunNetwork pass | kni `rules_test`, `props_test`, `nfteval_test` (text); `TestSetupNetworkKeepsALiveRulesetAndLoadsTheBaselineAfterAReboot` |
| Rules held inside the ruleset: host-port DNAT, `sources`, node ports, LB IPs, per-tap anti-spoofing, lease cut rules | kernel | rebuilt by the first pass, which now waits for every informer (R-2) | same | `TestRunNetworkFirstApplyAfterARestartKeepsOpenLeases` |
| `/etc/kevaso-silos.nft` | disk | rewritten each apply; nothing loads it at boot | kept, unused | — |
| Last applied ruleset (`last`) | memory | "" in a new process, so it applies again; also forced every minute | same | — |
| Lease expiry timer | memory, from the stored `Lease.status.until` | recomputed every pass, not reset | same | worker `TestWithLeases` (pure) |
| A lease that ends while kevasod is down, or while it was restarted cut off (blocked in step 1) | kernel rule | **stays open** until kevasod applies again (R-13) | closed (baseline) | none |
| Pool /32s on the uplink, `lo:kv`, the endpoint address on `kvbr0:kv` | kernel | stay while kevasod is down (R-14); resynced each pass | re-added by RunNetwork | pure tests only |
| Container veth and pause netns | kernel and engine | kept; `wire` is skipped when eth0 has its address | `wire` makes it again at Start | container runtime tests |
| TAP | kernel | kept | remade by Start (fixed on `phase/metal`) | cloudhypervisor `storage_test` |
| DNS listeners, egress gate listener (:15001) | goroutines; bind retried every 5s | down while kevasod is down | bind waits for the addresses | `dns_test`, `gate_test` |
| Gate injection cache (1 min), leaf certificates (24 h) | memory | fetched again or minted again | same | `gate_test` |
| Egress CA `DATA/egress-ca/ca.{key,crt}` | disk | loaded; was written in place (R-10) | kept | `TestACAWriteCutShortIsNotKeptAsTheCA` |

(d) does not apply: all of the above runs on the worker.

## Mesh and tunnels

| State | Where | (a) / (b) | (c) | Test |
|---|---|---|---|---|
| WireGuard keys `DATA/mesh/kevaso{0,1}.key` | disk | loaded; were written in place (R-11) | kept | `TestAMeshKeyWriteCutShortIsNotKept` |
| WireGuard links, peers, addresses, routes | kernel | stay; diffed against the Host list on every change and every 30s | rebuilt only once kevasod reaches the API: the peers come from the Host list | `diff_test`, `plan_test` (pure); nothing tests the apply |
| Agent tunnels to system nodes, known control planes | memory; the URLs are on disk (`KeepServers`) | rebuilt from a Host list every 15s | same | `tunnel_test` |

## Secrets

| State | Where | (a) | (b) | (c) | Test |
|---|---|---|---|---|---|
| What the agent last delivered to each silo (`delivered`) | memory | empty, so it writes again (atomic `mv`). A silo that receives nothing now used to be skipped, keeping what was revoked while kevasod was down (R-3) | a kill between a file and the list leaves a file the list doesn't name (low, open) | VM `/run` is empty; the files are written again once it runs | `TestSecretRevokedWhileTheAgentWasDownGoesAfterItsRestart` |
| A VM's `/run` secrets, `secrets.env`, `/run/kevaso/delivered` | guest tmpfs | kept | — | gone; written again once the VM runs. The guest's own services start before them on every boot (by design, ADR 0009) | `TestHostWrittenDeliveries`, `TestDeliveriesOnlyOnTmpfs` |
| Egress CA in a VM's trust store | guest disk | skipped on its hash | its marker is written last | kept | `TestEgressCAInVM` |
| `/run/kevaso-secrets/SHORT` tmpfs (files, env file) | host tmpfs | kept, written again when changed | `.tmp` left in a folder the container mounts read-only (low, open) | empty; `prepareSecrets` refuses to start a container until SetSecrets has run | `TestSecretsPlan` |
| Container `state.json` secrets record | `/var/lib/kevaso-containers` | kept (temp and rename) | a file written but not recorded is kept until Delete or a reboot (low, open) | kept | none |
| kevaso-oci configuration and link | `/etc/kevaso`, `/usr/local/lib/kevaso` | rewritten at every Install | atomic | kept. A missing env file fails closed | `TestInstallRegistersTheRuntime`, ocienv `TestFailsClosed` |
| Docker `daemon.json` | `/etc/docker` | rewritten only when changed. A kill between the write and dockerd's restart left dockerd on the old configuration for good (R-9) | — | kept | `TestADaemonConfigWrittenButNotAppliedIsAppliedOnTheNextInstall` |
| How env secrets travel (`envPlanned`) | memory | unset until Install; a silo keeps the way it had | — | same | `TestEnvWayKeptBeforeInstall` |
| Grant and Secret informer caches | memory | the agent used to reconcile before they synced (R-4) | — | same | `TestASiloWaitsForItsGrantsBeforeItsInitSteps` |
| Local endpoint registrations (`byAddr`) | memory | empty until each silo's reconcile reaches Running. Meanwhile a silo gets 404 "no Kevaso endpoint", the same answer as a missing secret (low, open) | — | same; the listener retries until the address is back | `endpoint_test` (no restart) |
| OpenShell policy hash and providers | runtime `state.json` | skipped on an equal hash | redone (the CLI calls are idempotent) | undetermined: whether the gateway keeps providers across its own restart | none |

## Volumes and downloads

| State | Where | (a) / (b) | (c) | Test |
|---|---|---|---|---|
| Provider (block) volume mounts | kernel | `mountpoint` checked every pass; `mkfs` only when `blkid -p` exits 2 | mounted again before Start | `TestMountFormatsOnlyAnEmptyVolume` |
| Mount-reach (JuiceFS) mounts made by a plugin's node side; the agent's `nodeMounts` | external FUSE; memory | were trusted for the whole run; a mount lost behind the agent's back was never made again (R-6) | made again before Start | `TestALostNodeMountIsMountedAgain`; whether the node side survives its own restart is up to the plugin (undetermined) |
| Unmounting a silo's volume folder | host fs | removed recursively after one umount; with two mounts stacked the lower one's files went (R-7) | — | `TestUnmountNeverRemovesAFolderThatIsStillMounted` |
| VM state `silo.json` | `/var/lib/kevaso-silos/SHORT` | was written in place (R-5). An unreadable one still reads as an absent silo (R-15, handed off) | kept | `TestLocalWriteFileIsNeverSeenHalfWritten`; skipped `TestAnUnreadableStateIsNotAnAbsentSilo` |
| A VM Create killed after it saved its state | disk, LVM | never finished: Created for good, Start fails (R-16, handed off) | same | skipped `TestACreateKilledHalfwayIsFinishedNextTime` |
| Thin pool, VG, local LVs, loop file | LVM | `vgchange -ay` at every Install, before Ready | loop reattach (fixed on `phase/metal`) | `storage_test` |
| `guestMounted` (what a guest last mounted) | memory | not cleared when the VM restarts within one run (liveness restart, a VMM restarted by resync): only the guest's `nofail` fstab mounts it (handed off with R-17) | cleared (new process) | none |
| virtiofsd units | `/etc/systemd/system` | their own units, which outlive kevasod | restarted by Start after the mounts | `TestStartStopWithShares`, `TestVirtiofsdOutlivesAGuestReboot` |
| Disk image and binary downloads | `ImagesDir`, temp `.download` | hashed, then renamed; every Fetch hashes again. Two Creates of one image share the temp path (low, open) | kept | none for the race |
| Registry auth file of a pull | `/run/kevaso-pull` | removed by a defer only; left behind by a kill (low, open) | gone | `TestPullWithCredential` |

## Ingress, certificates, probes, panes, daemons

| State | Where | (a) / (b) | (c) / (d) | Test |
|---|---|---|---|---|
| Probe results and timers | status (`lastTime`, `startedAt`; wall clock) | read back from status; nothing restarts | a silo started again keeps its old Ready, so it is routed before readiness passes (R-17, handed off) | probes tests (pure); skipped `TestARestartedSiloIsNotRoutedBeforeItsReadinessPassesAgain` |
| Routing | derived from status on each write; read by DNS, Service endpoints, host ports and ingress | — | same | `routing_test` |
| Daemons | pid files in the silo's `/run/kevaso/daemons` (a tmpfs in containers) | probed again, never started twice | gone with `/run`, started once | `keep_test`; OpenShell's `/run`: undetermined |
| Upkeep `every` | `status.upkeep[].lastCheck` | not reset; after a kill the check runs first | same | keep tests (pure) |
| Ingress plan last applied (`applied`) | memory | a file driver reads the config back. It skipped the reload when the file matched, so a stop between move and reload was never loaded (R-8) | — | `TestARestartAfterTheMoveStillReloads` |
| Ingress last good plan while a class is held (`lastGood`) | memory only | after a restart with a refused Ingress nothing is applied, and new ACME answers stop (open) | — | none |
| Kong config | the proxy's memory | `applied` is cleared only when a 3s tick sees the silo not Running, so a quick proxy restart is never configured again (open, kong) | — | none |
| Rendered proxy config and certificate files | inside the controller silo | kept | kept on reboot, gone on reset | `TestApplyFiles` |
| ACME account key | store, sealed | stored before registration; a failed registration left every later order without an account (R-12) | — | `TestAnAccountWhoseRegistrationFailedIsRegisteredNextTime` |
| HTTP-01 challenges, DNS-01 TXT records | store rows; external DNS | a kill mid-issue leaves the TXT record and the row (the row expires) (low, open) | (d): undetermined whether a lost term cancels a running Issue | none |
| Issued certificate | Secret, then status | a kill between the two orders again (one more ACME order) (low, open) | — | none |
| Pane fetchers (cut-off, backoff) | memory | reset, so a hostile silo is asked again at once (low, open) | — | `panes_internal_test` |

## Moves, drains, fencing

| State | Where | (a) / (b) | (c) | (d) | Test |
|---|---|---|---|---|---|
| Handoff (`status.host`, `status.movingFrom`) | store, one CAS | nothing to rebuild; each step is redone on the next reconcile, and Stop and Delete are idempotent | the old host releases only after its runtime says the silo is gone | — | `moves` truth tables, `TestMoves`, `TestDrainWaitsForTheOldHostToLetGo` |
| A Move whose new host is lost before the old host let go | store | movingFrom was cleared: two copies, or stuck forever on a volume (R-18) | — | — | `TestAMoveWhoseNewHostIsLostStillWaitsForTheOldOne` |
| A handoff whose old host is lost | store | never finishes: `PlanMove` refuses even with `--confirm-fenced`. Stuck but safe (open) | — | — | none |
| Agent `fenced`, `heldBack` | memory | recomputed every second; Stop called again | same | — | `fence_test` |
| Last contact (`worker.Contact`) | memory, wall clock | zero until a heartbeat succeeds. Zero meant never fence (R-19) | same | — | `TestARunWithNoContactYetStillFences` |
| Fence record `/run/kevaso-fence/record.json` | host tmpfs, atomic | read back; keeps the earlier run's last contact, so there is no fresh 30s | gone; the agent now counts from its own start (R-19) | — | `TestAgentWritesTheFenceRecord` |
| Fence applies? (control plane with a worker) | memory | undecided until contact; the earlier record's answer stands | gone: **no fence** on a control-plane-plus-worker host until it reaches its peers (open) | — | none |
| Watcher (`kevaso-fence.service`) state | memory | kills again (idempotent) | same | — | `TestWatcherKills` |
| Host lost, RecreateAfter | store (`lastHeartbeat`, the HostLost condition's time) | not reset | — | not reset | `host_test`, `silo_test` |
| Clocks across machines | heartbeat stamped by the host, judged by the leader; fence judged by the host | a host more than ~19s behind breaks the margin; more than ~34s runs two copies; a step on a cut-off host moves its fence by the step (open: design) | — | a leader whose clock is ahead acts early | `TestFenceTiming` assumes skew ≤ 4s |

## Control plane

| State | Where | (a) / (b) | (d) | Test |
|---|---|---|---|---|
| Leader lease | store (CAS); candidate state in memory, monotonic clock | the node the record names takes it back at once; others wait 15s after a kill | a new term builds fresh controllers and waits for in-flight reconciles; no term token on writes | `leader_test`, `sim_test` |
| Controller queues, assume caches, plugin "already ensured" caches | memory | rebuilt each term; a plugin that restarted within a term isn't asked again for 10 to 30 min (low, open) | same | `silo_test`, `ip/race_test` |
| Plugin registry | memory, filled only on the leader | followers see no plugin classes; admission can differ per node (open) | a node that lost leadership keeps stale plugins | none |
| Port leases, approvals | store, absolute times | no timer to rebuild. A gate waiting on an approval fails at any API error; the Approval stays Pending | — | `leases_test`, approvals tests |
| Leased load-balancer ports | plugin; closed only by the leader | open past their end while there is no leader (open) | — | none |
| Master key `kms/local.json` | disk | a missing file became a new key, silently, over sealed secrets (R-20) | — | `TestAControlPlaneWithSealedDataButNoMasterKeyRefusesToStart` |
| CA `pki/ca.key` | disk | a missing file becomes a new CA (every host certificate invalid; loud, not silent) (open) | — | `TestControlPlaneComesUpReadyAndIssuesAdminCredentials` |
| Join of a system node | token spent before the answer reaches the node | an answer lost leaves the node with a spent token and a learner in etcd (open) | — | `TestJoinRefusals` |
| etcd data, member TLS, SQLite migration | disk | TLS rewritten each start; migration restartable. A crash between "done" and the compaction: undetermined | — | `rotate_test`, `store_test` |
| Backups | `.backup-*` in the data dir | a kill leaks the snapshot folder (sealed; low, open) | — | backup tests |
| `kvoadm upgrade` midway | host | restarts kevasod only; `kevaso-fence.service` keeps the old binary. The binary is replaced with `install`, not a rename (handed off) | — | none |

## Findings

Ranked by damage. Fixed means a test failed first and passes now, in its own commit on `phase/restart-audit`.

| # | Damage | What | Status |
|---|---|---|---|
| R-5 | data loss | a torn `silo.json` (written in place) read as no silo; Create then removed the root LV and imaged a new one | fixed (atomic write); the runtime-side guard is R-15 |
| R-20 | data loss | a missing master key became a new one over sealed secrets | fixed |
| R-7 | data loss | a volume folder removed recursively while a stacked mount was still there | fixed |
| R-6 | data in the wrong place | a lost node-side mount was never made again; the silo wrote to the host's root disk | fixed |
| R-18 | run twice | a Move whose new host is lost mid-handoff cleared movingFrom | fixed |
| R-19 | run twice | no contact yet in a run (after a reboot) meant never fence | fixed |
| R-1 | exposed, and an outage | Install replaced the live firewall with the baseline on every restart and retry: anti-spoofing and every port gone for up to a minute | fixed |
| R-3 | exposed | a secret revoked while kevasod was down stayed in the running silo | fixed |
| R-13 | exposed | a lease that ends while kevasod is down stays open | handed off (bare-metal check) |
| R-14 | exposed or conflicting | pool /32s and announced addresses stay while kevasod is down, also after the silo is recreated elsewhere | handed off (bare-metal check) |
| R-2 | silently not applied | the first ruleset after a restart had no leases: open leases' connections reset | fixed |
| R-4 | silently not applied | silos reconciled before the grant cache synced: init steps without secrets, a container remade without them | fixed |
| R-8 | silently not applied | the ingress config was moved but never reloaded after a restart | fixed |
| R-9 | silently not applied | `daemon.json` written but dockerd never restarted: env secrets in the engine's config | fixed |
| R-10 | silently not applied | a cut egress CA switched injection off for good | fixed |
| R-11 | silently not applied | a cut mesh key kept the host off the mesh for good | fixed |
| R-12 | silently not applied | a failed ACME registration stopped all issuing | fixed |
| R-15 | data loss | an unreadable `silo.json` reads as an absent silo | handed off (skipped test) |
| R-16 | stuck | a VM Create killed halfway is never finished | handed off (skipped test) |
| R-17 | exposed (traffic to a silo not ready) | a restarted silo is routed before its readiness passes; its guest volumes may not be mounted again | handed off (skipped test) |

Rows marked "open" in the tables are lower in damage, or need a design decision (clock skew, fencing during a control-plane outage, the held ingress config). They are listed in the hand-over note for this branch.

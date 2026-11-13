//go:build metal

package e2e

// The owner's intended setup — a small cloud VM as the system node, this machine as its only
// worker — is NOT written here, on purpose. The cloud VM would have to come from the provider
// repository's helpers (kevaso.com/provider-linode/linodetest: Bed for the account and the run's
// tagged machines, Kit and Cluster for kvoadm and kvo against them), and core can't use them
// without importing the provider module (core must not depend on a provider; the provider
// depends on core). There is no command in the provider repository that makes a machine outside
// a test, so it can't be called as a program either. The test belongs in the provider
// repository's test/e2e, next to the helpers, gated by KEVASO_METAL_WITH_LINODE=1 and the same
// KEVASO_METAL_* variables (the metal machine through core's testbed/remote driver, which the
// provider module can import). What it would do:
//
//  1. Reset the metal machine to clean (remote.Driver.Reset, the checklist passing), and make one
//     Linode (Bed, tag kvt-mx-<run>, the smallest plan, Ubuntu 24.04). The provider tests accept a
//     throwaway Linode's host key on first use (Bed.SSHFlags); the metal machine keeps its pin.
//  2. kvoadm init on the Linode (control plane only, --external-ip its public IPv4, --store
//     etcd), then kvoadm host add on the metal machine with --install worker, --runtime
//     cloud-hypervisor --runtime docker, --external-ip KEVASO_METAL_EXTERNAL_IP (and
//     --internal-ip when set). The mesh joins over the external IPs (Reach()).
//  3. The model over two networks: a cloud-hypervisor silo on the metal worker with a port open
//     on [external] answers the test from the metal IP; its name answers from a silo with the
//     silo IP; kvo exec reaches it through the agent's tunnel to the Linode.
//  4. Placement: the Linode has no worker, so every silo lands on the metal machine; a silo
//     asking for a runtime only the Linode would have is Pending with the reason.
//  5. The fence where it acts: silos stay (Wait), moves (Recreate, docker) and vm (Wait,
//     cloud-hypervisor) on the metal worker; the metal machine cut off from the Linode (nft drop
//     to the Linode's IP on the metal machine, or kevasod stopped there) for longer than
//     fence.DefaultAfter: the fence record says fence: true, kevaso-fence stops moves within
//     fence.WorstStopped, and stay and vm keep running; with no other worker, moves is Pending
//     with the reason rather than started twice. The cut lifted: the host Ready again, moves
//     started again on it, stay and vm never restarted.
//  6. Control plane restart: systemctl restart kevasod on the Linode stops no silo on the
//     worker (start times unchanged), and the worker's agent reconnects by itself.
//  7. Clean up: the namespaces deleted, the Linode deleted by the Bed's sweep (by tag), and the
//     metal machine reset with its checklist.
//
// It must never be run by a session without the owner's go-ahead: it creates a cloud machine.

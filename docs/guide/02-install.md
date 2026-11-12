# 2 · Installing

This page sets up a control plane on one machine, in separate steps, each doing one thing. Nothing
here is magic: you'll make the SSH key yourself, check the machine's identity yourself, look before
anything changes, and only then install.

| Step | You do | Why |
|---|---|---|
| [1](#step-1--build-the-tools) | Build `kvo`, `kvoadm` and `kevasod` | No releases yet |
| [2](#step-2--make-an-ssh-key-for-kevaso) | Make an SSH key for Kevaso | So `kvoadm` never needs a password |
| [3](#step-3--put-the-key-on-the-machine) | Put its public half on the machine | So the machine lets that key in |
| [4](#step-4--write-down-the-machines-fingerprint) | Write down the machine's host-key fingerprint | So you know you're talking to *your* machine |
| [5](#step-5--check-the-machine) | `kvoadm check` | See what Kevaso finds before it changes anything |
| [6](#step-6--install-the-control-plane) | `kvoadm init` | Install the control plane, get your `kvo` access |
| [7](#step-7--let-the-machine-run-silos-optional) | `kvoadm host enable-worker` *(optional)* | Run silos on the same machine |

---

## Step 1 · Build the tools

From a checkout of this repository, on your computer:

```bash
go build -o bin/kvo ./cmd/kvo
```

```bash
go build -o bin/kvoadm ./cmd/kvoadm
```

`kevasod` runs on the machine, so build it for Linux and for the machine's CPU (`amd64` for x86_64,
`arm64` for ARM; step 5 tells you which):

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/kevasod-linux-amd64 ./cmd/kevasod
```

> **Why `CGO_ENABLED=0`?** It makes a static binary that runs on any Linux, with nothing to install
> next to it. The same file also becomes `kvo-guest` inside your VMs later.

---

## Step 2 · Make an SSH key for Kevaso

`kvoadm` logs in to your machines over SSH to install `kevasod`. Give it a key of its own, separate
from your everyday key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/kevaso_ed25519 -C "kevaso admin"
```

It asks for a **passphrase**: set one. You get two files:

| File | What it is | Who sees it |
|---|---|---|
| `~/.ssh/kevaso_ed25519` | The **private** key | Only you. Never copy it anywhere. |
| `~/.ssh/kevaso_ed25519.pub` | The **public** key | Every machine Kevaso manages |

> **Why a key, not a password?** A password can be guessed or phished, and it travels to the server
> each time. A key never leaves your computer: the machine only checks a signature made with it.
> **Why ed25519?** Short, fast, and what every current OpenSSH accepts.
> **Why its own key?** You can revoke it (remove one line on each machine) without touching your
> personal access, and you can tell Kevaso's logins apart in the machine's logs.
> **Why a passphrase?** If your laptop is stolen, the key file alone is useless. `kvoadm` takes the
> key from your `ssh-agent` if it's loaded there (`ssh-add ~/.ssh/kevaso_ed25519`), or asks for the
> passphrase once.

---

## Step 3 · Put the key on the machine

The machine has to accept the public key for the account `kvoadm` will use (`root`, or a user with
`sudo`, like `ubuntu` on most cloud images). Pick the way that matches how you got the machine:

**A · A cloud provider or VPS** — most let you paste a public key when you create the machine. Paste
the contents of:

```bash
cat ~/.ssh/kevaso_ed25519.pub
```

**B · A machine you can already log in to with a password** — copy the key over with OpenSSH:

```bash
ssh-copy-id -i ~/.ssh/kevaso_ed25519.pub root@203.0.113.10
```

This is the one time you type the password. Keep reading before you answer `yes` to the question it
asks: that's step 4.

Then check that the key works on its own:

```bash
ssh -i ~/.ssh/kevaso_ed25519 -o IdentitiesOnly=yes root@203.0.113.10 true && echo "the key works"
```

> **Prefer not to do this by hand?** `kvoadm init --password` logs in with the password once,
> installs a key of its own, turns password logins off and changes the root password. It's the
> same result, done for you, and it still asks you to confirm the machine first.

---

## Step 4 · Write down the machine's fingerprint

The first time you connect to a machine, SSH shows its **host key fingerprint**, something like
`SHA256:kVvp5Yv9fNU4r4yX2P7+O99SU45jwdxC60ylimGFta4`. This is the machine's identity. If someone
sits between you and the machine, the fingerprint won't match, and that's the only moment you can
notice.

So get the real fingerprint **from somewhere other than this network connection**:

| Where the machine is | Where to read the fingerprint |
|---|---|
| A cloud provider | Its web console (Linode *Lish*, a serial console…), running the command below |
| A box you can sit at | Its own keyboard and screen |
| Some providers | The boot log they show you, which prints the SSH host keys |

The command, on the machine itself:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Compare it with what `ssh` showed you in step 3. Same? Keep it: you'll give it to `kvoadm` as
`--host-key`, so it checks the machine for you every time.

> **Why bother?** Everything after this (the cluster's CA, your admin certificate, secrets) is
> trusted because this first connection was to the right machine.

---

## Step 5 · Check the machine

Before changing anything, look. `kvoadm check` logs in exactly the way `init` will, reads the
machine, and **changes nothing**:

```bash
bin/kvoadm check root@203.0.113.10 --ssh-key ~/.ssh/kevaso_ed25519 --host-key SHA256:kVvp5Yv9fNU4r4yX2P7+O99SU45jwdxC60ylimGFta4
```

```
root@203.0.113.10 (host key SHA256:kVvp5Yv9fNU4r4yX2P7+O99SU45jwdxC60ylimGFta4)

✓ operating system    Ubuntu 24.04.1 LTS
✓ CPU                 x86_64            build kevasod with GOARCH=amd64
✓ account             root
✓ systemd             yes
✓ openssl             yes
✓ KVM                 /dev/kvm          microVM silos (cloud-hypervisor, openshell) can run here
✓ size                4 CPUs, 7953 MiB memory, 71 GiB free
! SSH password login  on                anyone can try passwords: set PasswordAuthentication no once your key works

Ready for kvoadm init. Nothing was changed.
```

| Mark | Means |
|---|---|
| `✓` | Fine |
| `!` | Works, but read the note |
| `✗` | Fix it before `init` (it exits non-zero) |

> **Password logins on?** Now that your key works, turn them off: on the machine, put
> `PasswordAuthentication no` in `/etc/ssh/sshd_config.d/00-local.conf` and run
> `systemctl reload ssh`. Keep your current session open until a new key login works.

---

## Step 6 · Install the control plane

```bash
bin/kvoadm init root@203.0.113.10 --ssh-key ~/.ssh/kevaso_ed25519 --host-key SHA256:kVvp5Yv9fNU4r4yX2P7+O99SU45jwdxC60ylimGFta4 --kevasod bin/kevasod-linux-amd64 --name hv1 --cluster home
```

| Flag | Meaning |
|---|---|
| `--name hv1` | The host's name in Kevaso (default: its address with dashes) |
| `--cluster home` | The cluster's name, and the name of your `kvo` context |
| `--api-server URL` | Only if *you* reach the API at another address than the machine's (a tunnel, a DNS name) |
| `--address IP` | The address *other hosts* should use for this one, if not the SSH address |

What it does, in order (each line is printed as it happens):

1. **Connects** with your key, checking the host key against `--host-key`.
2. **Checks** the CPU matches the `kevasod` you built.
3. **Installs `kevasod`**, signed: `kvoadm` signs the binary with a key of its own
   (`~/.kevaso/signing.key`, made on first use), pins the public half on the machine
   (`/etc/kevaso/release.pub`) and the machine verifies the signature before installing to
   `/usr/local/bin/kevasod`. A binary changed on the way doesn't get installed.
4. **Starts the control plane** as `kevasod.service`. On first start it makes the cluster's
   private CA, its store, and the master key for secrets, all in `/var/lib/kevaso` (root only).
5. **Gets you an admin certificate**: the private key is made *on your computer*; only a signing
   request goes to the machine, which signs it through its root-only admin socket.
6. **Writes your `kvo` context** to `~/.kevaso/config.yaml`: the API address, the cluster CA (so
   `kvo` trusts only *this* cluster) and your certificate.
7. **Waits for the host to be Ready**, then prints the **recovery key**:

```
Recovery key for secrets (needed to restore a backup; shown only now, keep it offline):

    KVR1-3NQF-…
```

Put the recovery key in your password manager or on paper, **now**. It's shown once and never
again. [Secrets](07-secrets.md#the-master-key-and-the-recovery-key) explains what it's for.

Now try `kvo`:

```bash
bin/kvo get hosts
```

```
NAME   ADDRESS        REGION   COMPONENTS      RUNTIMES   AGE
hv1    203.0.113.10   -        control-plane   -          1m
```

---

## Step 7 · Let the machine run silos (optional)

A control plane alone runs no silos. For a one-machine cluster, let it be a worker too:

```bash
bin/kvoadm host enable-worker root@203.0.113.10 --ssh-key ~/.ssh/kevaso_ed25519 --host-key SHA256:kVvp5Yv9fNU4r4yX2P7+O99SU45jwdxC60ylimGFta4 --runtime cloud-hypervisor
```

`--runtime` picks what kind of silos it runs (repeat it for several; see [Runtimes](08-runtimes.md)):

| Runtime | Needs |
|---|---|
| `cloud-hypervisor` | KVM, and a volume group named `kevaso` for silo disks (or `--loop-storage 40G` to use a file, for trying things out) |
| `openshell`, `openshell-container` | KVM for the first; Docker for the second (installed for you) |
| `docker`, `podman` | Nothing special (installed for you) |

The worker installs its runtimes in the background (packages, Cloud Hypervisor, the Ubuntu image).
Watch it:

```bash
bin/kvo watch hosts
```

Wait for `cloud-hypervisor=Ready`. That's it: **[your first silo →](03-first-silo.md)**

> **One command, later.** `kvoadm init … --worker --runtime cloud-hypervisor` does steps 6 and 7
> together, and produces exactly the same setup. The steps are separate here so you can see each
> one.

---

## If something goes wrong

| Message | What to do |
|---|---|
| `host key mismatch` | The machine isn't the one you wrote down, or it was reinstalled. Check the fingerprint again (step 4). |
| `how should kvoadm log in?` | Give `--ssh-key PATH`, or `--password` to type it once. |
| `… has a passphrase: load it with ssh-add first` | Run `ssh-add ~/.ssh/kevaso_ed25519`, or run `kvoadm` in a terminal so it can ask. |
| `the host is aarch64 but --kevasod is built for x86_64` | Rebuild `kevasod` with the other `GOARCH` (step 1). |
| `host hv1 not Ready` | On the machine: `journalctl -u kevasod -n 50`. |

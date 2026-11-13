# Demo: your first silo (M3)

One Linux machine runs everything: the control plane and a worker that boots silos as Cloud
Hypervisor microVMs. Here the "machine" is a Lima VM on a Mac (Apple silicon, M3 or later, for
nested virtualization); any fresh Ubuntu 24.04 box with KVM works the same way.

About 15 minutes, most of it the worker installing its runtime (downloads, packages, the image).

## 0. Build

From a checkout of this repo:

```bash
go build -o bin/kvo ./cmd/kvo && go build -o bin/kvoadm ./cmd/kvoadm && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/kevasod-linux-arm64 ./cmd/kevasod
```

## 1. A machine

A Lima VM with nested virtualization, 4 CPUs, 6 GiB, 60 GiB disk:

```bash
limactl create --name=kevaso-demo --vm-type=vz --nested-virt --cpus=4 --memory=6 --disk=60 --mount-none --tty=false template:ubuntu-24.04 && limactl start kevaso-demo
```

## 2. `kvoadm init`: control plane + worker

`kvoadm` connects over SSH, checks the host key you pin, installs a signed `kevasod`, and writes your
`kvo` credentials to `~/.kevaso/config.yaml`. With `--worker` the same host also runs silos; the
silo disks come from a thin-LVM pool on a 40G loop file (real hosts use a disk).

```bash
eval "$(awk '/^ *(Hostname|Port|User|IdentityFile) /{gsub(/"/,"",$2); print "SSH_"toupper($1)"="$2}' ~/.lima/kevaso-demo/ssh.config)" && PIN=$(limactl shell kevaso-demo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}') && bin/kvoadm init "$SSH_USER@$SSH_HOSTNAME" --ssh-port "$SSH_PORT" --ssh-key "$SSH_IDENTITYFILE" --host-key "$PIN" --kevasod bin/kevasod-linux-arm64 --name hv1 --cluster demo --api-server https://127.0.0.1:6443 --worker --loop-storage 40G
```

(Lima forwards the VM's port 6443 to your Mac's 127.0.0.1:6443.)

```bash
bin/kvo watch hosts
```

hv1 is Ready; `cloud-hypervisor` shows each install step (packages, binaries, the ~600 MB image,
network, storage) and then `Ready`, about 5 minutes the first time. Ctrl-C, then all of it at once:

```bash
bin/kvo describe host hv1
```

## 3. The silo

```bash
bin/kvo apply -f examples/01-one-host.yaml
```

```bash
bin/kvo watch silos -n demo
```

Ctrl-C when it's Running. Everything about it, init steps and conditions included:

```bash
bin/kvo describe silo hello -n demo
```

What you see, in order: the scheduler places it on `hv1` (`phase: Scheduled`), the worker creates its
disk and VM, then each init step goes `Running` → `Done`, then `phase: Running` with an
`siloIP: 10.64.0.x` and the `Ready` condition.

## 4. Inside it

```bash
bin/kvo exec silo hello -n demo -- cat /root/hello
```

```bash
bin/kvo exec silo hello -n demo -- uname -a
```

```bash
echo 'piped in' | bin/kvo exec silo hello -n demo -- sh -c 'cat; exit 4'; echo "exit code $?"
```

`kvo exec` goes kvo → API server (TLS, your client certificate) → the host agent's **outgoing**
tunnel (hosts need no inbound port) → the silo.

## 5. How locked down is it?

```bash
limactl shell kevaso-demo sudo sh -c 'p=$(pgrep -f cloud-hypervisor/cloud-hypervisor | head -1); ps -o user= -p $p; grep -E "^(CapEff|NoNewPrivs|Seccomp):" /proc/$p/status'
```

The VMM runs as its own user `kevaso-vmm`, with no capabilities, no-new-privileges and a syscall
filter. Silos can reach the gateway and the internet but not each other.

## 6. Clean up

```bash
bin/kvo delete silo hello -n demo
```

The VM and its disk go away. Then remove the machine and the demo cluster's CA, keys and kvo context:

```bash
limactl delete -f kevaso-demo && rm -rf ~/.kevaso
```

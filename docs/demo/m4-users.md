# Demo: a second user who only sees their namespace (M4)

You're the admin of a one-host cluster; you invite **bob** into the `payments` namespace. Bob signs
in with `kvo login` (browser + a one-time invite code; the control plane is its own OIDC issuer
behind its private CA), works there, and can't see anything else. About 5 minutes.

Bob's side runs here too, in a second kvo config (`KVO_CONFIG`), as if on his laptop.

## 0. Build

```bash
go build -o bin/kvo ./cmd/kvo && go build -o bin/kvoadm ./cmd/kvoadm && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/kevasod-linux-arm64 ./cmd/kevasod
```

## 1. A machine and a control plane

```bash
limactl create --name=kevaso-demo --vm-type=vz --cpus=2 --memory=2 --disk=10 --mount-none --tty=false template:ubuntu-24.04 && limactl start kevaso-demo
```

```bash
eval "$(awk '/^ *(Hostname|Port|User|IdentityFile) /{gsub(/"/,"",$2); print "SSH_"toupper($1)"="$2}' ~/.lima/kevaso-demo/ssh.config)" && PIN=$(limactl shell kevaso-demo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}') && bin/kvoadm init "$SSH_USER@$SSH_HOSTNAME" --ssh-port "$SSH_PORT" --ssh-key "$SSH_IDENTITYFILE" --host-key "$PIN" --kevasod bin/kevasod-linux-arm64 --name hv1 --cluster demo --api-server https://127.0.0.1:6443
```

## 2. Two namespaces, a secret in one

```bash
printf 'apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: payments }\n---\napiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: secret-project }\n---\napiVersion: kevaso/v1\nkind: Silo\nmetadata: { name: ledger, namespace: secret-project }\nspec: { runtime: cloud-hypervisor, image: ubuntu-24.04, resources: { cpu: 1, memory: 1Gi } }\n' | bin/kvo apply -f -
```

## 3. Invite bob

```bash
bin/kvoadm users invite bob --namespace payments
```

It binds bob as `editor` in `payments` and prints two lines to send him: a `kvo login` command
(the server and the CA fingerprint to pin) and a one-time code (15 minutes).

## 4. Bob signs in (as on his laptop)

Copy the `kvo login …` line from step 3 and run it with Bob's own config in front:

```bash
export KVO_CONFIG=~/.kevaso-bob/config.yaml
```

```bash
bin/kvo login https://127.0.0.1:6443 --ca sha256:PASTE-FROM-STEP-3
```

Your browser opens a "Sign in to Kevaso" page on `http://127.0.0.1:…` (kvo relays it to the
cluster over the pinned TLS, so no certificate warning). Paste the `kvi_…` code. The terminal says
`signed in … as bob`. His tokens are in the macOS Keychain (`com.kevaso.kvo`), not in the file.

## 5. What bob can do

```bash
bin/kvo auth whoami
```

```bash
bin/kvo ns payments
```

```bash
printf '{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"api"},"spec":{"runtime":"cloud-hypervisor","image":"ubuntu-24.04","resources":{"cpu":1,"memory":"1Gi"}}}' | bin/kvo apply -f -
```

```bash
bin/kvo get silos
```

```bash
bin/kvo get ns
```

Only `payments`.

## 6. What bob can't

```bash
bin/kvo get silos -n secret-project
```

```bash
bin/kvo get hosts
```

```bash
bin/kvo auth can-i create silos/exec; bin/kvo auth can-i delete silo/ledger -n secret-project
```

`Forbidden`, with the reason (`no role lets bob list silos in namespace secret-project`), and
`yes` / `no` for the two questions.

## 7. Back to the admin

```bash
unset KVO_CONFIG
```

```bash
bin/kvoadm users list
```

```bash
bin/kvoadm users disable bob
```

Bob's next command fails at once (`Unauthorized: session ended`):

```bash
KVO_CONFIG=~/.kevaso-bob/config.yaml bin/kvo get silos
```

## 8. The audit log

```bash
limactl shell kevaso-demo sudo tail -n 8 /var/lib/kevaso/audit.log
```

Every decision about people, allowed or denied, with the reason: bob's sign-in, his create in
`payments`, the refusals, the disable.

## 9. Clean up

```bash
KVO_CONFIG=~/.kevaso-bob/config.yaml bin/kvo logout; limactl delete -f kevaso-demo && rm -rf ~/.kevaso ~/.kevaso-bob
```

# Demo: a key that works in a silo but never enters it (M7)

One host (control plane + worker). You put an API key in a `Secret`, a `Grant` says the egress
gate adds it to requests for one host, and a silo uses the API without ever holding the key. Then
the same silo gets a password over its own vsock channel, signs with a key that stays outside, and
follows a rotation. About 15 minutes, most of it the first boot.

The API is [httpbin.org](https://httpbin.org/headers): it echoes the headers it got, so you can see
the gate's work. (That echo is httpbin's doing; a real API doesn't send your key back.)

## 0. Build

```bash
go build -o bin/kvo ./cmd/kvo && go build -o bin/kvoadm ./cmd/kvoadm && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/kevasod-linux-arm64 ./cmd/kevasod
```

## 1. A machine, a control plane and a worker

```bash
limactl create --name=kevaso-demo --vm-type=vz --nested-virt --cpus=4 --memory=6 --disk=60 --mount-none --tty=false template:ubuntu-24.04 && limactl start kevaso-demo
```

```bash
eval "$(awk '/^ *(Hostname|Port|User|IdentityFile) /{gsub(/"/,"",$2); print "SSH_"toupper($1)"="$2}' ~/.lima/kevaso-demo/ssh.config)" && PIN=$(limactl shell kevaso-demo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}') && bin/kvoadm init "$SSH_USER@$SSH_HOSTNAME" --ssh-port "$SSH_PORT" --ssh-key "$SSH_IDENTITYFILE" --host-key "$PIN" --kevasod bin/kevasod-linux-arm64 --name hv1 --cluster demo --api-server https://127.0.0.1:6443 --worker --loop-storage 40G
```

At the end it prints a **recovery key** (`KVR1-…`), once. It's what restores secrets from a backup;
for the demo you can let it go.

## 2. Secrets, from stdin (never on the command line)

```bash
printf 'apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: dev }\n' | bin/kvo apply -f - && printf 'demo-key-123' | bin/kvo create secret api-key -n dev --from-file - --allow inject --write-only && printf 's3cret-pw' | bin/kvo create secret db-password -n dev --from-file - && bin/kvo create secret validator-key -n dev --type ed25519 --generate
```

```bash
bin/kvo get secrets -n dev
```

`api-key` is write-only and may only be injected; `validator-key` was made on the server, and
nobody, not even you, can read it.

```bash
bin/kvo get secret api-key -n dev --reveal
```

Refused: write-only.

## 3. Grants and a silo

```bash
printf 'apiVersion: kevaso/v1\nkind: Grant\nmetadata: { name: httpbin, namespace: dev }\nspec:\n  secrets:\n    - { name: api-key, deliver: inject, to: { host: httpbin.org } }\n---\napiVersion: kevaso/v1\nkind: Grant\nmetadata: { name: app, namespace: dev }\nspec:\n  secrets:\n    - { name: db-password }\n    - { name: db-password, deliver: file, path: /run/secrets/db }\n  operations:\n    sign: { keyRef: validator-key }\n---\napiVersion: kevaso/v1\nkind: Silo\nmetadata: { name: agent, namespace: dev }\nspec:\n  runtime: cloud-hypervisor\n  vm: { image: ubuntu-24.04 }\n  resources: { cpu: 1, memory: 1Gi }\n  disk: { size: 10Gi }\n  grants: [httpbin, app]\n' | bin/kvo apply -f -
```

```bash
bin/kvo describe grant httpbin -n dev
```

It says which tier each secret uses: injection, here.

```bash
bin/kvo watch silos -n dev
```

Wait for `phase=Running` (Ctrl-C to stop watching).

## 4. The key works, and isn't there

```bash
bin/kvo exec silo agent -n dev -- curl -s https://httpbin.org/headers
```

`"Authorization": "Bearer demo-key-123"`: the gate on the host added it.

```bash
bin/kvo exec silo agent -n dev -- curl -s -H 'Authorization: Bearer stolen' https://httpbin.org/headers
```

Still `demo-key-123`: what the silo sends is replaced.

```bash
bin/kvo exec silo agent -n dev -- sh -c 'env | grep -c demo-key; grep -rl demo-key-123 /etc /root /home /run 2>/dev/null | wc -l'
```

`0` and `0`: the key isn't in the silo's environment or files.

```bash
bin/kvo exec silo agent -n dev -- curl -s --max-time 5 https://example.com
```

Nothing: no grant names example.com, and silos reach nothing outside without one.

## 5. The local endpoint, and a file the host wrote

```bash
bin/kvo exec silo agent -n dev -- sh -c 'curl -sS -H "Kevaso-Local: 1" http://169.254.42.1/v1/secrets/db-password; echo; cat /run/secrets/db; echo; curl -sS -H "Kevaso-Local: 1" http://169.254.42.1/v1/secrets/api-key'
```

The password twice (asked for, and as a tmpfs file the host wrote), then
`{"error":"no secret \"api-key\" for this silo"}`: injected secrets never come into the silo.

```bash
bin/kvo exec silo agent -n dev -- sh -c "printf 'transfer 10 to alice' | curl -sS -H 'Kevaso-Local: 1' --data-binary @- http://169.254.42.1/v1/sign/validator-key"
```

A signature; the key stayed on the control plane.

## 6. Rotate, once

```bash
printf 'demo-key-456' | bin/kvo secret set api-key -n dev --from-file - && sleep 2 && bin/kvo exec silo agent -n dev -- curl -s https://httpbin.org/headers
```

`demo-key-456` on the next request; nothing changed inside the silo.

## 7. The recovery key leaked

```bash
eval "$(awk '/^ *(Hostname|Port|User|IdentityFile) /{gsub(/"/,"",$2); print "SSH_"toupper($1)"="$2}' ~/.lima/kevaso-demo/ssh.config)" && bin/kvoadm kms rotate "$SSH_USER@$SSH_HOSTNAME" --ssh-port "$SSH_PORT" --ssh-key "$SSH_IDENTITYFILE" --host-key "$(limactl shell kevaso-demo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')" --new-recovery-key
```

A new master key and a new recovery key, printed once: the old recovery key opens nothing backed
up from now on. The secrets didn't change, and the silo didn't notice:

```bash
bin/kvo exec silo agent -n dev -- curl -sS -H 'Kevaso-Local: 1' http://169.254.42.1/v1/secrets/db-password
```

## 8. Clean up

```bash
limactl delete -f kevaso-demo && rm -rf ~/.kevaso
```

# What a worker reads

Inventory of every control-plane read made with a host certificate by the worker side, taken before
the read rule in this file's design section. There is no field selector and no label selector on
`client.List` or `client.Watch`: a call is one kind, and either one namespace or all of them
(`namespace ""`). Every informer below is `informer.New`, which lists all namespaces and then
watches them. Secret values are not in these objects; a value is a different request, and a host
is already refused it except a ClusterSecret value with `?for=PLUGIN`.

A system node's controllers, and the mesh agent on a system node, use kevasod's own component
client, not a host certificate. They are not in this inventory. The worker on a system node is:
`workerClient` authenticates as that host with role `worker`, and it makes the same reads as a
worker-only host.

## Callers that do not read the API

| Caller | What it does instead |
| --- | --- |
| `internal/fence`, `kevasod fence-watch` | `runtime.List` of silos on this machine. No client. |
| `internal/gate` | No client. `internal/worker`'s egress gate holds the client and calls the broker. |
| `internal/ingress` | Renders and applies a desired state the agent already fetched. No client. |
| `builtin/kni` | Pure rules from the view `internal/worker` built. No client. |
| `builtin/kri` (cloud-hypervisor, container, docker, podman, hostexec, openshell) | No client. OpenShell and cloud-hypervisor installers HTTP GET a release tarball, not this API. |
| Plugin node sides (`sdk/kplugin`, `internal/plugins.Registry`) | A local socket (`DIR/NAME/node.sock`). They do not use the host's client. |
| Local endpoint (`internal/agent/endpoint.go`) | Silos call it on the bridge. It POSTs `/agent/broker`. It does not list or get objects. |

## Kind reads

| Where | Call | Kind | Namespace | What it is for | Objects it actually uses |
| --- | --- | --- | --- | --- | --- |
| `internal/worker.RunNetworkWith` | list, watch | Silo | all | Rebuild the firewall, DNS, and egress denylist on every change | Every silo with an address, so `allowFrom` can name a caller on another host (`kni.Host.All`). This host's own silos, in full (ports, grants, egress, routeWhen). DNS answers every silo's name (`names.View`). The egress gate treats every silo's addresses as cluster-internal so a grant cannot be used to reach them. |
| `internal/worker.RunNetworkWith` | list, watch | Host | all | This host's addresses, and DNS and the egress denylist | Its own Host (internal, external, mesh, DNS listeners). Every Host's internal, external, and mesh address, so a granted name must not resolve to a cluster address. DNS of host names. |
| `internal/worker.RunNetworkWith` | list, watch | Grant | all | Egress rules and the gate's policy for silos on this host | Grants named by `spec.grants` of silos placed here (`v1.GrantsFor`). Grants of silos elsewhere are not read. |
| `internal/worker.RunNetworkWith` | list, watch | Secret | all | Drop the gate's cached injections when a secret changes | The cache is not read. A change of a secret named by a grant of a silo here invalidates injections; the value is fetched with POST `/agent/broker` (`OpInjections`), which the server already limits to silos on this host. |
| `internal/worker.RunNetworkWith` | list, watch | Service | all | DNAT to cluster IPs, node ports, DNS, egress denylist | Every Service that has endpoints: cluster IP, ports, endpoint addresses, which endpoints are on this host. DNS of service names. Every Service's cluster and load-balancer address for the denylist. |
| `internal/worker.RunNetworkWith` | list, watch | Ingress | all | Open a backend port to the ingress controller, as if `allowFrom` named it | Ingresses whose backend is a silo on this host (the silo's own service, or a Service that selects it). The controller silo may be on another host; its name comes from the IngressClass and its address from the Silo list. Ingresses that do not target a silo here are not used. |
| `internal/worker.RunNetworkWith` | list, watch | IngressClass | all | Which silo runs the proxy for those Ingresses | Every class, matched with `Controller.Runs` against the Silo list. A class is small (driver, options, which silo or silo set runs it). Certificates are not on the class. |
| `internal/worker.RunNetworkWith` | list, watch | Lease | all | Close a leased port when its lease is not open | Leases whose silo and silo UID are a silo on this host (`leases.For`). The firewall closes the port at `status.until` even if the API has not said so yet. |
| `internal/worker.Run`, heartbeat, `Join` | get | Host | cluster | Wait for this host's subnet, publish worker status, beat | This host's own Host only (`cfg.HostName`). |
| `internal/worker.reportHost`, `reportPortRules` | get | Host, Silo | cluster, the silo's namespace | Read-modify-write of the SiloFirewall and PortRules conditions | This host, and silos placed here. |
| `internal/agent.Run` | list, watch | Silo | all | Reconcile silos placed here, and notice one leaving | Silos with `status.host` equal to this host: spec, status, volumes, grants. A silo whose host changes is stopped here. Resync and garbage collection look at the same cache. |
| `internal/agent.watchDeletes` | list, watch | Silo | all | A separate watch, from now: only a delete seen on it may remove a disk | The delete event. `mayHaveHere` keeps it only when the deleted object was placed or moving here, or a runtime still lists it. |
| `internal/agent` status, volumes, `mayRemove` | get | Silo | the silo's namespace | Read-modify-write of status; decide whether a local copy may be deleted | The silo this host is acting on. `mayRemove` also gets a silo that is now placed on another host: that is how it tells a handoff (`status.movingFrom` is this host, the disk may go) from "placed on X with no handoff" (the disk stays). The kept-copy message on the Host is that sentence. |
| `internal/agent.Run` | list, watch | Grant | all | Deliver files and env, apply a runtime policy, fan out a grant change | Grants named by silos placed here. |
| `internal/agent.Run` | list, watch | OpenShellPolicy | all | Apply a runtime policy and fan out a policy change | OpenShellPolicies named by `spec.openshellPolicies` of silos placed here. |
| `internal/agent.Run` | list, watch | Secret | all | Fan out a secret change onto the silos here that receive it | The object is not read (no value is in it). The handler looks at grants to see which local silos name the secret. |
| `internal/agent.runIngress` | list, watch | IngressClass | all | Find controller silos on this host and report their status | Classes for which `Controller.Runs` is true of a silo here. |
| `internal/agent` ingress report | get | IngressClass | cluster | Read-modify-write of this silo's entry in the class status | The class that silo runs. |
| `internal/agent.RunTunnels` | list | Host | cluster | One dial-out tunnel per system node that serves the API | Every Host's `spec.components.controlPlane` and `status.controlPlane.apiURL`. |
| `internal/agent` fence record, watermark | get | Host | cluster | Record contact and whether this host is fenced | This host's own Host. |
| `internal/agent.RunClusterSecrets` | list, watch | ClusterSecret | cluster | Notice a rotation (`status.version`) and a delete | Allowed for a host certificate. The object is metadata and status; it never carries a value. A seen delete removes the host's file. |
| `internal/mesh.Agent` on a worker | list, watch | Host | cluster | Build this host's WireGuard peers | Every Host that has a mesh index and a public key: keys, endpoints, NAT, index, subnet. |
| `internal/mesh.Agent` | get | Host | cluster | Publish this host's public keys | This host's own Host. |
| System node (`controlplane.Run` → `RunClusterSecrets`) | list, watch, get value | ClusterSecret | cluster | Same delivery, as host role `control-plane`. With a worker on the same node, this loop delivers the controller side and the worker delivers the node side | GET `.../clustersecrets/NAME/value?for=PLUGIN&side=node\|controller` is allowed when the service account of that side (`plugin-PLUGIN` or `plugin-PLUGIN-node`) in `kevaso-system` may read that name. A worker certificate may ask only for `side=node`. |

`cmd/kevasod` does not read objects itself. `kevasod worker` builds the host client and calls `worker.Run`, `worker.Heartbeat`, and `mesh.Agent.Run`. `kevasod control-plane` starts the same worker when `--worker` is set, on `workerClient`.

## Reads that are not a kind

| Where | Call | What it is for | What the server already checks |
| --- | --- | --- | --- |
| `internal/agent` deliver, policy, pull; `internal/worker` egress; local endpoint | POST `/agent/broker` | Secret values, signatures, pull credentials, port open and close, pane reports | The silo is placed on this host, and one of its grants allows the operation. |
| `internal/agent` ingress loop | GET `/agent/ingress?namespace=&name=` | Routes, certificates (keys included), and challenges for one controller silo | The silo is placed on this host and runs the class. |
| `internal/agent.fetchClusterSecret` | GET `/apis/kevaso/v1/clustersecrets/NAME/value?for=PLUGIN&side=node\|controller` | The plugin's credential file | The service account of that side may read that name. A worker certificate may ask only for the node side. |

## Kinds nothing on the worker reads

Role, RoleBinding, ClusterRole, ClusterRoleBinding, Namespace, IP, Issuer, Certificate, VMImage,
SiloSet, Approval, Pane, KindDefinition, ValidationPolicy, MutationPolicy, Plugin, ServiceAccount,
and any kind defined at runtime.

Pane documents are not read. The agent asks the silo for its panes and POSTs them to the broker;
the control plane writes the Pane. Approval objects are not read. The broker's answer carries a
pending approval's name. Volumes are not a kind: they are fields of the Silo. A lease is the Lease
kind above; the silo asks for one through the broker.

## The rule

A host certificate with role `worker` may read the following on GET, list and watch. Role
`control-plane` is unchanged: a system node uses it, and it is not a worker certificate. Writes are
unchanged: a worker's own Host status, the status of silos placed on it (including a volume it is
letting go of), and an IngressClass's status for controller silos on it.

A silo is on the worker when `status.host` is that host or `status.movingFrom` is that host. The
second one is the move: the host the silo is leaving and the host it is going to both still run it,
so both read what it needs. The server decides this from the stored Silo objects (the same records
placement writes). There is no separate index.

| Kind | Scope | Why this wide, and no wider |
| --- | --- | --- |
| Host | Cluster-wide | The mesh builds peers from every host's keys and endpoints. Tunnels dial every system node's API address. DNS answers host names. The egress denylist is every host address. |
| Silo | Cluster-wide | Three callers need silos that are not placed here, and the API returns a whole object, so the kind is cluster-wide. `allowFrom` names a caller on another host and needs its address. DNS answers every silo's name, and a service's host port is answered from the silo. The egress denylist is every silo's addresses: a hole there would let a grant reach another silo. `mayRemove` reads a silo that has moved away, to tell a handoff (the disk may go) from "placed on X with no handoff" (the disk stays). The server cannot see which copies a runtime still has, so it cannot narrow this to "silos you still hold". |
| Service | Cluster-wide | Every worker DNATs to every service's endpoints, answers service names, and treats every service address as cluster-internal. |
| IngressClass | Cluster-wide | A class does not change when a silo is placed, so a watch filtered to "classes whose controller is here" would hide a class that already existed. A class is the driver, its options, and which silo runs it. Certificate keys are not on it; they come from GET `/agent/ingress`. |
| Grant | On this host | Named by `spec.grants` of a silo on this host, in that silo's namespace. |
| OpenShellPolicy | On this host | Named by `spec.openshellPolicies` of a silo on this host, in that silo's namespace. |
| Secret | On this host | Metadata only. A value stays refused (403 on `…/value`); the broker delivers values for silos on this host. The secret is named by a grant of a silo on this host (`Grant.SecretNames`, which includes a signing key), or it is that silo's `container.pull.secretRef`. A namespace's default pull secret is not included: the worker never reads that object; the broker resolves it when the silo pulls. An Ingress's TLS secret is not included: it arrives through GET `/agent/ingress`. |
| Lease | On this host | `spec.silo` and `spec.siloUID` are a silo on this host, in that silo's namespace. |
| Ingress | On this host | A rule's backend is a silo on this host: the silo's own service, or a Service that selects it (`ingress.Targets`). An ingress that only targets silos elsewhere is not returned. The controller's certificate material is not on the Ingress. |
| Anything else | Never | Namespace, Role, RoleBinding, ClusterRole, ClusterRoleBinding, IP, Issuer, Certificate, VMImage, SiloSet, Approval, Pane, KindDefinition, ValidationPolicy, MutationPolicy, Plugin, ServiceAccount, ClusterSecret, and any kind defined at runtime. List and watch of these are refused, not returned empty. ClusterSecret is the rule it already had: a host has no clustersecret access of its own; GET `…/value?for=PLUGIN` is unchanged. |

Subresources that are not an object read stay refused, as they were: a secret's value, exec, token, move, ssh, files, opening or closing a lease, answering an approval, a pane's bundle.

List and watch of a related kind return 200 and only the objects the rule allows. An empty page is an empty list, not a 403, so a worker's informer still starts in a namespace where nothing is placed. GET of one object that exists and is outside the rule is 403. GET of one that does not exist is 404.

A watch does not replay an object's earlier revisions from before it was on this host. When the relationship appears, the current object is sent once. When it ends, the watch says the object was deleted and does not send a later state the host is no longer allowed to see. History from before the link is not sent. A client that listed first and watches from that revision is not sent the objects it already has.

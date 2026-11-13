package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"kevaso.com/core/api/meta"
)

// Images, sets and standalone services (design §0.2, §0.4, §7.1).

// ── Image ────────────────────────────────────────────────────────────────────

// Image is a named base ("seed") with immutable versions: what silos and sets start from
// (`image: geth-node:v1`). Each version says where its bits are for each runtime family: an OCI
// reference for container runtimes and OpenShell, a disk image (URL and SHA-256) for
// cloud-hypervisor. A version never changes once added, so an instance on v1 always runs the same
// thing; a new release is a new version. Namespaced.
type Image struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            ImageSpec `json:"spec"`
}

// ImageSpec lists the versions, oldest first: a reference without a version gets the last.
type ImageSpec struct {
	Versions []ImageVersion `json:"versions"`
}

// ImageVersion is one immutable version.
type ImageVersion struct {
	Name string `json:"name"` // e.g. v1
	// Container is an OCI reference (pin it by digest to make it truly immutable).
	Container string     `json:"container,omitempty"`
	Disk      *ImageDisk `json:"disk,omitempty"`
}

// ImageDisk is a bootable disk image, checked against its hash when a host fetches it.
type ImageDisk struct {
	URL    string `json:"url"` // https://
	SHA256 string `json:"sha256"`
}

// DiskRef is how a disk image reaches the runtime: its URL with the hash it must have.
func DiskRef(d ImageDisk) string { return d.URL + "#sha256=" + strings.ToLower(d.SHA256) }

// SplitImage splits NAME[:VERSION]. A registry reference with a port ("host:5000/x") has a slash
// after the colon, so it's never split.
func SplitImage(ref string) (name, version string) {
	i := strings.LastIndex(ref, ":")
	if i < 0 || strings.Contains(ref[i:], "/") {
		return ref, ""
	}
	return ref[:i], ref[i+1:]
}

// ResolveImage turns a silo's spec.image into what its runtime gets. An Image of that name in
// the silo's namespace wins (its version, or its newest); anything else is used as it is (Kevaso's
// built-in names like ubuntu-24.04, or an OCI reference). images are the namespace's Images.
func ResolveImage(spec, runtime string, images []*Image) (string, error) {
	name, version := SplitImage(spec)
	var img *Image
	for _, i := range images {
		if i.Name == name {
			img = i
		}
	}
	if img == nil {
		return spec, nil
	}
	if len(img.Spec.Versions) == 0 {
		return "", fmt.Errorf("image %s has no versions", name)
	}
	v := img.Spec.Versions[len(img.Spec.Versions)-1]
	if version != "" {
		found := false
		for _, x := range img.Spec.Versions {
			if x.Name == version {
				v, found = x, true
			}
		}
		if !found {
			return "", fmt.Errorf("image %s has no version %s", name, version)
		}
	}
	if runtime == "cloud-hypervisor" {
		if v.Disk == nil {
			return "", fmt.Errorf("image %s:%s has no disk image, which %s needs", name, v.Name, runtime)
		}
		return DiskRef(*v.Disk), nil
	}
	if v.Container == "" {
		return "", fmt.Errorf("image %s:%s has no container image, which %s needs", name, v.Name, runtime)
	}
	return v.Container, nil
}

// ── SiloSet ──────────────────────────────────────────────────────────────────

// SiloSet is a VMSS-style set of stateful silos from one image (design §0.2): instances with
// stable names (NAME-0, NAME-1, …), each its own Silo, kept until scaled in or deleted. Nothing is
// killed to "heal": an instance is restarted in place on its disk; you decide when to reset it.
// Namespaced.
type SiloSet struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            SiloSetSpec   `json:"spec"`
	Status          SiloSetStatus `json:"status,omitempty"`
}

// SiloSetSpec is the set's shape.
type SiloSetSpec struct {
	// Image every instance starts from (it overrides template.image).
	Image     string `json:"image,omitempty"`
	Instances int    `json:"instances"`
	// Standby: extra instances booted and kept idle, ready to hand out (warm pools for runs).
	// They carry kevaso.com/standby=true, so no Service selects them.
	Standby int `json:"standby,omitempty"`
	// Spread: keep instances on different hosts (zones, regions) where possible.
	Spread   string       `json:"spread,omitempty"` // host | zone | region
	Template SiloTemplate `json:"template"`
	// UpgradePolicy: Manual (default: a new image or template reaches new instances, and existing
	// ones when you reset them) or Rolling (instances are reset onto it, a few at a time).
	UpgradePolicy string        `json:"upgradePolicy,omitempty"`
	Update        SiloSetUpdate `json:"update,omitempty"`
	// ScaleInPolicy: NewestFirst (default) or OldestFirst. Protected instances are never removed.
	ScaleInPolicy string `json:"scaleInPolicy,omitempty"`
	// Reset, when it changes, resets every instance onto the current image, rolling
	// (`kvo reset siloset --rolling`), whatever the upgrade policy.
	Reset string `json:"reset,omitempty"`
}

// SiloTemplate is each instance's Silo spec, plus its labels.
type SiloTemplate struct {
	Labels   map[string]string `json:"labels,omitempty"`
	SiloSpec                   // inline
}

// SiloSetUpdate is how a rollout goes. With exclusive instances it's always one at a time,
// stop-first (maxSurge 0): never two copies.
type SiloSetUpdate struct {
	// Strategy: StopFirst (default: take instances down to update them, maxUnavailable at a time)
	// or StartFirst (start maxSurge extra instances on the new image first, so the set never has
	// fewer ready instances than it asks for).
	Strategy       string `json:"strategy,omitempty"`
	MaxUnavailable *int   `json:"maxUnavailable,omitempty"` // default 1
	MaxSurge       *int   `json:"maxSurge,omitempty"`       // default 0 (StartFirst: 1)
}

// Upgrade and scale-in policies.
const (
	UpgradeManual  = "Manual"
	UpgradeRolling = "Rolling"
	NewestFirst    = "NewestFirst"
	OldestFirst    = "OldestFirst"
)

// Labels a set puts on its instances.
const (
	LabelSiloSet   = "kevaso.com/siloset"
	LabelRevision  = "kevaso.com/revision"
	LabelStandby   = "kevaso.com/standby"
	LabelProtected = "kevaso.com/protected" // "true": never removed by scale-in (kvo protect)
)

// SiloSetStatus is the set as its controller sees it.
type SiloSetStatus struct {
	ObservedGeneration int64            `json:"observedGeneration,omitempty"`
	Revision           string           `json:"revision,omitempty"` // of the current template and image
	Instances          int              `json:"instances"`          // that exist (standby included)
	Ready              int              `json:"ready"`
	Updated            int              `json:"updated"` // on the current revision
	Standby            int              `json:"standby,omitempty"`
	Conditions         []meta.Condition `json:"conditions,omitempty"`
}

// Limits returns the rollout's maxUnavailable and maxSurge, with their defaults.
func (s *SiloSet) Limits() (unavailable, surge int) {
	unavailable, surge = 1, 0
	if s.Spec.Update.Strategy == StartFirst {
		surge = 1
	}
	if p := s.Spec.Update.MaxUnavailable; p != nil {
		unavailable = *p
	}
	if p := s.Spec.Update.MaxSurge; p != nil {
		surge = *p
	}
	if s.Spec.Template.Exclusive {
		surge = 0
		if unavailable > 1 {
			unavailable = 1
		}
	}
	if unavailable < 1 && surge < 1 {
		unavailable = 1 // a rollout must be able to move
	}
	return unavailable, surge
}

// InstanceName is the name of the set's instance number i.
func InstanceName(set string, i int) string { return set + "-" + strconv.Itoa(i) }

// InstanceIndex is the number of one of set's instances (-1 if it isn't one).
func InstanceIndex(set, silo string) int {
	rest, ok := strings.CutPrefix(silo, set+"-")
	if !ok {
		return -1
	}
	i, err := strconv.Atoi(rest)
	if err != nil || i < 0 || strconv.Itoa(i) != rest {
		return -1
	}
	return i
}

// ── Service (standalone) ─────────────────────────────────────────────────────

// Service load-balances several silos (typically a SiloSet's instances) behind one virtual IP and
// name, NAME.NAMESPACE.kevaso (design §7.1). Its endpoints are the Ready silos its selector picks;
// every worker sends the virtual IP's ports to them (like kube-proxy). type LoadBalancer also gives
// it an outside address from a plugin's class. Single silos carry their own spec.service instead.
// Namespaced.
type Service struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            ServiceSpec   `json:"spec"`
	Status          ServiceStatus `json:"status,omitempty"`
}

// Service types.
const (
	ServiceClusterIP    = "ClusterIP"    // the default: a virtual IP on the mesh
	ServiceLoadBalancer = "LoadBalancer" // plus an outside address
)

// ServiceSpec is what the service selects and serves.
type ServiceSpec struct {
	Selector map[string]string `json:"selector"`
	Ports    []ServicePortSpec `json:"ports"`
	Type     string            `json:"type,omitempty"` // ClusterIP (default) | LoadBalancer
	// LoadBalancerClass: a plugin's class (e.g. linode-nodebalancer) for type LoadBalancer.
	LoadBalancerClass string `json:"loadBalancerClass,omitempty"`
}

// ServicePortSpec is one port: Port on the virtual IP goes to TargetPort on each endpoint (a
// port name of the silo's own service, or a number; default: the same port).
type ServicePortSpec struct {
	Name       string `json:"name"`
	Port       int    `json:"port"`
	TargetPort string `json:"targetPort,omitempty"`
	Protocol   string `json:"protocol,omitempty"` // TCP (default) | UDP
}

// ServiceStatus is where the service is and who serves it.
type ServiceStatus struct {
	ClusterIP string `json:"clusterIP,omitempty"`
	Name      string `json:"name,omitempty"` // NAME.NAMESPACE.kevaso
	// Endpoints are the Ready silos it sends to now.
	Endpoints []ServiceEndpoint `json:"endpoints,omitempty"`
	// For type LoadBalancer: the outside address, the node port each port arrives on at the
	// endpoints' hosts, and where the load balancer's traffic comes from.
	PublicIP     string           `json:"publicIP,omitempty"`
	NodePorts    []NodePort       `json:"nodePorts,omitempty"`
	SourceRanges []string         `json:"sourceRanges,omitempty"`
	Conditions   []meta.Condition `json:"conditions,omitempty"`
}

// ServiceEndpoint is one silo behind a service, with each service port's target there.
type ServiceEndpoint struct {
	Silo    string     `json:"silo"`
	Host    string     `json:"host"`
	Address string     `json:"address"`
	Ports   []NodePort `json:"ports"` // Name: the service port, Port: the service's, NodePort: the silo's target
}

// Selects reports whether a selector picks these labels (an empty selector picks nothing).
func Selects(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// TargetPort resolves a service port on one silo: by name among its own service's ports, or as a
// number (0 if it can't).
func TargetPort(p ServicePortSpec, s *Silo) int {
	t := p.TargetPort
	if t == "" {
		return p.Port
	}
	if n, err := strconv.Atoi(t); err == nil {
		return n
	}
	if s.Spec.Service != nil {
		for _, sp := range s.Spec.Service.Ports {
			if sp.Name == t {
				return sp.Port
			}
		}
	}
	return 0
}

// SortEndpoints orders endpoints by silo name (deterministic rules).
func SortEndpoints(eps []ServiceEndpoint) {
	sort.Slice(eps, func(i, j int) bool { return eps[i].Silo < eps[j].Silo })
}

// ServiceCIDR is where services' virtual IPs come from.
const ServiceCIDR = "10.65.0.0/16"

// Node ports: silos' own load balancers take theirs per host from NodePortMin…NodePortSiloMax;
// services take theirs cluster-wide above it, so the two never collide.
const NodePortSiloMax = 31999

// InstanceSpec is the Silo spec of each of the set's instances: the template, the set's image,
// its spread, and its reset.
func (s *SiloSet) InstanceSpec() SiloSpec {
	spec := s.Spec.Template.SiloSpec
	if s.Spec.Image != "" {
		spec.Image = s.Spec.Image
	}
	if s.Spec.Spread != "" {
		spec.Placement.Spread = &Spread{By: s.Spec.Spread, Selector: map[string]string{LabelSiloSet: s.Name}}
	}
	if s.Spec.Reset != "" {
		spec.Reset = s.Spec.Reset
	}
	return spec
}

// Revision identifies the set's current instance spec and labels: instances on another revision
// are due an update.
func (s *SiloSet) Revision() string {
	b, _ := json.Marshal(struct {
		Spec   SiloSpec          `json:"spec"`
		Labels map[string]string `json:"labels"`
	}{s.InstanceSpec(), s.Spec.Template.Labels})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:5])
}

// Instance is the set's instance number i as it should be now.
func (s *SiloSet) Instance(i int, standby bool) *Silo {
	labels := map[string]string{}
	for k, v := range s.Spec.Template.Labels {
		labels[k] = v
	}
	labels[LabelSiloSet], labels[LabelRevision] = s.Name, s.Revision()
	if standby {
		labels[LabelStandby] = "true"
	}
	return &Silo{
		TypeMeta: meta.TypeMeta{APIVersion: APIVersion, Kind: "Silo"},
		ObjectMeta: meta.ObjectMeta{Name: InstanceName(s.Name, i), Namespace: s.Namespace, Labels: labels,
			OwnerReferences: []meta.OwnerReference{{APIVersion: APIVersion, Kind: "SiloSet", Name: s.Name, UID: s.UID, Controller: true}}},
		Spec: s.InstanceSpec(),
	}
}

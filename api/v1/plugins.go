package v1

import (
	"slices"
	"time"

	"kevaso.com/core/api/meta"
)

// Plugin operators (design §4.2, §6; ADR 0006): a plugin package brings KindDefinitions, admission
// policies and the roles its controller needs, next to the controller itself. `kvoadm plugin
// install` applies them and records the install as a Plugin, which owns (owner references) what it
// installed; `kvoadm plugin uninstall` removes them.

// Plugin is an installed plugin operator. Cluster-scoped; its name is the package's.
type Plugin struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            PluginSpec   `json:"spec"`
	Status          PluginStatus `json:"status,omitempty"`
}

// PluginSpec is what was installed.
type PluginSpec struct {
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	// Controller is where the plugin's controller runs, and as whom.
	Controller *PluginController `json:"controller,omitempty"`
	// Owns is everything the install made (KindDefinitions, policies, roles, bindings, the service
	// account); each carries an owner reference to this Plugin.
	Owns []PluginObject `json:"owns,omitempty"`
}

// PluginController is a plugin's controller: the host whose systemd unit runs it, and the service
// account it runs as (in PluginNamespace).
type PluginController struct {
	Host           string `json:"host"`
	ServiceAccount string `json:"serviceAccount"`
}

// PluginObject names one object a plugin owns.
type PluginObject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// PluginStatus is what the plugin's controller reports about itself.
type PluginStatus struct {
	Controller PluginControllerStatus `json:"controller,omitempty"`
}

// PluginControllerStatus: the controller writes a heartbeat while it runs.
type PluginControllerStatus struct {
	Heartbeat *time.Time `json:"heartbeat,omitempty"`
	Version   string     `json:"version,omitempty"`
}

// PluginNamespace is where plugin controllers' service accounts live.
const PluginNamespace = "kevaso-system"

// PluginFinalizer holds a Plugin while `kvoadm plugin uninstall` removes what it owns.
const PluginFinalizer = "kevaso.com/plugin-uninstall"

// HeartbeatEvery is how often a plugin controller reports; one not heard from for three times
// that isn't running.
const HeartbeatEvery = 30 * time.Second

// Kinds are the resources (PLURAL.GROUP) of the KindDefinitions the plugin owns.
func (p *Plugin) Kinds() []string {
	var out []string
	for _, o := range p.Spec.Owns {
		if o.Kind == "KindDefinition" {
			out = append(out, o.Name)
		}
	}
	slices.Sort(out)
	return out
}

// Running reports whether the plugin's controller has reported recently.
func (p *Plugin) Running(now time.Time) bool {
	hb := p.Status.Controller.Heartbeat
	return hb != nil && now.Sub(*hb) < 3*HeartbeatEvery
}

// OwnerPlugin is the name of the Plugin an object belongs to ("" if none).
func OwnerPlugin(m *meta.ObjectMeta) string {
	for _, r := range m.OwnerReferences {
		if r.APIVersion == APIVersion && r.Kind == "Plugin" {
			return r.Name
		}
	}
	return ""
}

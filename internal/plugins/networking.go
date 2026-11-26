package plugins

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"kevaso.com/core/sdk/kplugin"
)

// Networking is what admission asks about providers at apply (networking v2): a provider is an
// installed plugin, by the name it was installed under (linode, linode-work). The Registry answers
// from what each registered plugin declared in Info; Static answers from a fixed map (tests).
type Networking interface {
	// ValidateServiceAnnotations checks a service's annotations in provider's domain
	// (PROVIDER.kevaso.com/…): one error per annotation it doesn't declare or whose value it
	// refuses, each naming the annotation and, for a misspelling, the one meant
	// (*kplugin.AnnotationError, joined). ErrNoProvider (wrapped) if no such provider is installed;
	// nil, unchecked, for a provider that declares nothing (built before sdk wire revision 2).
	ValidateServiceAnnotations(provider string, annotations map[string]string) error
	// ValidateIPAnnotations is the same for an IP of type Provider.
	ValidateIPAnnotations(provider string, annotations map[string]string) error
	// ValidateProviderIP checks that provider makes IPs of type Provider in region.
	ValidateProviderIP(provider, region string) error
	// ValidateLoadBalancer checks that provider makes balancers for services of type LoadBalancer.
	ValidateLoadBalancer(provider string) error
	// CanFrontWithIP says whether a kept Provider IP can front provider's balancers
	// (loadBalancer: { ip: NAME }).
	CanFrontWithIP(provider string) bool
	// KeepsClientIP says whether silos behind provider's balancers see the client's address.
	KeepsClientIP(provider string) bool
	// Reach is where provider's IPs and balancers reach silos (placement follows it).
	Reach(provider string) (Reach, error)
	// Providers are the installed providers' names, sorted.
	Providers() []string
}

// Reach is where a provider's IPs and balancers can reach a silo.
type Reach struct {
	// Scope is host, region or global (kplugin.FollowsHost, …).
	Scope string
	// Regions it serves; empty: any.
	Regions []string
	// OwnHostsOnly: only the provider's own machines (its workers).
	OwnHostsOnly bool
}

// ErrNoProvider: no provider of that name is installed (it may be on its way: a plugin restarting
// is held, not dropped, so this is a name nobody installed).
var ErrNoProvider = errors.New("no such provider")

// Static is a Networking over a fixed map of provider name → declaration (nil: declares nothing).
type Static map[string]*kplugin.Networking

func (s Static) declared(provider string) (*kplugin.Networking, error) {
	n, ok := s[provider]
	if !ok {
		names := make([]string, 0, len(s))
		for k := range s {
			names = append(names, k)
		}
		return nil, noProvider(provider, names)
	}
	return n, nil
}

// Providers implements Networking.
func (s Static) Providers() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidateServiceAnnotations implements Networking.
func (s Static) ValidateServiceAnnotations(provider string, a map[string]string) error {
	return validateAnnotations(s.declared, provider, kplugin.OnService, a)
}

// ValidateIPAnnotations implements Networking.
func (s Static) ValidateIPAnnotations(provider string, a map[string]string) error {
	return validateAnnotations(s.declared, provider, kplugin.OnIP, a)
}

// ValidateProviderIP implements Networking.
func (s Static) ValidateProviderIP(provider, region string) error {
	return validateProviderIP(s.declared, provider, region)
}

// ValidateLoadBalancer implements Networking.
func (s Static) ValidateLoadBalancer(provider string) error {
	return validateLoadBalancer(s.declared, provider)
}

// CanFrontWithIP implements Networking.
func (s Static) CanFrontWithIP(provider string) bool {
	n, err := s.declared(provider)
	return err == nil && n != nil && n.FrontWithIP
}

// KeepsClientIP implements Networking.
func (s Static) KeepsClientIP(provider string) bool {
	n, err := s.declared(provider)
	return err == nil && n != nil && n.KeepsClientIP
}

// Reach implements Networking.
func (s Static) Reach(provider string) (Reach, error) { return reach(s.declared, provider) }

// The Registry answers Networking from what its plugins declared.

var _ Networking = (*Registry)(nil)
var _ Networking = Static(nil)

func (r *Registry) declared(provider string) (*kplugin.Networking, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[provider]
	if !ok {
		names := make([]string, 0, len(r.plugins))
		for k := range r.plugins {
			names = append(names, k)
		}
		return nil, noProvider(provider, names)
	}
	return p.Info.Networking, nil
}

// Providers implements Networking: every registered plugin.
func (r *Registry) Providers() []string {
	var out []string
	for _, p := range r.All() {
		out = append(out, p.Info.Name)
	}
	return out
}

// ValidateServiceAnnotations implements Networking.
func (r *Registry) ValidateServiceAnnotations(provider string, a map[string]string) error {
	return validateAnnotations(r.declared, provider, kplugin.OnService, a)
}

// ValidateIPAnnotations implements Networking.
func (r *Registry) ValidateIPAnnotations(provider string, a map[string]string) error {
	return validateAnnotations(r.declared, provider, kplugin.OnIP, a)
}

// ValidateProviderIP implements Networking.
func (r *Registry) ValidateProviderIP(provider, region string) error {
	return validateProviderIP(r.declared, provider, region)
}

// ValidateLoadBalancer implements Networking.
func (r *Registry) ValidateLoadBalancer(provider string) error {
	return validateLoadBalancer(r.declared, provider)
}

// CanFrontWithIP implements Networking.
func (r *Registry) CanFrontWithIP(provider string) bool {
	n, err := r.declared(provider)
	return err == nil && n != nil && n.FrontWithIP
}

// KeepsClientIP implements Networking.
func (r *Registry) KeepsClientIP(provider string) bool {
	n, err := r.declared(provider)
	return err == nil && n != nil && n.KeepsClientIP
}

// Reach implements Networking.
func (r *Registry) Reach(provider string) (Reach, error) { return reach(r.declared, provider) }

type lookup func(provider string) (*kplugin.Networking, error)

func noProvider(provider string, installed []string) error {
	sort.Strings(installed)
	if len(installed) == 0 {
		return fmt.Errorf("provider %s: %w: none is installed (kvoadm plugin install)", provider, ErrNoProvider)
	}
	return fmt.Errorf("provider %s: %w: installed are %s", provider, ErrNoProvider, strings.Join(installed, ", "))
}

func validateAnnotations(get lookup, provider, on string, a map[string]string) error {
	n, err := get(provider)
	if err != nil {
		return err
	}
	if err := n.ValidateAnnotations(provider, on, a); err != nil {
		return fmt.Errorf("provider %s: %w", provider, err)
	}
	return nil
}

// undeclared is the error for a capability a plugin that declares nothing can't promise.
func undeclared(provider, what string) error {
	return fmt.Errorf("provider %s declares nothing about networking (built against an sdk before wire revision 2), so Kevaso can't tell whether it makes %s: upgrade the plugin", provider, what)
}

func validateProviderIP(get lookup, provider, region string) error {
	n, err := get(provider)
	if err != nil {
		return err
	}
	switch {
	case n == nil:
		return undeclared(provider, "IPs of type Provider")
	case !n.ProviderIPs:
		return fmt.Errorf("provider %s doesn't make IPs of type Provider", provider)
	case region == "":
		return fmt.Errorf("provider %s: an IP of type Provider needs a region%s", provider, among(n.Regions))
	case len(n.Regions) > 0 && !contains(n.Regions, region):
		return fmt.Errorf("provider %s doesn't serve region %s%s", provider, region, among(n.Regions))
	}
	return nil
}

func among(regions []string) string {
	if len(regions) == 0 {
		return ""
	}
	return " (one of " + strings.Join(regions, ", ") + ")"
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func validateLoadBalancer(get lookup, provider string) error {
	n, err := get(provider)
	if err != nil {
		return err
	}
	switch {
	case n == nil:
		return undeclared(provider, "load balancers")
	case !n.LoadBalancers:
		return fmt.Errorf("provider %s doesn't make load balancers (services of type LoadBalancer)", provider)
	}
	return nil
}

func reach(get lookup, provider string) (Reach, error) {
	n, err := get(provider)
	if err != nil {
		return Reach{}, err
	}
	if n == nil {
		return Reach{}, undeclared(provider, "IPs or load balancers")
	}
	scope := n.Reach
	if scope == "" {
		scope = kplugin.FollowsRegion
	}
	return Reach{Scope: scope, Regions: append([]string(nil), n.Regions...), OwnHostsOnly: n.OwnHostsOnly}, nil
}

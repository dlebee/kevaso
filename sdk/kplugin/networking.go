package kplugin

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Networking is what a plugin's provider does for services and IPs (networking v2), declared in
// Info so core can check a service against it at apply: whether it makes Provider IPs and load
// balancers, whether a kept IP can front a balancer, whether the client's address survives, where
// its addresses reach silos, and the annotations it accepts. A nil Networking (a plugin built
// before sdk wire revision 2) declares nothing: core can't check its annotations and leaves them to
// the plugin.
type Networking struct {
	// ProviderIPs: it makes IPs of type Provider (an address reserved from the provider).
	ProviderIPs bool `json:"providerIPs,omitempty"`
	// LoadBalancers: it makes balancers for services of type LoadBalancer.
	LoadBalancers bool `json:"loadBalancers,omitempty"`
	// FrontWithIP: a kept Provider IP can front one of its balancers (loadBalancer: { ip: NAME }).
	// Without it the balancer has its own address (a Linode NodeBalancer).
	FrontWithIP bool `json:"frontWithIP,omitempty"`
	// KeepsClientIP: the silo sees the client's address behind its balancers.
	KeepsClientIP bool `json:"keepsClientIP,omitempty"`
	// Reach is where its IPs and balancers can reach a silo: host, region (the default, "") or
	// global (the Follows values). A silo using them is placed within it.
	Reach string `json:"reach,omitempty"`
	// Regions are the regions it serves (an IP's region must be one); empty: any.
	Regions []string `json:"regions,omitempty"`
	// OwnHostsOnly: only its own machines (DescribeHosts) can be behind its IPs and balancers.
	OwnHostsOnly bool `json:"ownHostsOnly,omitempty"`
	// Annotations are every annotation it accepts, in its domain.
	Annotations []Annotation `json:"annotations,omitempty"`
}

// Annotation is one annotation a provider accepts. Its full name is the plugin's domain and Key:
// NAME.kevaso.com/KEY, NAME being the name the plugin is installed under (a second account,
// linode-work, reads linode-work.kevaso.com/KEY), so a plugin declares the key alone.
type Annotation struct {
	Key         string `json:"key"` // e.g. nodebalancer
	Description string `json:"description,omitempty"`
	// Type is the value's: string (the default, ""), int, bool or enum.
	Type string `json:"type,omitempty"`
	// Values (enum) are the values allowed.
	Values []string `json:"values,omitempty"`
	// Pattern (string) is an RE2 expression the whole value must match; empty: any.
	Pattern string `json:"pattern,omitempty"`
	// Min and Max (int) bound the value; nil: unbounded.
	Min *int64 `json:"min,omitempty"`
	Max *int64 `json:"max,omitempty"`
	// On is where it goes: service, ip, or both; empty: service.
	On []string `json:"on,omitempty"`
}

// Annotation value types.
const (
	AnnotationString = "string"
	AnnotationInt    = "int"
	AnnotationBool   = "bool"
	AnnotationEnum   = "enum"
)

// Where an annotation goes (Annotation.On).
const (
	OnService = "service"
	OnIP      = "ip"
)

// Domain is the annotation prefix of the plugin installed as name: NAME.kevaso.com/.
func Domain(name string) string { return name + ".kevaso.com/" }

var keyRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`)

// Goes says whether the annotation goes on what (OnService, OnIP).
func (a Annotation) Goes(on string) bool {
	if len(a.On) == 0 {
		return on == OnService
	}
	for _, o := range a.On {
		if o == on {
			return true
		}
	}
	return false
}

// Check says what is wrong with the declaration, or nil: core refuses to register a plugin that
// declares something it can't check (and Conformance fails it).
func (n *Networking) Check() error {
	if n == nil {
		return nil
	}
	var errs []error
	switch n.Reach {
	case "", FollowsHost, FollowsRegion, FollowsGlobal:
	default:
		errs = append(errs, fmt.Errorf("reach %q: want %s, %s or %s", n.Reach, FollowsHost, FollowsRegion, FollowsGlobal))
	}
	if n.FrontWithIP && (!n.ProviderIPs || !n.LoadBalancers) {
		errs = append(errs, errors.New("frontWithIP needs both providerIPs and loadBalancers"))
	}
	seen := map[string]bool{}
	for _, r := range n.Regions {
		if r == "" || seen["region "+r] {
			errs = append(errs, fmt.Errorf("region %q empty or twice", r))
		}
		seen["region "+r] = true
	}
	for _, a := range n.Annotations {
		if !keyRE.MatchString(a.Key) {
			errs = append(errs, fmt.Errorf("annotation key %q: want lower-case letters, digits, '-' and '.', without the domain (the plugin's install name gives it)", a.Key))
		}
		if seen["key "+a.Key] {
			errs = append(errs, fmt.Errorf("annotation %s declared twice", a.Key))
		}
		seen["key "+a.Key] = true
		if err := a.check(); err != nil {
			errs = append(errs, fmt.Errorf("annotation %s: %w", a.Key, err))
		}
	}
	return errors.Join(errs...)
}

func (a Annotation) check() error {
	for _, o := range a.On {
		if o != OnService && o != OnIP {
			return fmt.Errorf("on %q: want %s or %s", o, OnService, OnIP)
		}
	}
	if a.Pattern != "" && a.Type != "" && a.Type != AnnotationString {
		return fmt.Errorf("a pattern is for type %s, not %s", AnnotationString, a.Type)
	}
	if (a.Min != nil || a.Max != nil) && a.Type != AnnotationInt {
		return fmt.Errorf("min and max are for type %s", AnnotationInt)
	}
	if len(a.Values) > 0 && a.Type != AnnotationEnum {
		return fmt.Errorf("values are for type %s", AnnotationEnum)
	}
	switch a.Type {
	case "", AnnotationString:
		if a.Pattern != "" {
			if _, err := regexp.Compile(a.Pattern); err != nil {
				return fmt.Errorf("pattern: %w", err)
			}
		}
	case AnnotationInt:
		if a.Min != nil && a.Max != nil && *a.Min > *a.Max {
			return fmt.Errorf("min %d above max %d", *a.Min, *a.Max)
		}
	case AnnotationBool:
	case AnnotationEnum:
		if len(a.Values) == 0 {
			return errors.New("an enum needs values")
		}
	default:
		return fmt.Errorf("type %q: want %s, %s, %s or %s", a.Type, AnnotationString, AnnotationInt, AnnotationBool, AnnotationEnum)
	}
	return nil
}

// Value says what is wrong with v as the annotation's value, or nil.
func (a Annotation) Value(v string) error {
	switch a.Type {
	case "", AnnotationString:
		if a.Pattern == "" {
			return nil
		}
		re, err := regexp.Compile(`^(?:` + a.Pattern + `)$`)
		if err != nil {
			return fmt.Errorf("its declared pattern doesn't compile: %w", err)
		}
		if !re.MatchString(v) {
			return fmt.Errorf("%q doesn't match %s", v, a.Pattern)
		}
	case AnnotationInt:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("%q isn't a whole number", v)
		}
		if a.Min != nil && n < *a.Min {
			return fmt.Errorf("%d is below %d", n, *a.Min)
		}
		if a.Max != nil && n > *a.Max {
			return fmt.Errorf("%d is above %d", n, *a.Max)
		}
	case AnnotationBool:
		if v != "true" && v != "false" {
			return fmt.Errorf("%q: want true or false", v)
		}
	case AnnotationEnum:
		for _, ok := range a.Values {
			if v == ok {
				return nil
			}
		}
		return fmt.Errorf("%q: want one of %s", v, strings.Join(a.Values, ", "))
	}
	return nil
}

// ValidateAnnotations checks annotations on a service or IP (on: OnService, OnIP) against what
// the plugin installed as name declares: every annotation in its domain must be one it declares
// for on, with a value it accepts. Annotations outside its domain aren't its business. One error
// per bad annotation, sorted, each naming the annotation (and, for a misspelling, the one meant).
// A nil Networking declares nothing and checks nothing. A plugin may call it on what core sends.
func (n *Networking) ValidateAnnotations(name, on string, annotations map[string]string) error {
	if n == nil {
		return nil
	}
	domain := Domain(name)
	keys := make([]string, 0, len(annotations))
	for k := range annotations {
		if strings.HasPrefix(k, domain) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var errs []error
	for _, k := range keys {
		key := strings.TrimPrefix(k, domain)
		a, ok := n.annotation(key)
		switch {
		case !ok || !a.Goes(on):
			errs = append(errs, &AnnotationError{Name: k, Problem: n.unknown(domain, key, on)})
		default:
			if err := a.Value(annotations[k]); err != nil {
				errs = append(errs, &AnnotationError{Name: k, Problem: err.Error()})
			}
		}
	}
	return errors.Join(errs...)
}

func (n *Networking) annotation(key string) (Annotation, bool) {
	for _, a := range n.Annotations {
		if a.Key == key {
			return a, true
		}
	}
	return Annotation{}, false
}

// unknown says why key isn't accepted on on, and what is.
func (n *Networking) unknown(domain, key, on string) string {
	var accepted []string
	best, bestD := "", 0
	for _, a := range n.Annotations {
		if !a.Goes(on) {
			continue
		}
		accepted = append(accepted, domain+a.Key)
		if d := distance(key, a.Key); best == "" || d < bestD {
			best, bestD = a.Key, d
		}
	}
	sort.Strings(accepted)
	what := "a service"
	if on == OnIP {
		what = "an IP"
	}
	msg := "not an annotation " + strings.TrimSuffix(domain, ".kevaso.com/") + " accepts on " + what
	if a, ok := n.annotation(key); ok && !a.Goes(on) {
		goes := a.On
		if len(goes) == 0 {
			goes = []string{OnService}
		}
		msg = "it goes on " + strings.Join(goes, " or ") + ", not on " + what
	}
	if best != "" && bestD <= 1+len(key)/3 {
		msg += "; did you mean " + domain + best + "?"
	}
	if len(accepted) == 0 {
		return msg + " (it accepts none)"
	}
	return msg + " (it accepts " + strings.Join(accepted, ", ") + ")"
}

// AnnotationError is one annotation a provider refuses.
type AnnotationError struct {
	Name    string // the full annotation name
	Problem string
}

func (e *AnnotationError) Error() string { return "annotation " + e.Name + ": " + e.Problem }

// distance is the Levenshtein distance between a and b.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

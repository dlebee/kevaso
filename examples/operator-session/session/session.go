// Package session is the example plugin operator's controller (examples/operator-session): for
// each Session it keeps spec.replicas silos made from the session's SessionTemplate, and reports
// them in the session's status. It's built on the public modules only (kevaso.com/core/api and
// kevaso.com/core/sdk), as any plugin's controller would be.
package session

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/controller"
	"kevaso.com/core/sdk/operator"
)

// The plugin's names.
const (
	APIVersion       = "example.dev/v1"
	Sessions         = "sessions.example.dev"
	Templates        = "sessiontemplates.example.dev"
	Finalizer        = "sessions.example.dev/silos" // a session's silos go before it does
	SessionLabel     = "sessions.example.dev/session"
	PromptAnnotation = "sessions.example.dev/prompt"
)

// Session is the plugin's Go type for sessions.example.dev.
type Session struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            Spec   `json:"spec"`
	Status          Status `json:"status,omitempty"`
}

// Spec is what people ask for.
type Spec struct {
	Template string `json:"template"`
	Replicas *int64 `json:"replicas,omitempty"` // the schema's default is 1
	Prompt   string `json:"prompt,omitempty"`
}

// Status is what the controller reports.
type Status struct {
	ObservedGeneration int64            `json:"observedGeneration,omitempty"`
	Replicas           int64            `json:"replicas"`
	Phase              string           `json:"phase,omitempty"` // Waiting | Creating | Starting | Running
	Silos              []SiloRef        `json:"silos,omitempty"`
	Conditions         []meta.Condition `json:"conditions,omitempty"`
}

// SiloRef is one of a session's silos.
type SiloRef struct {
	Name  string `json:"name"`
	Phase string `json:"phase,omitempty"`
}

// Template is sessiontemplates.example.dev.
type Template struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            struct {
		Silo v1.SiloSpec `json:"silo"`
	} `json:"spec"`
}

// Main is the controller program: it reads the credentials kvoadm plugin install gave it, reports
// a heartbeat, and runs until ctx ends.
func Main(ctx context.Context, creds *operator.Credentials) error {
	c, err := creds.Client(ctx)
	if err != nil {
		return err
	}
	go operator.Heartbeat(ctx, c, creds.Plugin.Name, creds.Plugin.Version)
	Run(ctx, c)
	return nil
}

// Run runs the controller with a client until ctx ends.
func Run(ctx context.Context, c *client.Client) {
	r := &reconciler{c: c, sessions: informer.New(c, Sessions), templates: informer.New(c, Templates), silos: informer.New(c, "Silo")}
	ctl := &controller.Controller{Name: "sessions", Informer: r.sessions, Reconcile: r.reconcile, Base: 50 * time.Millisecond,
		Also: []controller.Watch{
			{Informer: r.silos, Map: r.sessionOfSilo},
			{Informer: r.templates, Map: r.sessionsOfTemplate},
		}}
	ctl.Run(ctx) // runs the informers too
}

type reconciler struct {
	c                          *client.Client
	sessions, templates, silos *informer.Informer
}

func (r *reconciler) sessionOfSilo(k informer.Key) []informer.Key {
	obj, ok := r.silos.Get(k.Namespace, k.Name)
	if !ok { // gone: its name says which session it was
		if i := strings.LastIndex(k.Name, "-"); i > 0 {
			return []informer.Key{{Namespace: k.Namespace, Name: k.Name[:i]}}
		}
		return nil
	}
	if s := obj.GetObjectMeta().Labels[SessionLabel]; s != "" {
		return []informer.Key{{Namespace: k.Namespace, Name: s}}
	}
	return nil
}

func (r *reconciler) sessionsOfTemplate(k informer.Key) []informer.Key {
	var out []informer.Key
	for _, obj := range r.sessions.List() {
		var s Session
		if u, ok := obj.(*v1.Unstructured); ok && u.Into(&s) == nil && s.Namespace == k.Namespace && s.Spec.Template == k.Name {
			out = append(out, informer.Key{Namespace: s.Namespace, Name: s.Name})
		}
	}
	return out
}

// siloName is a session's i-th silo.
func siloName(session string, i int64) string { return session + "-" + strconv.FormatInt(i, 10) }

// silosOf are the session's silos, by name.
func (r *reconciler) silosOf(s *Session) map[string]*v1.Silo {
	out := map[string]*v1.Silo{}
	for _, obj := range r.silos.List() {
		if silo, ok := obj.(*v1.Silo); ok && silo.Namespace == s.Namespace && silo.Labels[SessionLabel] == s.Name {
			out[silo.Name] = silo
		}
	}
	return out
}

func (r *reconciler) reconcile(ctx context.Context, k informer.Key) (controller.Result, error) {
	obj, ok := r.sessions.Get(k.Namespace, k.Name)
	if !ok {
		return controller.Result{}, nil // gone (after its finalizer: its silos went first)
	}
	var s Session
	if err := obj.(*v1.Unstructured).Into(&s); err != nil {
		return controller.Result{}, err
	}
	have := r.silosOf(&s)
	if s.DeletionTimestamp != nil {
		for name := range have {
			if err := r.c.Delete(ctx, "Silo", s.Namespace, name); err != nil && !client.IsNotFound(err) {
				return controller.Result{}, err
			}
		}
		if len(have) > 0 {
			return controller.Result{RequeueAfter: time.Second}, nil // the silo informer wakes us sooner
		}
		s.Finalizers = slices.DeleteFunc(s.Finalizers, func(f string) bool { return f == Finalizer })
		return requeueOnConflict(r.c.Update(ctx, &s))
	}
	if !slices.Contains(s.Finalizers, Finalizer) {
		s.Finalizers = append(s.Finalizers, Finalizer)
		return requeueOnConflict(r.c.Update(ctx, &s))
	}
	want := int64(1)
	if s.Spec.Replicas != nil {
		want = *s.Spec.Replicas
	}
	next := s.Status
	next.Conditions = slices.Clone(s.Status.Conditions) // SetCondition changes them in place
	next.ObservedGeneration = s.Generation
	now := time.Now().UTC().Truncate(time.Second)
	tobj, ok := r.templates.Get(s.Namespace, s.Spec.Template)
	if !ok {
		next.Phase = "Waiting"
		meta.SetCondition(&next.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "TemplateMissing",
			Message: fmt.Sprintf("no SessionTemplate %s in %s", s.Spec.Template, s.Namespace), ObservedGeneration: s.Generation}, now)
		return r.writeStatus(ctx, &s, next)
	}
	var tmpl Template
	if err := tobj.(*v1.Unstructured).Into(&tmpl); err != nil {
		return controller.Result{}, err
	}
	for i := int64(0); i < want; i++ {
		name := siloName(s.Name, i)
		if _, ok := have[name]; ok {
			continue
		}
		silo := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"},
			ObjectMeta: meta.ObjectMeta{Name: name, Namespace: s.Namespace, Labels: map[string]string{SessionLabel: s.Name},
				OwnerReferences: []meta.OwnerReference{{APIVersion: APIVersion, Kind: "Session", Name: s.Name, UID: s.UID, Controller: true}}},
			Spec: tmpl.Spec.Silo}
		if s.Spec.Prompt != "" {
			silo.Annotations = map[string]string{PromptAnnotation: s.Spec.Prompt}
		}
		if err := r.c.Create(ctx, silo); err != nil && !client.IsAlreadyExists(err) {
			meta.SetCondition(&next.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Reason: "SiloRefused",
				Message: err.Error(), ObservedGeneration: s.Generation}, now)
			_, _ = r.writeStatus(ctx, &s, next)
			return controller.Result{}, err
		}
		have[name] = silo
	}
	for name := range have { // scaled down: the highest ones go
		if i, err := strconv.ParseInt(strings.TrimPrefix(name, s.Name+"-"), 10, 64); err != nil || i >= want {
			if err := r.c.Delete(ctx, "Silo", s.Namespace, name); err != nil && !client.IsNotFound(err) {
				return controller.Result{}, err
			}
			delete(have, name)
		}
	}
	next.Silos, next.Replicas = nil, int64(len(have))
	running := int64(0)
	for i := int64(0); i < want; i++ {
		if silo, ok := have[siloName(s.Name, i)]; ok {
			next.Silos = append(next.Silos, SiloRef{Name: silo.Name, Phase: silo.Status.Phase})
			if silo.Status.Phase == "Running" {
				running++
			}
		}
	}
	switch {
	case next.Replicas < want:
		next.Phase = "Creating"
	case running < want:
		next.Phase = "Starting"
	default:
		next.Phase = "Running"
	}
	ready := meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "Running", ObservedGeneration: s.Generation}
	if next.Phase != "Running" {
		ready.Status, ready.Reason = meta.ConditionFalse, next.Phase
		ready.Message = fmt.Sprintf("%d of %d silos running", running, want)
	}
	meta.SetCondition(&next.Conditions, ready, now)
	return r.writeStatus(ctx, &s, next)
}

func (r *reconciler) writeStatus(ctx context.Context, s *Session, next Status) (controller.Result, error) {
	if reflect.DeepEqual(s.Status, next) {
		return controller.Result{}, nil
	}
	s.Status = next
	return requeueOnConflict(r.c.UpdateStatus(ctx, s))
}

func requeueOnConflict(err error) (controller.Result, error) {
	if client.IsConflict(err) || client.IsNotFound(err) {
		return controller.Result{RequeueAfter: 20 * time.Millisecond}, nil // the informer brings the newer one
	}
	return controller.Result{}, err
}

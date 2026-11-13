package integration

// A plugin's controller for its own kind, as a plugin would write it: it imports only the public
// api and sdk modules (no kevaso.com/core/internal), and works on its own Go type.

import (
	"context"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/controller"
)

// Database is the plugin's Go type for databases.acme.dev.
type Database struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            DatabaseSpec   `json:"spec"`
	Status          DatabaseStatus `json:"status,omitempty"`
}

// DatabaseSpec is what people ask for.
type DatabaseSpec struct {
	Engine   string `json:"engine"`
	Size     string `json:"size,omitempty"`
	Replicas int    `json:"replicas,omitempty"`
}

// DatabaseStatus is what the controller reports.
type DatabaseStatus struct {
	ObservedGeneration int64            `json:"observedGeneration,omitempty"`
	Endpoint           string           `json:"endpoint,omitempty"`
	Conditions         []meta.Condition `json:"conditions,omitempty"`
}

// dbController "provisions" each database: it writes an endpoint and a Ready condition.
type dbController struct {
	c   *client.Client
	inf *informer.Informer
}

func runDBController(ctx context.Context, c *client.Client) {
	inf := informer.New(c, "databases.acme.dev")
	r := &dbController{c: c, inf: inf}
	ctl := &controller.Controller{Name: "databases", Informer: inf, Reconcile: r.reconcile, Workers: 2, Base: 20 * time.Millisecond}
	ctl.Run(ctx)
}

func (r *dbController) reconcile(ctx context.Context, k informer.Key) (controller.Result, error) {
	obj, ok := r.inf.Get(k.Namespace, k.Name)
	if !ok {
		return controller.Result{}, nil // gone: nothing to clean up in this example
	}
	var db Database
	if err := obj.(*v1.Unstructured).Into(&db); err != nil {
		return controller.Result{}, err
	}
	if db.Status.ObservedGeneration == db.Generation && meta.IsTrue(db.Status.Conditions, "Ready") {
		return controller.Result{}, nil
	}
	db.Status.ObservedGeneration = db.Generation
	db.Status.Endpoint = db.Spec.Engine + "://" + db.Name + "." + db.Namespace + ":5432"
	meta.SetCondition(&db.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "Provisioned",
		ObservedGeneration: db.Generation}, time.Now().UTC().Truncate(time.Second))
	err := r.c.UpdateStatus(ctx, &db)
	if client.IsConflict(err) || client.IsNotFound(err) {
		return controller.Result{RequeueAfter: 10 * time.Millisecond}, nil // the informer brings the newer one
	}
	return controller.Result{}, err
}

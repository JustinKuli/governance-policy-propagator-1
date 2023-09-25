// Copyright (c) 2023 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package propagator

import (
	"context"
	"sort"
	"sync"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	policiesv1 "open-cluster-management.io/governance-policy-propagator/api/v1"
	"open-cluster-management.io/governance-policy-propagator/controllers/common"
)

//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=policies,verbs=get;list;watch
//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=policies/status,verbs=get;update;patch

// SetupWithManager sets up the controller with the Manager.
func (r *RootPolicyStatusReconciler) SetupWithManager(mgr ctrl.Manager, _ ...source.Source) error {
	policyStatusPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// If there was an update and the generation is the same, the status must have changed.
			return e.ObjectOld.GetGeneration() == e.ObjectNew.GetGeneration()
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{MaxConcurrentReconciles: int(r.MaxConcurrentReconciles)}).
		Named("root-policy-status").
		For(
			&policiesv1.Policy{},
			builder.WithPredicates(common.NeverEnqueue)).
		// This is a workaround - the controller-runtime requires a "For", but does not allow it to
		// modify the eventhandler. Currently we need to enqueue requests for Policies in a very
		// particular way, so we will define that in a separate "Watches"
		Watches(
			&policiesv1.Policy{},
			handler.EnqueueRequestsFromMapFunc(common.PolicyMapper(mgr.GetClient())),
			builder.WithPredicates(policyStatusPredicate)).
		// TODO: Watch Placements and Bindings
		Complete(r)
}

// blank assignment to verify that RootPolicyStatusReconciler implements reconcile.Reconciler
var _ reconcile.Reconciler = &RootPolicyStatusReconciler{}

// RootPolicyStatusReconciler handles replicated policy status updates and updates the root policy status.
type RootPolicyStatusReconciler struct {
	Propagator
	MaxConcurrentReconciles uint
}

// Reconcile will update the root policy status based on the current state whenever a root or replicated policy status
// is updated. The reconcile request is always on the root policy. This approach is taken rather than just handling a
// single replicated policy status per reconcile to be able to "batch" status update requests when there are bursts of
// replicated policy status updates. This lowers resource utilization on the controller and the Kubernetes API server.
func (r *RootPolicyStatusReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	log := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	log.V(1).Info("Reconciling the root policy status")

	log.V(3).Info("Acquiring the lock for the root policy")

	lock, _ := r.RootPolicyLocks.LoadOrStore(request.NamespacedName, &sync.Mutex{})

	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()

	// Set the hub template watch metric after reconcile
	defer func() {
		hubTempWatches := r.DynamicWatcher.GetWatchCount()
		log.V(3).Info("Setting hub template watch metric", "value", hubTempWatches)

		hubTemplateActiveWatchesMetric.Set(float64(hubTempWatches))
	}()

	rootPolicy := &policiesv1.Policy{}

	err := r.Get(ctx, request.NamespacedName, rootPolicy)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(2).Info("The root policy has been deleted. Doing nothing.")

			return reconcile.Result{}, nil
		}

		log.Error(err, "Failed to get the root policy")

		return reconcile.Result{}, err
	}

	log.Info("Updating the root policy status")

	replicatedPolicyList := &policiesv1.PolicyList{}

	err = r.List(ctx, replicatedPolicyList, client.MatchingLabels(common.LabelsForRootPolicy(rootPolicy)))
	if err != nil {
		log.Error(err, "Failed to list the replicated policies")

		return reconcile.Result{}, err
	}

	pbList := &policiesv1.PlacementBindingList{}

	err = r.List(ctx, pbList, &client.ListOptions{Namespace: request.Namespace})
	if err != nil {
		log.Error(err, "Could not list the placement bindings")

		return reconcile.Result{}, err
	}

	_, placements, err := r.getAllClusterDecisions(rootPolicy, pbList)
	if err != nil {
		log.Error(err, "Failed to calculate the placements")

		return reconcile.Result{}, err
	}

	cpcs := make([]*policiesv1.CompliancePerClusterStatus, len(replicatedPolicyList.Items))

	for i := range replicatedPolicyList.Items {
		cpcs[i] = &policiesv1.CompliancePerClusterStatus{
			ComplianceState:  replicatedPolicyList.Items[i].Status.ComplianceState,
			ClusterName:      replicatedPolicyList.Items[i].Namespace,
			ClusterNamespace: replicatedPolicyList.Items[i].Namespace,
		}
	}

	sort.Slice(cpcs, func(i, j int) bool {
		return cpcs[i].ClusterName < cpcs[j].ClusterName
	})

	err = r.Get(ctx, request.NamespacedName, rootPolicy)
	if err != nil {
		log.Error(err, "Failed to refresh the cached policy. Will use existing policy.")
	}

	if equality.Semantic.DeepEqual(rootPolicy.Status.Status, cpcs) {
		log.V(1).Info("No status changes required in the root policy. Doing nothing.")

		return reconcile.Result{}, nil
	}

	rootPolicy.Status.Placement = placements
	rootPolicy.Status.Status = cpcs
	rootPolicy.Status.ComplianceState = CalculateRootCompliance(cpcs)

	err = r.Status().Update(ctx, rootPolicy)
	if err != nil {
		log.Error(err, "Failed to update the root policy status. Will Requeue.")

		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

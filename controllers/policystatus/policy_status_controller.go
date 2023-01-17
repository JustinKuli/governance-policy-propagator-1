// Copyright Contributors to the Open Cluster Management project

package policystatus

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	policiesv1 "open-cluster-management.io/governance-policy-propagator/api/v1"
	"open-cluster-management.io/governance-policy-propagator/controllers/common"
	"open-cluster-management.io/governance-policy-propagator/controllers/propagator"
)

const ControllerName string = "policy-status"

var log = ctrl.Log.WithName(ControllerName)

//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=policies,verbs=get;list;watch
//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=policies/status,verbs=get;update;patch

// SetupWithManager sets up the controller with the Manager.
func (r *PolicyStatusReconciler) SetupWithManager(mgr ctrl.Manager, additionalSources ...source.Source) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{MaxConcurrentReconciles: int(r.MaxConcurrentReconciles)}).
		Named(ControllerName).
		For(
			&policiesv1.Policy{},
			builder.WithPredicates(policyStatusPredicate(mgr.GetClient())),
		).
		Complete(r)
}

// blank assignment to verify that PolicyStatusReconciler implements reconcile.Reconciler
var _ reconcile.Reconciler = &PolicyStatusReconciler{}

// PolicyStatusReconciler handles replicated policy status updates and updates the root policy status.
type PolicyStatusReconciler struct {
	client.Client
	MaxConcurrentReconciles uint
	// Use a shared lock with the main policy controller to avoid conflicting updates.
	RootPolicyLocks *common.PoliciesLock
	Scheme          *runtime.Scheme
}

// Reconcile handles a replicated policy status update and then updates the root policy status. It does not handle
// creations or deletions of replicated policies. Those are handled by the main policy controller. This Reconcile
// may have a lot retries if several clusters are updating the same policy at the same time due to a race condition
// where the root policy status update hasn't been updated in the cache.
func (r *PolicyStatusReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	log := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	log.Info("Reconciling the root policy status")

	// Get the root policy name and namespace this way to handle the case where the replicated policy is deleted
	// and the label can't be retrieved.
	rootName, rootNamespace, err := common.ParseRootPolicyLabel(request.Name)
	if err != nil {
		log.Error(err, "The replicated policy name was in an unexpected format. Will not retry the request.")

		return reconcile.Result{}, nil
	}

	log = log.WithValues("rootNamespace", rootNamespace, "rootName", rootName)
	rootNsName := types.NamespacedName{Namespace: rootNamespace, Name: rootName}

	log.V(3).Info("Acquiring the lock for the root policy")
	r.RootPolicyLocks.Lock(rootNsName)
	defer func() { r.RootPolicyLocks.Unlock(rootNsName) }()

	rootPolicy := &policiesv1.Policy{}

	err = r.Get(ctx, types.NamespacedName{Namespace: rootNamespace, Name: rootName}, rootPolicy)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(2).Info("The root policy has been deleted. Doing nothing.")

			return reconcile.Result{}, nil
		}

		log.Error(err, "Failed to get the root policy", "rootNamespace", rootNamespace, "rootName", rootName)

		return reconcile.Result{}, err
	}

	replicatedPolicy := &policiesv1.Policy{}

	err = r.Get(ctx, request.NamespacedName, replicatedPolicy)
	if err != nil {
		log.Error(err, "Failed to get the replicated policy")

		return reconcile.Result{}, err
	}

	log.Info("Updating the root policy status")

	foundStatus := false

	for i, status := range rootPolicy.Status.Status {
		if status.ClusterName != replicatedPolicy.Labels[common.ClusterNameLabel] {
			continue
		}

		if status.ComplianceState == replicatedPolicy.Status.ComplianceState {
			log.V(2).Info("The compliance state is already correct in the root policy status")

			return reconcile.Result{}, nil
		}

		foundStatus = true
		rootPolicy.Status.Status[i].ComplianceState = replicatedPolicy.Status.ComplianceState

		break
	}

	if !foundStatus {
		// When the replicated policy doesn't have a status, the main controller will handle that
		log.V(3).Info("The replicated policy doesn't have a status in the root policy. Doing nothing.")

		return reconcile.Result{}, nil
	}

	rootPolicy.Status.ComplianceState = propagator.CalculateRootCompliance(rootPolicy.Status.Status)

	err = r.Status().Update(context.TODO(), rootPolicy, &client.UpdateOptions{})
	if err != nil {
		log.Error(err, "Failed to update the root policy status. Will Requeue.")

		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

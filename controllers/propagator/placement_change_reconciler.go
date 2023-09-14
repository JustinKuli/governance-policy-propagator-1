package propagator

import (
	"context"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
	appsv1 "open-cluster-management.io/multicloud-operators-subscription/pkg/apis/apps/placementrule/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policiesv1 "open-cluster-management.io/governance-policy-propagator/api/v1"
	"open-cluster-management.io/governance-policy-propagator/controllers/common"
)

//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=placementbindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cluster.open-cluster-management.io,resources=placementdecisions;placements,verbs=get;list;watch
//+kubebuilder:rbac:groups=apps.open-cluster-management.io,resources=placementrules,verbs=get;list;watch

// SetupWithManager sets up the controller with the Manager.
func (r *PlacementChangeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	placementBindingMapper := func(c client.Client) handler.MapFunc {
		return func(ctx context.Context, obj client.Object) []reconcile.Request {
			//nolint:forcetypeassert
			pb := obj.(*policiesv1.PlacementBinding)

			log := log.WithValues("placementBindingName", pb.GetName(), "namespace", pb.GetNamespace())
			log.V(2).Info("Reconcile request for a PlacementBinding")

			return common.GetPoliciesInPlacementBinding(ctx, c, pb)
		}
	}

	// only reconcile when the pb contains a policy or a policyset as a subject
	pbPredicateFuncs := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			//nolint:forcetypeassert
			pbObjNew := e.ObjectNew.(*policiesv1.PlacementBinding)
			//nolint:forcetypeassert
			pbObjOld := e.ObjectOld.(*policiesv1.PlacementBinding)

			return common.IsForPolicyOrPolicySet(pbObjNew) || common.IsForPolicyOrPolicySet(pbObjOld)
		},
		CreateFunc: func(e event.CreateEvent) bool {
			//nolint:forcetypeassert
			pbObj := e.Object.(*policiesv1.PlacementBinding)

			return common.IsForPolicyOrPolicySet(pbObj)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			//nolint:forcetypeassert
			pbObj := e.Object.(*policiesv1.PlacementBinding)

			return common.IsForPolicyOrPolicySet(pbObj)
		},
	}

	// placementRuleMapper maps from a PlacementRule to the PlacementBindings associated with it
	placementRuleMapper := func(c client.Client) handler.MapFunc {
		return func(ctx context.Context, object client.Object) []reconcile.Request {
			log := log.WithValues("placementRuleName", object.GetName(), "namespace", object.GetNamespace())
			log.V(2).Info("Reconcile Request for PlacementRule")

			pbList := &policiesv1.PlacementBindingList{}
			lopts := &client.ListOptions{Namespace: object.GetNamespace()}

			opts := client.MatchingFields{"placementRef.name": object.GetName()}
			opts.ApplyToList(lopts)

			if err := c.List(ctx, pbList, lopts); err != nil {
				return nil
			}

			var result []reconcile.Request
			// loop through pbs find the matching ones
			for _, pb := range pbList.Items {
				match := pb.PlacementRef.APIGroup == appsv1.SchemeGroupVersion.Group &&
					pb.PlacementRef.Kind == "PlacementRule" &&
					pb.PlacementRef.Name == object.GetName()

				if match {
					result = append(result, reconcile.Request{NamespacedName: types.NamespacedName{
						Namespace: pb.GetNamespace(),
						Name:      pb.GetName(),
					}})
				}
			}

			return result
		}
	}

	// placementDecisionMapper maps from a PlacementDecision to the PlacementBindings associated with its Placement
	placementDecisionMapper := func(c client.Client) handler.MapFunc {
		return func(ctx context.Context, object client.Object) []reconcile.Request {
			log := log.WithValues("placementDecisionName", object.GetName(), "namespace", object.GetNamespace())
			log.V(2).Info("Reconcile request for a placement decision")

			// get the Placement name from the PlacementDecision
			placementName := object.GetLabels()["cluster.open-cluster-management.io/placement"]
			if placementName == "" {
				return nil
			}

			pbList := &policiesv1.PlacementBindingList{}
			lopts := &client.ListOptions{Namespace: object.GetNamespace()}

			opts := client.MatchingFields{"placementRef.name": placementName}
			opts.ApplyToList(lopts)

			if err := c.List(ctx, pbList, lopts); err != nil {
				return nil
			}

			var result []reconcile.Request
			// loop through pbs find the matching ones
			for _, pb := range pbList.Items {
				match := pb.PlacementRef.APIGroup == clusterv1beta1.SchemeGroupVersion.Group &&
					pb.PlacementRef.Kind == "Placement" &&
					pb.PlacementRef.Name == placementName

				if match {
					result = append(result, reconcile.Request{NamespacedName: types.NamespacedName{
						Namespace: pb.GetNamespace(),
						Name:      pb.GetName(),
					}})
				}
			}

			return result
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("placement-change-reconciler").
		For(
			&policiesv1.Policy{},
			builder.WithPredicates(common.NeverEnqueue)). // (workaround)
		Watches(
			&policiesv1.PlacementBinding{},
			handler.EnqueueRequestsFromMapFunc(placementBindingMapper(mgr.GetClient())),
			builder.WithPredicates(pbPredicateFuncs)).
		Watches(
			&appsv1.PlacementRule{},
			handler.EnqueueRequestsFromMapFunc(placementRuleMapper(mgr.GetClient()))).
		Watches(
			&clusterv1beta1.PlacementDecision{},
			handler.EnqueueRequestsFromMapFunc(placementDecisionMapper(mgr.GetClient()))).
		Complete(r)
}

var _ reconcile.Reconciler = &PlacementChangeReconciler{}

type PlacementChangeReconciler struct {
	Propagator
}

func (r *PlacementChangeReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	log := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	log.Info("Reconciling")

	pb := &policiesv1.PlacementBinding{}

	if err := r.Get(ctx, request.NamespacedName, pb); err != nil {
		if k8serrors.IsNotFound(err) {
			// TODO: need to handle this in the root policy controller, I think...
			// it could have a predicate for only delete events, and then do a map func that would
			// use the "old" placementbinding to find affected policies.

			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, err
	}

	policies := common.GetPoliciesInPlacementBinding(ctx, r.Client, pb)
	for _, plc := range policies {
		instance := &policiesv1.Policy{}

		if err := r.Get(ctx, plc.NamespacedName, instance); err != nil {
			if k8serrors.IsNotFound(err) {
				continue // This situation will be handled by the root policy controller
			}

			// TODO: or should we try to handle the other policies before giving up?
			// Thanks to the cache, I don't think this Get will fail often...
			return reconcile.Result{}, err
		}

		// TODO: need to get the Lock here.

		if err := r.handleRootPolicy(instance, false); err != nil {
			// TODO: or should we try to handle the other policies before giving up?
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

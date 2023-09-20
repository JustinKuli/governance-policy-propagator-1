// Copyright (c) 2022 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package controllers

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
	appsv1 "open-cluster-management.io/multicloud-operators-subscription/pkg/apis/apps/placementrule/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyv1 "open-cluster-management.io/governance-policy-propagator/api/v1"
	policyv1beta1 "open-cluster-management.io/governance-policy-propagator/api/v1beta1"
	"open-cluster-management.io/governance-policy-propagator/controllers/common"
)

const ControllerName string = "policy-set"

var log = ctrl.Log.WithName(ControllerName)

// PolicySetReconciler reconciles a PolicySet object
type PolicySetReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// blank assignment to verify that PolicySetReconciler implements reconcile.Reconciler
var _ reconcile.Reconciler = &PolicySetReconciler{}

//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=policysets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=policysets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=policy.open-cluster-management.io,resources=policysets/finalizers,verbs=update

func (r *PolicySetReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	log := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	log.Info("Reconciling policy sets...")
	// Fetch the PolicySet instance
	instance := &policyv1beta1.PolicySet{}

	err := r.Get(ctx, request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			log.Info("Policy set not found, so it may have been deleted.")

			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to retrieve policy set")

		return reconcile.Result{}, err
	}

	log.V(1).Info("Policy set was found, processing it")

	originalInstance := instance.DeepCopy()
	setNeedsUpdate := r.processPolicySet(ctx, instance)

	if setNeedsUpdate {
		log.Info("Status update needed")

		err := r.Status().Patch(ctx, instance, client.MergeFrom(originalInstance))
		if err != nil {
			log.Error(err, "Failed to update policy set status")

			return reconcile.Result{}, err
		}
	}

	log.Info("Policy set successfully processed, reconcile complete.")

	r.Recorder.Event(
		instance,
		"Normal",
		fmt.Sprintf("policySet: %s", instance.GetName()),
		fmt.Sprintf("Status successfully updated for policySet %s in namespace %s", instance.GetName(),
			instance.GetNamespace()),
	)

	return reconcile.Result{}, nil
}

// processPolicySet compares the status of a policyset to its desired state and determines whether an update is needed
func (r *PolicySetReconciler) processPolicySet(ctx context.Context, plcSet *policyv1beta1.PolicySet) bool {
	log.V(1).Info("Processing policy sets")

	needsUpdate := false

	// compile results and compliance state from policy statuses
	compliancesFound := []string{}
	deletedPolicies := []string{}
	unknownPolicies := []string{}
	disabledPolicies := []string{}
	pendingPolicies := []string{}
	aggregatedCompliance := policyv1.Compliant
	placementsByBinding := map[string]policyv1beta1.PolicySetStatusPlacement{}

	// if there are no policies in the policyset, status should be empty
	if len(plcSet.Spec.Policies) == 0 {
		builtStatus := policyv1beta1.PolicySetStatus{}

		if !equality.Semantic.DeepEqual(plcSet.Status, builtStatus) {
			plcSet.Status = *builtStatus.DeepCopy()

			return true
		}

		return false
	}

	for i := range plcSet.Spec.Policies {
		childPlcName := plcSet.Spec.Policies[i]
		childNamespacedName := types.NamespacedName{
			Name:      string(childPlcName),
			Namespace: plcSet.Namespace,
		}

		childPlc := &policyv1.Policy{}

		err := r.Client.Get(ctx, childNamespacedName, childPlc)
		if err != nil {
			// policy does not exist, log error message and generate event
			var errMessage string
			if errors.IsNotFound(err) {
				errMessage = string(childPlcName) + " not found"
			} else {
				split := strings.Split(err.Error(), "Policy.policy.open-cluster-management.io ")
				if len(split) < 2 {
					errMessage = err.Error()
				} else {
					errMessage = split[1]
				}
			}

			log.V(2).Info(errMessage)

			r.Recorder.Event(plcSet, "Warning", "PolicyNotFound",
				fmt.Sprintf(
					"Policy %s is in PolicySet %s but could not be found in namespace %s",
					childPlcName,
					plcSet.GetName(),
					plcSet.GetNamespace(),
				),
			)

			deletedPolicies = append(deletedPolicies, string(childPlcName))
		} else {
			// aggregate placements
			for _, placement := range childPlc.Status.Placement {
				if placement.PolicySet == plcSet.GetName() {
					placementsByBinding[placement.PlacementBinding] = plcPlacementToSetPlacement(*placement)
				}
			}

			if childPlc.Spec.Disabled {
				// policy is disabled, do not process compliance
				disabledPolicies = append(disabledPolicies, string(childPlcName))

				continue
			}

			// create list of all relevant clusters
			clusters := []string{}
			for pbName := range placementsByBinding {
				pbNamespacedName := types.NamespacedName{
					Name:      pbName,
					Namespace: plcSet.Namespace,
				}

				pb := &policyv1.PlacementBinding{}

				err := r.Client.Get(ctx, pbNamespacedName, pb)
				if err != nil {
					log.V(1).Info("Error getting placement binding " + pbName)
				}

				var decisions []appsv1.PlacementDecision
				decisions, err = common.GetDecisions(r.Client, pb)
				if err != nil {
					log.Error(err, "Error getting placement decisions for binding "+pbName)
				}

				for _, decision := range decisions {
					clusters = append(clusters, decision.ClusterName)
				}
			}

			// aggregate compliance state
			plcComplianceState := complianceInRelevantClusters(childPlc.Status.Status, clusters)
			if plcComplianceState == "" {
				unknownPolicies = append(unknownPolicies, string(childPlcName))
			} else {
				if plcComplianceState == policyv1.Pending {
					pendingPolicies = append(pendingPolicies, string(childPlcName))
					if aggregatedCompliance != policyv1.NonCompliant {
						aggregatedCompliance = policyv1.Pending
					}
				} else {
					compliancesFound = append(compliancesFound, string(childPlcName))
					if plcComplianceState == policyv1.NonCompliant {
						aggregatedCompliance = policyv1.NonCompliant
					}
				}
			}
		}
	}

	generatedPlacements := []policyv1beta1.PolicySetStatusPlacement{}
	for _, pcmt := range placementsByBinding {
		generatedPlacements = append(generatedPlacements, pcmt)
	}

	builtStatus := policyv1beta1.PolicySetStatus{
		Placement:     generatedPlacements,
		StatusMessage: getStatusMessage(disabledPolicies, unknownPolicies, deletedPolicies, pendingPolicies),
	}
	if showCompliance(compliancesFound, unknownPolicies, pendingPolicies) {
		builtStatus.Compliant = string(aggregatedCompliance)
	}

	if !equality.Semantic.DeepEqual(plcSet.Status, builtStatus) {
		plcSet.Status = *builtStatus.DeepCopy()
		needsUpdate = true
	}

	return needsUpdate
}

// getStatusMessage returns a message listing disabled, deleted and policies with no status
func getStatusMessage(
	disabledPolicies []string,
	unknownPolicies []string,
	deletedPolicies []string,
	pendingPolicies []string,
) string {
	statusMessage := ""
	separator := ""
	allReporting := true

	if len(pendingPolicies) > 0 {
		allReporting = false
		statusMessage += fmt.Sprintf("Policies awaiting pending dependencies: %s",
			strings.Join(pendingPolicies, ", "))
		separator = "; "
	}

	if len(disabledPolicies) > 0 {
		allReporting = false
		statusMessage += fmt.Sprintf(separator+"Disabled policies: %s", strings.Join(disabledPolicies, ", "))
		separator = "; "
	}

	if len(unknownPolicies) > 0 {
		allReporting = false
		statusMessage += fmt.Sprintf(separator+"No status provided while awaiting policy status: %s",
			strings.Join(unknownPolicies, ", "))
		separator = "; "
	}

	if len(deletedPolicies) > 0 {
		allReporting = false
		statusMessage += fmt.Sprintf(separator+"Deleted policies: %s", strings.Join(deletedPolicies, ", "))
	}

	if allReporting {
		return "All policies are reporting status"
	}

	return statusMessage
}

// showCompliance only if there are policies with compliance and none are still awaiting status
func showCompliance(compliancesFound []string, unknown []string, pending []string) bool {
	if len(unknown) > 0 {
		return false
	}

	if len(compliancesFound)+len(pending) > 0 {
		return true
	}

	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *PolicySetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	policySetPredicateFuncs := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			//nolint:forcetypeassert
			policySetObjNew := e.ObjectNew.(*policyv1beta1.PolicySet)
			//nolint:forcetypeassert
			policySetObjOld := e.ObjectOld.(*policyv1beta1.PolicySet)

			return !equality.Semantic.DeepEqual(
				policySetObjNew.Spec.Policies,
				policySetObjOld.Spec.Policies,
			)
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return true
		},
	}

	policyMapper := func(ctx context.Context, object client.Object) []reconcile.Request {
		log := log.WithValues("policyName", object.GetName(), "namespace", object.GetNamespace())
		log.V(2).Info("Reconcile Request for Policy")

		var result []reconcile.Request

		for _, plcmt := range object.(*policyv1.Policy).Status.Placement {
			// iterate through placement looking for policyset
			if plcmt.PolicySet != "" {
				log.V(2).Info("Found reconciliation request from a policy", "policySetName", plcmt.PolicySet)

				request := reconcile.Request{NamespacedName: types.NamespacedName{
					Name:      plcmt.PolicySet,
					Namespace: object.GetNamespace(),
				}}
				result = append(result, request)
			}
		}

		return result
	}

	policyPredicateFuncs := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			//nolint:forcetypeassert
			policyObjNew := e.ObjectNew.(*policyv1.Policy)
			//nolint:forcetypeassert
			policyObjOld := e.ObjectOld.(*policyv1.Policy)

			return !equality.Semantic.DeepEqual(policyObjNew.Status, policyObjOld.Status)
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return true
		},
	}

	placementBindingMapper := func(ctx context.Context, obj client.Object) []reconcile.Request {
		//nolint:forcetypeassert
		object := obj.(*policyv1.PlacementBinding)
		var result []reconcile.Request

		log := log.WithValues("placementBindingName", object.GetName(), "namespace", object.GetNamespace())

		log.V(2).Info("Reconcile request for a PlacementBinding")

		subjects := object.Subjects
		for _, subject := range subjects {
			if subject.APIGroup == policyv1.SchemeGroupVersion.Group {
				if subject.Kind == policyv1.PolicySetKind {
					log.V(2).Info("Found reconciliation request from policyset placement binding",
						"policySetName", subject.Name)

					request := reconcile.Request{NamespacedName: types.NamespacedName{
						Name:      subject.Name,
						Namespace: object.GetNamespace(),
					}}
					result = append(result, request)
				}
			}
		}

		return result
	}

	pbPredicateFuncs := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			//nolint:forcetypeassert
			pbObjNew := e.ObjectNew.(*policyv1.PlacementBinding)
			//nolint:forcetypeassert
			pbObjOld := e.ObjectOld.(*policyv1.PlacementBinding)

			return common.IsPbForPolicySet(pbObjNew) || common.IsPbForPolicySet(pbObjOld)
		},
		CreateFunc: func(e event.CreateEvent) bool {
			//nolint:forcetypeassert
			pbObj := e.Object.(*policyv1.PlacementBinding)

			return common.IsPbForPolicySet(pbObj)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			//nolint:forcetypeassert
			pbObj := e.Object.(*policyv1.PlacementBinding)

			return common.IsPbForPolicySet(pbObj)
		},
	}

	placementRuleMapper := func(ctx context.Context, object client.Object) []reconcile.Request {
		log := log.WithValues("placementRuleName", object.GetName(), "namespace", object.GetNamespace())

		log.V(2).Info("Reconcile Request for PlacementRule")

		// list pb
		pbList := &policyv1.PlacementBindingList{}

		// find pb in the same namespace of placementrule
		err := r.List(ctx, pbList, &client.ListOptions{Namespace: object.GetNamespace()})
		if err != nil {
			return nil
		}

		var result []reconcile.Request
		// loop through pb to find if current placementrule is used for policy set
		for _, pb := range pbList.Items {
			// found matching placement rule in pb
			if pb.PlacementRef.APIGroup == appsv1.SchemeGroupVersion.Group &&
				pb.PlacementRef.Kind == "PlacementRule" && pb.PlacementRef.Name == object.GetName() {
				// check if it is for policy set
				subjects := pb.Subjects
				for _, subject := range subjects {
					if subject.APIGroup == policyv1.SchemeGroupVersion.Group {
						if subject.Kind == policyv1.PolicySetKind {
							log.V(2).Info("Found reconciliation request from policyset placement rule",
								"policySetName", subject.Name)

							request := reconcile.Request{NamespacedName: types.NamespacedName{
								Name:      subject.Name,
								Namespace: object.GetNamespace(),
							}}
							result = append(result, request)
						}
					}
				}
			}
		}

		return result
	}

	placementDecisionMapper := func(ctx context.Context, object client.Object) []reconcile.Request {
		log := log.WithValues("placementDecisionName", object.GetName(), "namespace", object.GetNamespace())

		log.V(2).Info("Reconcile request for a placement decision")

		// get the placement name from the placementdecision
		placementName := object.GetLabels()["cluster.open-cluster-management.io/placement"]
		if placementName == "" {
			return nil
		}

		pbList := &policyv1.PlacementBindingList{}
		// find pb in the same namespace of placementrule
		lopts := &client.ListOptions{Namespace: object.GetNamespace()}
		opts := client.MatchingFields{"placementRef.name": placementName}
		opts.ApplyToList(lopts)

		err := r.List(ctx, pbList, lopts)
		if err != nil {
			return nil
		}

		var result []reconcile.Request
		// loop through pb to find if current placement is used for policy set
		for _, pb := range pbList.Items {
			if pb.PlacementRef.APIGroup != clusterv1beta1.SchemeGroupVersion.Group ||
				pb.PlacementRef.Kind != "Placement" || pb.PlacementRef.Name != placementName {
				continue
			}

			// found matching placement in pb -- check if it is for policyset
			subjects := pb.Subjects
			for _, subject := range subjects {
				if subject.APIGroup == policyv1.SchemeGroupVersion.Group {
					if subject.Kind == policyv1.PolicySetKind {
						log.V(2).Info("Found reconciliation request from policyset placement decision",
							"policySetName", subject.Name)

						request := reconcile.Request{NamespacedName: types.NamespacedName{
							Name:      subject.Name,
							Namespace: object.GetNamespace(),
						}}
						result = append(result, request)
					}
				}
			}
		}

		return result
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerName).
		For(
			&policyv1beta1.PolicySet{},
			builder.WithPredicates(policySetPredicateFuncs)).
		Watches(
			&policyv1.Policy{},
			handler.EnqueueRequestsFromMapFunc(policyMapper),
			builder.WithPredicates(policyPredicateFuncs)).
		Watches(
			&policyv1.PlacementBinding{},
			handler.EnqueueRequestsFromMapFunc(placementBindingMapper),
			builder.WithPredicates(pbPredicateFuncs)).
		Watches(
			&appsv1.PlacementRule{},
			handler.EnqueueRequestsFromMapFunc(placementRuleMapper)).
		Watches(
			&clusterv1beta1.PlacementDecision{},
			handler.EnqueueRequestsFromMapFunc(placementDecisionMapper)).
		Complete(r)
}

// Helper function to filter out compliance statuses that are not in scope
func complianceInRelevantClusters(
	status []*policyv1.CompliancePerClusterStatus,
	relevantClusters []string,
) policyv1.ComplianceState {
	complianceFound := false
	compliance := policyv1.Compliant

	for i := range status {
		if clusterInList(relevantClusters, status[i].ClusterName) {
			if status[i].ComplianceState == policyv1.NonCompliant {
				compliance = policyv1.NonCompliant
				complianceFound = true
			} else if status[i].ComplianceState == policyv1.Pending {
				complianceFound = true
				if compliance != policyv1.NonCompliant {
					compliance = policyv1.Pending
				}
			} else if status[i].ComplianceState != "" {
				complianceFound = true
			}
		}
	}

	if complianceFound {
		return compliance
	}

	return ""
}

// helper function to check whether a cluster is in a list of clusters
func clusterInList(list []string, cluster string) bool {
	for _, item := range list {
		if item == cluster {
			return true
		}
	}

	return false
}

// Helper function to convert policy placement to policyset placement
func plcPlacementToSetPlacement(plcPlacement policyv1.Placement) policyv1beta1.PolicySetStatusPlacement {
	return policyv1beta1.PolicySetStatusPlacement{
		PlacementBinding: plcPlacement.PlacementBinding,
		Placement:        plcPlacement.Placement,
		PlacementRule:    plcPlacement.PlacementRule,
	}
}

// Copyright Contributors to the Open Cluster Management project

package policystatus

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	policiesv1 "open-cluster-management.io/governance-policy-propagator/api/v1"
	"open-cluster-management.io/governance-policy-propagator/controllers/common"
)

// isValidReplicatedPolicy returns true if it's a replicated policy in the correct format (e.g. correct labels).
func isValidReplicatedPolicy(c client.Client, policy client.Object) bool {
	log := log.WithValues("name", policy.GetName(), "namespace", policy.GetNamespace())

	log.V(2).Info("Reconcile request for a policy")

	isReplicated, err := common.IsReplicatedPolicy(c, policy)
	if err != nil {
		log.Error(err, "Failed to determine if this queued policy is a replicated policy")

		return false
	}

	if !isReplicated {
		log.V(2).Info("Skipping the policy since it's a root policy")

		return false
	}

	if policy.GetLabels()[common.ClusterNameLabel] == "" {
		log.Info(
			"Skipping since the replicated policy is missing a required label",
			"label", common.ClusterNameLabel,
		)

		return false
	}

	if policy.GetLabels()[common.ClusterNamespaceLabel] == "" {
		log.Info(
			"Skipping since the replicated policy is missing a required label",
			"label", common.ClusterNamespaceLabel,
		)

		return false
	}

	return true
}

// policyStatusPredicate will filter out all events that are not from an updated status.compliance field on a replicated
// policy.
func policyStatusPredicate(c client.Client) predicate.Funcs {
	return predicate.Funcs{
		// Creations are handled by the main policy controller.
		CreateFunc: func(e event.CreateEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			// nolint: forcetypeassert
			oldPolicy := e.ObjectOld.(*policiesv1.Policy)
			// nolint: forcetypeassert
			updatedPolicy := e.ObjectNew.(*policiesv1.Policy)

			// Perform this check first even if we don't know that it's a replicated policy yet since it's less
			// resource intensive than isValidReplicatedPolicy.
			if oldPolicy.Status.ComplianceState == updatedPolicy.Status.ComplianceState {
				return false
			}

			return isValidReplicatedPolicy(c, updatedPolicy)
		},
		// Deletions are handled by the main policy controller.
		DeleteFunc: func(e event.DeleteEvent) bool { return false },
	}
}

// Copyright Contributors to the Open Cluster Management project

package automation

import (
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	policyv1beta1 "open-cluster-management.io/governance-policy-propagator/api/v1beta1"
)

// we only want to watch for pb contains policy as subjects
var policyAuomtationPredicateFuncs = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		//nolint:forcetypeassert
		policyAutomationNew := e.ObjectNew.(*policyv1beta1.PolicyAutomation)

		if policyAutomationNew.Spec.PolicyRef == "" {
			return false
		}

		if policyAutomationNew.ObjectMeta.Annotations["policy.open-cluster-management.io/rerun"] == "true" {
			return true
		}

		// the generation is incremented whenever the spec changes.
		return e.ObjectNew.GetGeneration() != e.ObjectOld.GetGeneration()
	},
	CreateFunc: func(e event.CreateEvent) bool {
		//nolint:forcetypeassert
		policyAutomationNew := e.Object.(*policyv1beta1.PolicyAutomation)

		return policyAutomationNew.Spec.PolicyRef != ""
	},
	DeleteFunc: func(e event.DeleteEvent) bool {
		return false
	},
}

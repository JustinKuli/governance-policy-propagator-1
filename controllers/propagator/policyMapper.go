// Copyright (c) 2021 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package propagator

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"open-cluster-management.io/governance-policy-propagator/controllers/common"
)

// policyMapper looks at object and returns a slice of reconcile.Request to reconcile
// owners of object from label: policy.open-cluster-management.io/root-policy
func policyMapper(c client.Client) handler.MapFunc {
	return func(object client.Object) []reconcile.Request {
		log := log.WithValues("name", object.GetName(), "namespace", object.GetNamespace())

		log.V(2).Info("Reconcile request for a policy")

		isReplicated, err := common.IsReplicatedPolicy(c, object)
		if err != nil {
			log.Error(err, "Failed to determine if this queued policy is a replicated policy")

			return nil
		}

		var name string
		var namespace string

		if isReplicated {
			log.V(2).Info("Found reconciliation request from replicated policy")

			rootPlcName := object.GetLabels()[common.RootPolicyLabel]
			// Skip error checking since IsReplicatedPolicy verified this already
			name, namespace, _ = common.ParseRootPolicyLabel(rootPlcName)
		} else {
			log.V(2).Info("Found reconciliation request from root policy")

			name = object.GetName()
			namespace = object.GetNamespace()
		}

		request := reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		}}

		return []reconcile.Request{request}
	}
}

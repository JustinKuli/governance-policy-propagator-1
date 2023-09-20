// Copyright (c) 2021 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package common

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
	appsv1 "open-cluster-management.io/multicloud-operators-subscription/pkg/apis/apps/placementrule/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policiesv1 "open-cluster-management.io/governance-policy-propagator/api/v1"
)

// PolicyMapper looks at object and returns a slice of reconcile.Request to reconcile
// owners of object from label: policy.open-cluster-management.io/root-policy
func PolicyMapper(c client.Client) handler.MapFunc {
	return func(ctx context.Context, object client.Object) []reconcile.Request {
		log := ctrl.Log.WithValues("name", object.GetName(), "namespace", object.GetNamespace())

		log.V(2).Info("Reconcile request for a policy")

		isReplicated, err := IsReplicatedPolicy(c, object)
		if err != nil {
			log.Error(err, "Failed to determine if this queued policy is a replicated policy")

			return nil
		}

		var name string
		var namespace string

		if isReplicated {
			log.V(2).Info("Found reconciliation request from replicated policy")

			rootPlcName := object.GetLabels()[RootPolicyLabel]
			// Skip error checking since IsReplicatedPolicy verified this already
			name, namespace, _ = ParseRootPolicyLabel(rootPlcName)
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

type MapperFromPlacementBinding func(context.Context, client.Client, *policiesv1.PlacementBinding) []reconcile.Request

// PlacementRuleMapper holds logic for finding PlacementBindings for a PlacementRule, and uses the
// provided MapperFromPlacementBinding to collect the relevant subjects from those PlacementBindings
func PlacementRuleMapper(
	c client.Client, pbMap MapperFromPlacementBinding,
) func(context.Context, client.Object) []reconcile.Request {
	return func(ctx context.Context, object client.Object) []reconcile.Request {
		pbList := &policiesv1.PlacementBindingList{}

		// find pb in the same namespace as the PlacementRule
		err := c.List(ctx, pbList, &client.ListOptions{Namespace: object.GetNamespace()})
		if err != nil {
			return nil
		}

		var result []reconcile.Request
		// loop through pbs and collect objects from each matching one.
		for _, pb := range pbList.Items {
			if pb.PlacementRef.APIGroup != appsv1.SchemeGroupVersion.Group ||
				pb.PlacementRef.Kind != "PlacementRule" || pb.PlacementRef.Name != object.GetName() {
				continue
			}

			result = append(result, pbMap(ctx, c, &pb)...)
		}

		return result
	}
}

// PlacementDecisionMapper holds logic for finding PlacementBindings for a PlacementDecision, and
// uses the provided MapperFromPlacementBinding to collect the relevant subjects from those
// PlacementBindings.
func PlacementDecisionMapper(
	c client.Client, pbMap MapperFromPlacementBinding,
) func(context.Context, client.Object) []reconcile.Request {
	return func(ctx context.Context, object client.Object) []reconcile.Request {
		// get the placement name from the PlacementDecision
		placementName := object.GetLabels()["cluster.open-cluster-management.io/placement"]
		if placementName == "" {
			return nil
		}

		pbList := &policiesv1.PlacementBindingList{}
		// find pb in the same namespace as the PlacementDecision
		lopts := &client.ListOptions{Namespace: object.GetNamespace()}
		opts := client.MatchingFields{"placementRef.name": placementName}
		opts.ApplyToList(lopts)

		err := c.List(ctx, pbList, lopts)
		if err != nil {
			return nil
		}

		var result []reconcile.Request
		// loop through pbs and collect objects from each matching one.
		for _, pb := range pbList.Items {
			if pb.PlacementRef.APIGroup != clusterv1beta1.SchemeGroupVersion.Group ||
				pb.PlacementRef.Kind != "Placement" || pb.PlacementRef.Name != placementName {
				continue
			}

			result = append(result, pbMap(ctx, c, &pb)...)
		}

		return result
	}
}

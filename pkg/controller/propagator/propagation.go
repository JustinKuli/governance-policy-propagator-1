// Copyright (c) 2021 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package propagator

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	templates "github.com/open-cluster-management/go-template-utils/pkg/templates"
	appsv1 "github.com/open-cluster-management/governance-policy-propagator/pkg/apis/apps/v1"
	clusterv1alpha1 "github.com/open-cluster-management/governance-policy-propagator/pkg/apis/cluster/v1alpha1"
	policiesv1 "github.com/open-cluster-management/governance-policy-propagator/pkg/apis/policy/v1"
	"github.com/open-cluster-management/governance-policy-propagator/pkg/controller/common"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var kubeConfig *rest.Config
var kubeClient *kubernetes.Interface
var templateCfg templates.Config

func Initialize(kubeconfig *rest.Config, kubeclient *kubernetes.Interface) {
	kubeConfig = kubeconfig
	kubeClient = kubeclient
	templateCfg = templates.Config{StartDelim: "{{hub", StopDelim: "hub}}"}
}

func (r *ReconcilePolicy) handleRootPolicy(instance *policiesv1.Policy) error {
	entry_ts := time.Now()
	defer func() {
		now := time.Now()
		elapsed := now.Sub(entry_ts).Seconds()
		roothandlerMeasure.Observe(elapsed)
	}()

	reqLogger := log.WithValues("Policy-Namespace", instance.GetNamespace(), "Policy-Name", instance.GetName())
	originalInstance := instance.DeepCopy()
	// flow -- if triggerred by user creating a new policy or updateing existing policy
	if instance.Spec.Disabled {
		// do nothing, clean up replicated policy
		// deleteReplicatedPolicy
		reqLogger.Info("Policy is disabled, doing clean up...")
		replicatedPlcList := &policiesv1.PolicyList{}
		err := r.client.List(context.TODO(), replicatedPlcList, client.MatchingLabels(common.LabelsForRootPolicy(instance)))
		if err != nil {
			// there was an error, requeue
			reqLogger.Error(err, "Failed to list replicated policy...")
			return err
		}
		for _, plc := range replicatedPlcList.Items {
			// #nosec G601 -- no memory addresses are stored in collections
			err := r.client.Delete(context.TODO(), &plc)
			if err != nil && !errors.IsNotFound(err) {
				reqLogger.Error(err, "Failed to delete replicated policy...", "Namespace", plc.GetNamespace(),
					"Name", plc.GetName())
				return err
			}
		}
		r.recorder.Event(instance, "Normal", "PolicyPropagation",
			fmt.Sprintf("Policy %s/%s was disabled", instance.GetNamespace(), instance.GetName()))
	}
	// get binding
	pbList := &policiesv1.PlacementBindingList{}
	err := r.client.List(context.TODO(), pbList, &client.ListOptions{Namespace: instance.GetNamespace()})
	if err != nil {
		reqLogger.Error(err, "Failed to list pb...")
		return err
	}
	// get placement
	placement := []*policiesv1.Placement{}
	// a set in the format of `namespace/name`
	allDecisions := map[string]struct{}{}
	for _, pb := range pbList.Items {
		subjects := pb.Subjects
		for _, subject := range subjects {
			if subject.APIGroup == policiesv1.SchemeGroupVersion.Group &&
				subject.Kind == policiesv1.Kind && subject.Name == instance.GetName() {
				decisions, p, err := getPlacementDecisions(r.client, pb, instance)
				if err != nil {
					return err
				}
				placement = append(placement, p)
				// only handle replicate policy when policy is not disabled
				if !instance.Spec.Disabled {
					// plr found, checking decision
					for _, decision := range decisions {
						key := fmt.Sprintf("%s/%s", decision.ClusterNamespace, decision.ClusterName)
						allDecisions[key] = struct{}{}
						// create/update replicated policy for each decision
						err := r.handleDecision(instance, decision)
						if err != nil {
							return err
						}
					}
				}
				// only handle first match in pb.spec.subjects
				break
			}
		}
	}
	status := []*policiesv1.CompliancePerClusterStatus{}
	if !instance.Spec.Disabled {
		// loop through all replciated policy, update status.status
		replicatedPlcList := &policiesv1.PolicyList{}
		err = r.client.List(context.TODO(), replicatedPlcList,
			client.MatchingLabels(common.LabelsForRootPolicy(instance)))
		if err != nil {
			// there was an error, requeue
			reqLogger.Error(err, "Failed to list replicated policy...",
				"MatchingLables", common.LabelsForRootPolicy(instance))
			return err
		}
		for _, rPlc := range replicatedPlcList.Items {
			status = append(status, &policiesv1.CompliancePerClusterStatus{
				ComplianceState:  rPlc.Status.ComplianceState,
				ClusterName:      rPlc.GetLabels()[common.ClusterNameLabel],
				ClusterNamespace: rPlc.GetLabels()[common.ClusterNamespaceLabel],
			})
		}
		sort.Slice(status, func(i, j int) bool {
			return status[i].ClusterName < status[j].ClusterName
		})
	}

	instance.Status.Status = status
	//loop through status and set ComplianceState
	instance.Status.ComplianceState = ""
	isCompliant := true
	for _, cpcs := range status {
		if cpcs.ComplianceState == "NonCompliant" {
			instance.Status.ComplianceState = policiesv1.NonCompliant
			isCompliant = false
			break
		} else if cpcs.ComplianceState == "" {
			isCompliant = false
		}
	}
	// set to compliant only when all status are compliant
	if len(status) > 0 && isCompliant {
		instance.Status.ComplianceState = policiesv1.Compliant
	}
	// looped through all pb, update status.placement
	sort.Slice(placement, func(i, j int) bool {
		return placement[i].PlacementBinding < placement[j].PlacementBinding
	})
	instance.Status.Placement = placement
	err = r.client.Status().Patch(context.TODO(), instance, client.MergeFrom(originalInstance))
	if err != nil && !errors.IsNotFound(err) {
		// failed to update instance.spec.placement, requeue
		reqLogger.Error(err, "Failed to update root policy status...")
		return err
	}

	// remove stale replicated policy based on allDecisions and status.status
	// if cluster exists in status.status but doesn't exist in allDecisions, then it's stale cluster.
	// we need to remove this replicated policy
	for _, cluster := range instance.Status.Status {
		key := fmt.Sprintf("%s/%s", cluster.ClusterNamespace, cluster.ClusterName)
		_, found := allDecisions[key]
		// not found in allDecision, orphan, delete it
		if !found {
			err := r.client.Delete(context.TODO(), &policiesv1.Policy{
				TypeMeta: metav1.TypeMeta{
					Kind:       policiesv1.Kind,
					APIVersion: policiesv1.SchemeGroupVersion.Group,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      common.FullNameForPolicy(instance),
					Namespace: cluster.ClusterNamespace,
				},
			})
			if err != nil && !errors.IsNotFound(err) {
				reqLogger.Error(err, "Failed to delete orphan policy...",
					"Namespace", cluster.ClusterNamespace, "Name", common.FullNameForPolicy(instance))
			}
		}
	}
	reqLogger.Info("Reconciliation complete.")
	return nil
}

// getApplicationPlacementDecisions return the placement decisions from an application
// lifecycle placementrule
func getApplicationPlacementDecisions(c client.Client, pb policiesv1.PlacementBinding, instance *policiesv1.Policy) ([]appsv1.PlacementDecision, *policiesv1.Placement, error) {
	plr := &appsv1.PlacementRule{}
	err := c.Get(context.TODO(), types.NamespacedName{Namespace: instance.GetNamespace(),
		Name: pb.PlacementRef.Name}, plr)
	// no error when not found
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Failed to get PlacementRule...", "Namespace", instance.GetNamespace(), "Name",
			pb.PlacementRef.Name)
		return nil, nil, err
	}
	// add the PlacementRule to placement, if not found there are no decisions
	placement := &policiesv1.Placement{
		PlacementBinding: pb.GetName(),
		PlacementRule:    plr.GetName(),
	}
	return plr.Status.Decisions, placement, nil
}

// getClusterPlacementDecisions return the placement decisions from cluster
// placement decisions
func getClusterPlacementDecisions(c client.Client, pb policiesv1.PlacementBinding, instance *policiesv1.Policy) ([]appsv1.PlacementDecision, *policiesv1.Placement, error) {
	pl := &clusterv1alpha1.Placement{}
	err := c.Get(context.TODO(), types.NamespacedName{Namespace: instance.GetNamespace(),
		Name: pb.PlacementRef.Name}, pl)
	// no error when not found
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Failed to get Placement...", "Namespace", instance.GetNamespace(), "Name",
			pb.PlacementRef.Name)
		return nil, nil, err
	}
	// add current Placement to placement, if not found no decisions will be found
	placement := &policiesv1.Placement{
		PlacementBinding: pb.GetName(),
		Placement:        pl.GetName(),
	}
	list := &clusterv1alpha1.PlacementDecisionList{}
	lopts := &client.ListOptions{Namespace: instance.GetNamespace()}

	opts := client.MatchingLabels{"cluster.open-cluster-management.io/placement": pl.GetName()}
	opts.ApplyToList(lopts)
	err = c.List(context.TODO(), list, lopts)
	// do not error out if not found
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Failed to get PlacementDecisions...", "Namespace", instance.GetNamespace(), "Name",
			pb.PlacementRef.Name)
		return nil, nil, err
	}
	var decisions []appsv1.PlacementDecision
	decisions = make([]appsv1.PlacementDecision, 0, len(list.Items))
	for _, item := range list.Items {
		for _, cluster := range item.Status.Decisions {
			decided := &appsv1.PlacementDecision{
				ClusterName:      cluster.ClusterName,
				ClusterNamespace: cluster.ClusterName,
			}
			decisions = append(decisions, *decided)
		}
	}
	return decisions, placement, nil
}

// getPlacementDecisions gets the PlacementDecisions for a PlacementBinding
func getPlacementDecisions(c client.Client, pb policiesv1.PlacementBinding,
	instance *policiesv1.Policy) ([]appsv1.PlacementDecision, *policiesv1.Placement, error) {
	if pb.PlacementRef.APIGroup == appsv1.SchemeGroupVersion.Group &&
		pb.PlacementRef.Kind == appsv1.Kind {
		d, placement, err := getApplicationPlacementDecisions(c, pb, instance)
		if err != nil {
			return nil, nil, err
		}
		return d, placement, nil
	} else if pb.PlacementRef.APIGroup == clusterv1alpha1.SchemeGroupVersion.Group &&
		pb.PlacementRef.Kind == clusterv1alpha1.Kind {
		d, placement, err := getClusterPlacementDecisions(c, pb, instance)
		if err != nil {
			return nil, nil, err
		}
		return d, placement, nil
	}
	return nil, nil, fmt.Errorf("Placement binding %s/%s reference is not valid", pb.Name, pb.Namespace)
}

func (r *ReconcilePolicy) handleDecision(instance *policiesv1.Policy, decision appsv1.PlacementDecision) error {
	reqLogger := log.WithValues("Policy-Namespace", instance.GetNamespace(), "Policy-Name", instance.GetName())
	// retrieve replicated policy in cluster namespace
	replicatedPlc := &policiesv1.Policy{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Namespace: decision.ClusterNamespace,
		Name: common.FullNameForPolicy(instance)}, replicatedPlc)
	if err != nil {
		if errors.IsNotFound(err) {
			// not replicated, need to create
			replicatedPlc = instance.DeepCopy()
			replicatedPlc.SetName(common.FullNameForPolicy(instance))
			replicatedPlc.SetNamespace(decision.ClusterNamespace)
			replicatedPlc.SetResourceVersion("")
			replicatedPlc.SetFinalizers(nil)
			labels := replicatedPlc.GetLabels()
			if labels == nil {
				labels = map[string]string{}
			}
			labels[common.ClusterNameLabel] = decision.ClusterName
			labels[common.ClusterNamespaceLabel] = decision.ClusterNamespace
			labels[common.RootPolicyLabel] = common.FullNameForPolicy(instance)
			replicatedPlc.SetLabels(labels)

			// Make sure the Owner Reference is cleared
			replicatedPlc.SetOwnerReferences(nil)

			//do a quick check for any template delims in the policy before putting it through
			// template processor
			if policyHasTemplates(instance) {
				//resolve hubTemplate before replicating
				err = r.processTemplates(replicatedPlc, decision, instance)
				if err != nil {
					return err
				}
			}

			reqLogger.Info("Creating replicated policy...", "Namespace", decision.ClusterNamespace,
				"Name", common.FullNameForPolicy(instance))
			err = r.client.Create(context.TODO(), replicatedPlc)
			if err != nil {
				// failed to create replicated object, requeue
				reqLogger.Error(err, "Failed to create replicated policy...", "Namespace", decision.ClusterNamespace,
					"Name", common.FullNameForPolicy(instance))
				return err
			}
			r.recorder.Event(instance, "Normal", "PolicyPropagation",
				fmt.Sprintf("Policy %s/%s was propagated to cluster %s/%s", instance.GetNamespace(),
					instance.GetName(), decision.ClusterNamespace, decision.ClusterName))
			//exit after handling the create path, shouldnt be going to through the update path
			return nil
		} else {
			// failed to get replicated object, requeue
			reqLogger.Error(err, "Failed to get replicated policy...", "Namespace", decision.ClusterNamespace,
				"Name", common.FullNameForPolicy(instance))
			return err
		}

	}
	// replicated policy already created, need to compare and patch
	comparePlc := instance
	if policyHasTemplates(instance) {
		//template delimis detected, build a temp holder policy with templates resolved
		//before doing a compare with the replicated policy in the cluster namespaces
		tempResolvedPlc := &policiesv1.Policy{}
		tempResolvedPlc.SetAnnotations(instance.GetAnnotations())
		tempResolvedPlc.Spec = instance.Spec
		tmplErr := r.processTemplates(tempResolvedPlc, decision, instance)
		if tmplErr != nil {
			return tmplErr
		}
		comparePlc = tempResolvedPlc
	}

	if !common.CompareSpecAndAnnotation(comparePlc, replicatedPlc) {
		// update needed
		reqLogger.Info("Root policy and Replicated policy mismatch, updating replicated policy...",
			"Namespace", replicatedPlc.GetNamespace(), "Name", replicatedPlc.GetName())
		replicatedPlc.SetAnnotations(comparePlc.GetAnnotations())
		replicatedPlc.Spec = comparePlc.Spec
		err = r.client.Update(context.TODO(), replicatedPlc)
		if err != nil {
			reqLogger.Error(err, "Failed to update replicated policy...",
				"Namespace", replicatedPlc.GetNamespace(), "Name", replicatedPlc.GetName())
			return err
		}
		r.recorder.Event(instance, "Normal", "PolicyPropagation",
			fmt.Sprintf("Policy %s/%s was updated for cluster %s/%s", instance.GetNamespace(),
				instance.GetName(), decision.ClusterNamespace, decision.ClusterName))
	}
	return nil
}

// a helper to quickly check if there are any templates in any of the policy templates
func policyHasTemplates(instance *policiesv1.Policy) bool {
	for _, policyT := range instance.Spec.PolicyTemplates {
		if templates.HasTemplate(policyT.ObjectDefinition.Raw, templateCfg.StartDelim) {
			return true
		}
	}
	return false
}

// iterates through policy definitions  and  processes hub templates
// a special  annotation policy.open-cluster-management.io/trigger-update is used to trigger reprocessing of the
// templates and ensuring that the replicated-policies in cluster is updated only if there is a change.
// this annotation is deleted from the replicated policies and not propagated to the cluster namespaces.

func (r *ReconcilePolicy) processTemplates(replicatedPlc *policiesv1.Policy, decision appsv1.PlacementDecision, rootPlc *policiesv1.Policy) error {

	reqLogger := log.WithValues("Policy-Namespace", rootPlc.GetNamespace(), "Policy-Name", rootPlc.GetName(), "Managed-Cluster", decision.ClusterName)
	reqLogger.Info("Processing Templates..")

	templateCfg.LookupNamespace = rootPlc.GetNamespace()
	tmplResolver, err := templates.NewResolver(kubeClient, kubeConfig, templateCfg)
	if err != nil {
		reqLogger.Error(err, "Error instantiating template resolver")
		panic(err)
	}

	//A policy can have multiple policy templates within it, iterate and process each
	for _, policyT := range replicatedPlc.Spec.PolicyTemplates {

		if !templates.HasTemplate(policyT.ObjectDefinition.Raw, templateCfg.StartDelim) {
			continue
		}

		if !isConfigurationPolicy(policyT) {
			// has Templates but not a configuration policy
			err = errors.NewBadRequest("Templates are restricted to only Configuration Policies")
			log.Error(err, "Not a Configuration Policy")

			r.recorder.Event(rootPlc, "Warning", "PolicyPropagation",
				fmt.Sprintf("Policy %s/%s has templates but it is not a ConfigurationPolicy.", rootPlc.GetName(), rootPlc.GetNamespace()))

			//TODO: when error handling is setup, need to return err
			return nil
		}

		reqLogger.Info("Found Object Definition with templates")

		templateContext := struct {
			ManagedClusterName string
		}{
			ManagedClusterName: decision.ClusterName,
		}
		resolveddata, tplErr := tmplResolver.ResolveTemplate(policyT.ObjectDefinition.Raw, templateContext)
		if tplErr != nil {
			reqLogger.Error(tplErr, "Failed to resolve templates")

			r.recorder.Event(rootPlc, "Warning", "PolicyPropagation",
				fmt.Sprintf("Failed to resolve templates for policy %s/%s for cluster %s/%s .", rootPlc.GetName(), rootPlc.GetNamespace(), decision.ClusterNamespace, decision.ClusterName))

			//TODO: when error handling is setup, need to return err
			return nil
		}

		policyT.ObjectDefinition.Raw = resolveddata

	}

	//Also remove  the tempate processing annotation from the replicated policy
	annotations := replicatedPlc.GetAnnotations()
	if _, ok := annotations["policy.open-cluster-management.io/trigger-update"]; ok {
		delete(annotations, "policy.open-cluster-management.io/trigger-update")
		replicatedPlc.SetAnnotations(annotations)
	}

	return nil
}

func isConfigurationPolicy(policyT *policiesv1.PolicyTemplate) bool {
	//check if it is a configuration policy first

	var jsonDef map[string]interface{}
	_ = json.Unmarshal(policyT.ObjectDefinition.Raw, &jsonDef)

	return jsonDef != nil && jsonDef["kind"] == "ConfigurationPolicy"
}

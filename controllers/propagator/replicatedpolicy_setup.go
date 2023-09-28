package propagator

import (
	"context"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	policiesv1 "open-cluster-management.io/governance-policy-propagator/api/v1"
	"open-cluster-management.io/governance-policy-propagator/controllers/common"
)

func (r *ReplicatedPolicyReconciler) SetupWithManager(
	mgr ctrl.Manager, dynWatcherSrc source.Source, updateSrc source.Source,
) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("replicated-policy").
		For(
			&policiesv1.Policy{},
			builder.WithPredicates(replicatedPolicyPredicates(r.ResourceVersions))).
		WatchesRawSource(
			dynWatcherSrc,
			// The dependency-watcher could create an event before the same sort of watch in the
			// controller-runtime triggers an update in the cache. This tries to ensure the cache is
			// updated before the reconcile is triggered.
			&delayGeneric{
				EventHandler: &handler.EnqueueRequestForObject{},
				delay:        time.Second * 3,
			}).
		WatchesRawSource(
			updateSrc,
			&handler.EnqueueRequestForObject{}).
		Complete(r)
}

// replicatedPolicyPredicates triggers reconciliation if the policy is a replicated policy, and is
// not a pure status update. It will use the ResourceVersions cache to try and skip events caused
// by the replicated policy reconciler itself.
func replicatedPolicyPredicates(resourceVersions *sync.Map) predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			_, isReplicated := e.Object.GetLabels()[common.RootPolicyLabel]
			if !isReplicated {
				return false
			}

			version := safeLoad(resourceVersions, e.Object)
			if version == "creating" || version == e.Object.GetResourceVersion() {
				return false
			}

			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, isReplicated := e.Object.GetLabels()[common.RootPolicyLabel]
			if !isReplicated {
				return false
			}

			version := safeLoad(resourceVersions, e.Object)

			return version != "deleting"
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, newIsReplicated := e.ObjectNew.GetLabels()[common.RootPolicyLabel]
			_, oldIsReplicated := e.ObjectOld.GetLabels()[common.RootPolicyLabel]

			// if neither has the label, it is not a replicated policy
			if !(oldIsReplicated || newIsReplicated) {
				return false
			}

			version := safeLoad(resourceVersions, e.ObjectNew)
			if version == e.ObjectNew.GetResourceVersion() {
				return false
			}

			// Ignore pure status updates since those are handled by a separate controller
			return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() ||
				!equality.Semantic.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) ||
				!equality.Semantic.DeepEqual(e.ObjectOld.GetAnnotations(), e.ObjectNew.GetAnnotations())
		},
	}
}

func safeLoad(resourceVersions *sync.Map, obj client.Object) string {
	key := obj.GetNamespace() + "/" + obj.GetName()

	if version, loaded := resourceVersions.Load(key); loaded {
		if versionString, ok := version.(string); ok {
			return versionString
		}
	}

	return ""
}

type delayGeneric struct {
	handler.EventHandler
	delay time.Duration
}

func (d *delayGeneric) Generic(_ context.Context, evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	q.AddAfter(reconcile.Request{NamespacedName: types.NamespacedName{
		Name:      evt.Object.GetName(),
		Namespace: evt.Object.GetNamespace(),
	}}, d.delay)
}

package externaldns

import (
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// KeyFunc creates a key for an API object. The key can be passed to a
// worker function that processes an object from a queue such as
// ProcessItem.
var KeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

// DefaultItemBasedRateLimiter returns a new rate limiter with base delay of 5
// seconds, max delay of 5 minutes.
func DefaultItemBasedRateLimiter() workqueue.TypedRateLimiter[types.NamespacedName] {
	return workqueue.NewTypedItemExponentialFailureRateLimiter[types.NamespacedName](5*time.Second, 5*time.Minute)
}

// QueuingEventHandler is an implementation of cache.ResourceEventHandler that
// simply queues objects that are added/updated/deleted.
type QueuingEventHandler struct {
	Queue workqueue.TypedRateLimitingInterface[types.NamespacedName]
}

// Enqueue adds a key for an object to the workqueue.
func (q *QueuingEventHandler) Enqueue(obj interface{}) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		runtime.HandleError(err)
		return
	}
	key := types.NamespacedName{
		Namespace: accessor.GetNamespace(),
		Name:      accessor.GetName(),
	}
	q.Queue.Add(key)
}

// OnAdd adds a newly created object to the workqueue.
func (q *QueuingEventHandler) OnAdd(obj interface{}, _ bool) {
	q.Enqueue(obj)
}

// OnUpdate adds an updated object to the workqueue.
func (q *QueuingEventHandler) OnUpdate(old, newObj interface{}) {
	if reflect.DeepEqual(old, newObj) {
		return
	}
	q.Enqueue(newObj)
}

// OnDelete adds a deleted object to the workqueue for processing.
func (q *QueuingEventHandler) OnDelete(obj interface{}) {
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = tombstone.Obj
	}
	q.Enqueue(obj)
}

// BlockingEventHandler is an implementation of cache.ResourceEventHandler that
// simply synchronously calls it's WorkFunc upon calls to OnAdd, OnUpdate or
// OnDelete.
type BlockingEventHandler struct {
	WorkFunc func(obj interface{})
}

// Enqueue synchronously adds a key for an object to the workqueue.
func (b *BlockingEventHandler) Enqueue(obj interface{}) {
	b.WorkFunc(obj)
}

// OnAdd synchronously adds a newly created object to the workqueue.
func (b *BlockingEventHandler) OnAdd(obj interface{}, _ bool) {
	b.WorkFunc(obj)
}

// OnUpdate synchronously adds an updated object to the workqueue.
func (b *BlockingEventHandler) OnUpdate(old, newObj interface{}) {
	if reflect.DeepEqual(old, newObj) {
		return
	}
	b.WorkFunc(newObj)
}

// OnDelete synchronously adds a deleted object to the workqueue.
func (b *BlockingEventHandler) OnDelete(obj interface{}) {
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = tombstone.Obj
	}
	b.WorkFunc(obj)
}

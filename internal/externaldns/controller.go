package externaldns

import (
	"context"
	"fmt"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/internal/nsregistry"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	extdns_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/externaldns/v1"
	k8s_nginx "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned"
	listersV1 "github.com/nginx/kubernetes-ingress/pkg/client/listers/configuration/v1"
	extdnslisters "github.com/nginx/kubernetes-ingress/pkg/client/listers/externaldns/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	k8s_nginx_informers "github.com/nginx/kubernetes-ingress/pkg/client/informers/externalversions"
)

const (
	// ControllerName is the name of the externaldns controller.
	ControllerName = "externaldns"
)

// ExtDNSController represents ExternalDNS controller.
type ExtDNSController struct {
	sync          SyncFn
	ctx           context.Context
	queue         workqueue.TypedRateLimitingInterface[types.NamespacedName]
	recorder      record.EventRecorder
	client        k8s_nginx.Interface
	informerGroup *nsregistry.Registry[namespacedInformer]
	resync        time.Duration
}

type namespacedInformer struct {
	vsLister              listersV1.VirtualServerLister
	sharedInformerFactory k8s_nginx_informers.SharedInformerFactory
	extdnslister          extdnslisters.DNSEndpointLister
	mustSync              []cache.InformerSynced
	stopCh                chan struct{}
}

// ExtDNSOpts represents config required for building the External DNS Controller.
type ExtDNSOpts struct {
	context       context.Context
	namespace     []string
	eventRecorder record.EventRecorder
	client        k8s_nginx.Interface
	resyncPeriod  time.Duration
	isDynamicNs   bool
}

// NewController takes external dns config and return a new External DNS Controller.
func NewController(opts *ExtDNSOpts) (*ExtDNSController, error) {
	ig := nsregistry.New[namespacedInformer]()

	rateLimiter := workqueue.DefaultTypedControllerRateLimiter[types.NamespacedName]()

	queue := workqueue.NewTypedRateLimitingQueueWithConfig(rateLimiter, workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{Name: ControllerName})

	c := &ExtDNSController{
		ctx:           opts.context,
		queue:         queue,
		informerGroup: ig,
		recorder:      opts.eventRecorder,
		client:        opts.client,
		resync:        opts.resyncPeriod,
	}

	for _, ns := range opts.namespace {
		if opts.isDynamicNs && ns == "" {
			// no initial namespaces with watched label - skip creating informers for now
			break
		}
		if _, err := c.newNamespacedInformer(ns); err != nil {
			return nil, fmt.Errorf("failed to create external-dns namespaced informer for namespace %s: %w", ns, err)
		}
	}

	c.sync = SyncFnFor(c.recorder, c.client, c.informerGroup)
	return c, nil
}

func (c *ExtDNSController) newNamespacedInformer(ns string) (*namespacedInformer, error) {
	nsi := &namespacedInformer{sharedInformerFactory: k8s_nginx_informers.NewSharedInformerFactoryWithOptions(c.client, c.resync, k8s_nginx_informers.WithNamespace(ns))}
	nsi.stopCh = make(chan struct{})
	nsi.vsLister = nsi.sharedInformerFactory.K8s().V1().VirtualServers().Lister()
	nsi.extdnslister = nsi.sharedInformerFactory.Externaldns().V1().DNSEndpoints().Lister()

	if _, err := nsi.sharedInformerFactory.K8s().V1().VirtualServers().Informer().AddEventHandler(
		&QueuingEventHandler{
			Queue: c.queue,
		},
	); err != nil {
		return nil, fmt.Errorf("failed to add VirtualServer event handler: %w", err)
	}

	if _, err := nsi.sharedInformerFactory.Externaldns().V1().DNSEndpoints().Informer().AddEventHandler(&BlockingEventHandler{
		WorkFunc: externalDNSHandler(c.queue),
	}); err != nil {
		return nil, fmt.Errorf("failed to add DNSEndpoint event handler: %w", err)
	}

	nsi.mustSync = append(
		nsi.mustSync,
		nsi.sharedInformerFactory.K8s().V1().VirtualServers().Informer().HasSynced,
		nsi.sharedInformerFactory.Externaldns().V1().DNSEndpoints().Informer().HasSynced,
	)
	c.informerGroup.Set(ns, nsi)
	return nsi, nil
}

// Run sets up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *ExtDNSController) Run(stopCh <-chan struct{}) {
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()

	l := nl.LoggerFromContext(ctx)

	nl.Info(l, "Starting external-dns control loop")

	var mustSync []cache.InformerSynced
	c.informerGroup.ForEach(func(ig *namespacedInformer) {
		ig.start()
		mustSync = append(mustSync, ig.mustSync...)
	})

	// wait for all informer caches to be synced
	nl.Debugf(l, "Waiting for %d caches to sync", len(mustSync))
	if !cache.WaitForNamedCacheSync(ControllerName, stopCh, mustSync...) {
		nl.Fatal(l, "error syncing extDNS queue")
	}

	nl.Debugf(l, "Queue is %v", c.queue.Len())

	go c.runWorker(ctx)

	<-stopCh
	nl.Debugf(l, "shutting down queue as workqueue signaled shutdown")
	c.informerGroup.ForEach(func(ig *namespacedInformer) {
		ig.stop()
	})
	c.queue.ShutDown()
}

func (nsi *namespacedInformer) start() {
	go nsi.sharedInformerFactory.Start(nsi.stopCh)
}

func (nsi *namespacedInformer) stop() {
	close(nsi.stopCh)
}

// runWorker is a long-running function that will continually call the processItem
// function in order to read and process a message on the workqueue.
func (c *ExtDNSController) runWorker(ctx context.Context) {
	l := nl.LoggerFromContext(ctx)
	nl.Debugf(l, "processing items on the workqueue")
	for {
		key, shutdown := c.queue.Get()
		if shutdown {
			break
		}

		func() {
			defer c.queue.Done(key)
			if err := c.processItem(ctx, key); err != nil {
				nl.Debugf(l, "Re-queuing item due to error processing: %v", err)
				c.queue.AddRateLimited(key)
				return
			}
			nl.Debugf(l, "finished processing work item")
			c.queue.Forget(key)
		}()
	}
}

func (c *ExtDNSController) processItem(ctx context.Context, key types.NamespacedName) error {
	namespace := key.Namespace
	name := key.Name
	l := nl.LoggerFromContext(ctx)
	var vs *conf_v1.VirtualServer
	var err error
	watched := c.informerGroup.WithInformer(namespace, func(nsi *namespacedInformer) {
		vs, err = nsi.vsLister.VirtualServers(namespace).Get(name)
	})
	if !watched {
		// the namespace stopped being watched between the item being queued
		// and it being processed, so there is nothing left to reconcile
		nl.Debugf(l, "Skipping VirtualServer %s/%s: namespace %s is not watched", namespace, name, namespace)
		return nil
	}

	// VS has been deleted
	if apierrors.IsNotFound(err) {
		return nil
	}

	if err != nil {
		return err
	}
	nl.Debugf(l, "processing virtual server resource")
	return c.sync(ctx, vs)
}

func externalDNSHandler(queue workqueue.TypedRateLimitingInterface[types.NamespacedName]) func(obj interface{}) {
	return func(obj interface{}) {
		ep, ok := obj.(*extdns_v1.DNSEndpoint)
		if !ok {
			runtime.HandleError(fmt.Errorf("not a DNSEndpoint object: %#v", obj))
			return
		}

		ref := metav1.GetControllerOf(ep)
		if ref == nil {
			// No controller should care about orphans being deleted or
			// updated.
			return
		}

		// We don't check the apiVersion
		// because there is no chance that another object called "VirtualServer" be
		// the controller of a DNSEndpoint.
		if ref.Kind != "VirtualServer" {
			return
		}

		key := types.NamespacedName{Namespace: ep.Namespace, Name: ref.Name}
		queue.Add(key)
	}
}

// BuildOpts builds the externalDNS controller options
func BuildOpts(ctx context.Context, ns []string, rdr record.EventRecorder, client k8s_nginx.Interface, resync time.Duration, idn bool) *ExtDNSOpts {
	return &ExtDNSOpts{
		context:       ctx,
		namespace:     ns,
		eventRecorder: rdr,
		client:        client,
		resyncPeriod:  resync,
		isDynamicNs:   idn,
	}
}

// AddNewNamespacedInformer adds watchers for a new namespace
func (c *ExtDNSController) AddNewNamespacedInformer(ns string) {
	l := nl.LoggerFromContext(c.ctx)
	nl.Debugf(l, "Adding or Updating external-dns Watchers for Namespace: %v", ns)
	nsi := c.informerGroup.Get(ns)
	if nsi == nil {
		var err error
		nsi, err = c.newNamespacedInformer(ns)
		if err != nil {
			nl.Errorf(l, "Failed to create external-dns namespaced informer for namespace %s: %v", ns, err)
			return
		}
		nsi.start()
	}
	if !cache.WaitForCacheSync(nsi.stopCh, nsi.mustSync...) {
		return
	}
}

// RemoveNamespacedInformer removes watchers for a namespace we are no longer watching
func (c *ExtDNSController) RemoveNamespacedInformer(ns string) {
	l := nl.LoggerFromContext(c.ctx)
	nl.Debugf(l, "Deleting external-dns Watchers for Deleted Namespace: %v", ns)
	// Remove waits for in-flight readers, so nothing is still reading it
	if nsi := c.informerGroup.Remove(ns); nsi != nil {
		nsi.stop()
	}
}

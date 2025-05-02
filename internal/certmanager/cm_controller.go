/*
Copyright 2020 The cert-manager Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package certmanager provides a controller for creating and managing
// certificates for VS resources.
package certmanager

import (
	"context"
	"fmt"
	"sync"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cm_clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cm_informers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	k8s_nginx "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned"
	vsinformers "github.com/nginx/kubernetes-ingress/pkg/client/informers/externalversions"
	listers_v1 "github.com/nginx/kubernetes-ingress/pkg/client/listers/configuration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	// ControllerName is the name of the certmanager controller
	ControllerName = "vs-cm-shim"

	// resyncPeriod is set to 10 hours across cert-manager. These 10 hours come
	// from a discussion on the controller-runtime project that boils down to:
	// never change this without an explicit reason.
	// https://github.com/kubernetes-sigs/controller-runtime/pull/88#issuecomment-408500629
	resyncPeriod = 10 * time.Hour
)

// CmController watches certificate and virtual server resources,
// and creates/ updates certificates for VS resources as required,
// and VS resources when certificate objects are created/ updated
type CmController struct {
	sync          SyncFn
	ctx           context.Context
	queue         workqueue.TypedRateLimitingInterface[types.NamespacedName]
	informerGroup map[string]*namespacedInformer
	recorder      record.EventRecorder
	cmClient      *cm_clientset.Clientset
	kubeClient    kubernetes.Interface
	vsClient      k8s_nginx.Interface
}

// CmOpts is the options required for building the CmController
type CmOpts struct {
	context       context.Context
	kubeConfig    *rest.Config
	kubeClient    kubernetes.Interface
	namespace     []string
	eventRecorder record.EventRecorder
	vsClient      k8s_nginx.Interface
	isDynamicNs   bool
}

type namespacedInformer struct {
	mustSync                  []cache.InformerSynced
	vsSharedInformerFactory   vsinformers.SharedInformerFactory
	cmSharedInformerFactory   cm_informers.SharedInformerFactory
	kubeSharedInformerFactory kubeinformers.SharedInformerFactory
	vsLister                  listers_v1.VirtualServerLister
	cmLister                  cmlisters.CertificateLister
	stopCh                    chan struct{}
	lock                      sync.RWMutex
}

func (c *CmController) register() workqueue.TypedRateLimitingInterface[types.NamespacedName] {
	c.sync = SyncFnFor(c.recorder, c.cmClient, c.informerGroup)
	return c.queue
}

// BuildOpts builds a CmOpts from the given parameters
func BuildOpts(ctx context.Context, kc *rest.Config, cl kubernetes.Interface, ns []string, er record.EventRecorder, vsc k8s_nginx.Interface, idn bool) *CmOpts {
	return &CmOpts{
		context:       ctx,
		kubeClient:    cl,
		kubeConfig:    kc,
		namespace:     ns,
		eventRecorder: er,
		vsClient:      vsc,
		isDynamicNs:   idn,
	}
}

func (c *CmController) newNamespacedInformer(ns string) *namespacedInformer {
	nsi := &namespacedInformer{}
	nsi.stopCh = make(chan struct{})
	nsi.cmSharedInformerFactory = cm_informers.NewSharedInformerFactoryWithOptions(c.cmClient, resyncPeriod, cm_informers.WithNamespace(ns))
	nsi.kubeSharedInformerFactory = kubeinformers.NewSharedInformerFactoryWithOptions(c.kubeClient, resyncPeriod, kubeinformers.WithNamespace(ns))
	nsi.vsSharedInformerFactory = vsinformers.NewSharedInformerFactoryWithOptions(c.vsClient, resyncPeriod, vsinformers.WithNamespace(ns))

	c.addHandlers(nsi)

	c.informerGroup[ns] = nsi
	return nsi
}

func (c *CmController) addHandlers(nsi *namespacedInformer) {
	nsi.vsLister = nsi.vsSharedInformerFactory.K8s().V1().VirtualServers().Lister()
	nsi.vsSharedInformerFactory.K8s().V1().VirtualServers().Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{
		Queue: c.queue,
	})
	nsi.mustSync = append(nsi.mustSync, nsi.vsSharedInformerFactory.K8s().V1().VirtualServers().Informer().HasSynced)

	nsi.cmSharedInformerFactory.Certmanager().V1().Certificates().Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: certificateHandler(c.queue),
	})
	nsi.cmLister = nsi.cmSharedInformerFactory.Certmanager().V1().Certificates().Lister()
	nsi.mustSync = append(nsi.mustSync, nsi.cmSharedInformerFactory.Certmanager().V1().Certificates().Informer().HasSynced)
}

func (c *CmController) processItem(ctx context.Context, key types.NamespacedName) error {
	l := nl.LoggerFromContext(ctx)
	nl.Debugf(l, "processing virtual server resource ")
	namespace := key.Namespace
	name := key.Name

	nsi := getNamespacedInformer(namespace, c.informerGroup)

	var vs *conf_v1.VirtualServer
	vs, err := nsi.vsLister.VirtualServers(namespace).Get(name)

	// VS has been deleted
	if apierrors.IsNotFound(err) {
		return nil
	}

	if err != nil {
		return err
	}
	return c.sync(ctx, vs)
}

// Whenever a Certificate gets updated, added or deleted, we want to reconcile
// its parent VirtualServer. This parent VirtualServer is called "controller object". For
// example, the following Certificate "cert-1" is controlled by the VirtualServer
// "vs-1":
//
//	kind: Certificate
//	metadata:                                           Note that the owner
//	  namespace: cert-1                                 reference does not
//	  ownerReferences:                                  have a namespace,
//	  - controller: true                                since owner refs
//	    apiVersion: networking.x-k8s.io/v1alpha1        only work inside
//	    kind: VirtualServer                             the same namespace.
//	    name: vs-1
//	    blockOwnerDeletion: true
//	    uid: 7d3897c2-ce27-4144-883a-e1b5f89bd65a
func certificateHandler(queue workqueue.TypedRateLimitingInterface[types.NamespacedName]) func(obj interface{}) {
	return func(obj interface{}) {
		crt, ok := obj.(*cmapi.Certificate)
		if !ok {
			runtime.HandleError(fmt.Errorf("not a Certificate object: %#v", obj))
			return
		}

		ref := metav1.GetControllerOf(crt)
		if ref == nil {
			// No controller should care about orphans being deleted or
			// updated.
			return
		}

		// We don't check the apiVersion
		// because there is no chance that another object called "VirtualServer" be
		// the controller of a Certificate.
		if ref.Kind != "VirtualServer" {
			return
		}

		queue.Add(types.NamespacedName{
			Namespace: crt.Namespace,
			Name:      ref.Name,
		})
	}
}

// NewCmController creates a new CmController
func NewCmController(opts *CmOpts) *CmController {
	// Create a cert-manager api client
	intcl, _ := cm_clientset.NewForConfig(opts.kubeConfig)

	ig := make(map[string]*namespacedInformer)

	cm := &CmController{
		ctx:           opts.context,
		queue:         workqueue.NewTypedRateLimitingQueueWithConfig(controllerpkg.DefaultItemBasedRateLimiter(), workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{Name: ControllerName}),
		informerGroup: ig,
		recorder:      opts.eventRecorder,
		cmClient:      intcl,
		kubeClient:    opts.kubeClient,
		vsClient:      opts.vsClient,
	}

	for _, ns := range opts.namespace {
		if opts.isDynamicNs && ns == "" {
			// no initial namespaces with watched label - skip creating informers for now
			break
		}
		cm.newNamespacedInformer(ns)
	}

	cm.register()
	return cm
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *CmController) Run(stopCh <-chan struct{}) {
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()

	l := nl.LoggerFromContext(ctx)

	nl.Info(l, "Starting cert-manager control loop")

	var mustSync []cache.InformerSynced
	for _, ig := range c.informerGroup {
		ig.start()
		mustSync = append(mustSync, ig.mustSync...)
	}
	// wait for all the informer caches we depend on are synced

	nl.Debugf(l, "Waiting for %d caches to sync", len(mustSync))
	if !cache.WaitForNamedCacheSync(ControllerName, stopCh, mustSync...) {
		nl.Fatal(l, "error syncing cm queue")
	}

	nl.Debugf(l, "Queue is %v", c.queue.Len())

	go c.runWorker(ctx)

	<-stopCh
	nl.Debugf(l, "shutting down queue as workqueue signaled shutdown")
	for _, ig := range c.informerGroup {
		ig.stop()
	}
	c.queue.ShutDown()
}

func (nsi *namespacedInformer) start() {
	go nsi.vsSharedInformerFactory.Start(nsi.stopCh)
	go nsi.cmSharedInformerFactory.Start(nsi.stopCh)
	go nsi.kubeSharedInformerFactory.Start(nsi.stopCh)
}

func (nsi *namespacedInformer) stop() {
	close(nsi.stopCh)
}

// runWorker is a long-running function that will continually call the
// processItem function in order to read and process a message on the
// workqueue.
func (c *CmController) runWorker(ctx context.Context) {
	l := nl.LoggerFromContext(ctx)
	nl.Debugf(l, "processing items on the workqueue")
	for {
		obj, shutdown := c.queue.Get()
		if shutdown {
			break
		}

		// use an inlined function so we can use defer
		func() {
			defer c.queue.Done(obj)

			err := c.processItem(ctx, obj)
			if err != nil {
				nl.Debugf(l, "Re-queuing item due to error processing: %v", err)
				c.queue.AddRateLimited(obj)
				return
			}
			nl.Debugf(l, "finished processing work item")
			c.queue.Forget(obj)
		}()
	}
}

// AddNewNamespacedInformer adds watchers for a new namespace
func (c *CmController) AddNewNamespacedInformer(ns string) {
	l := nl.LoggerFromContext(c.ctx)
	nl.Debugf(l, "Adding or Updating cert-manager Watchers for Namespace: %v", ns)
	nsi := getNamespacedInformer(ns, c.informerGroup)
	if nsi == nil {
		nsi = c.newNamespacedInformer(ns)
		nsi.start()
	}
	if !cache.WaitForCacheSync(nsi.stopCh, nsi.mustSync...) {
		return
	}
}

// RemoveNamespacedInformer removes watchers for a namespace we are no longer watching
func (c *CmController) RemoveNamespacedInformer(ns string) {
	l := nl.LoggerFromContext(c.ctx)
	nl.Debugf(l, "Deleting cert-manager Watchers for Deleted Namespace: %v", ns)
	nsi := getNamespacedInformer(ns, c.informerGroup)
	if nsi != nil {
		nsi.lock.Lock()
		defer nsi.lock.Unlock()
		nsi.stop()
		delete(c.informerGroup, ns)
		nsi = nil
	}
}

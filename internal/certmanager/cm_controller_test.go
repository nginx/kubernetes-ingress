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

package certmanager

import (
	"context"
	"fmt"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	testpkg "github.com/nginx/kubernetes-ingress/internal/certmanager/test_files"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	vsapi "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	k8s_nginx "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned"
)

func Test_controller_Register(t *testing.T) {
	tests := []struct {
		name              string
		existingVsObjects []runtime.Object
		existingCMObjects []runtime.Object
		givenCall         func(*testing.T, cmclient.Interface, k8s_nginx.Interface)
		expectRequeueKey  string
	}{
		{
			name: "virtualserver is re-queued when an 'Added' event is received for this virtualserver",
			givenCall: func(t *testing.T, _ cmclient.Interface, c k8s_nginx.Interface) {
				_, err := c.K8sV1().VirtualServers("namespace-1").Create(context.Background(), &vsapi.VirtualServer{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "vs-1",
				}}, metav1.CreateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: "namespace-1/vs-1",
		},
		{
			name: "virtualserver is re-queued when an 'Updated' event is received for this virtualserver",
			existingVsObjects: []runtime.Object{&vsapi.VirtualServer{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "vs-1",
			}}},
			givenCall: func(t *testing.T, _ cmclient.Interface, c k8s_nginx.Interface) {
				_, err := c.K8sV1().VirtualServers("namespace-1").Update(context.Background(), &vsapi.VirtualServer{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "vs-1",
				}}, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: "namespace-1/vs-1",
		},
		{
			name: "virtualserver is re-queued when a 'Deleted' event is received for this ingress",
			existingVsObjects: []runtime.Object{&vsapi.VirtualServer{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "vs-1",
			}}},
			givenCall: func(t *testing.T, _ cmclient.Interface, c k8s_nginx.Interface) {
				err := c.K8sV1().VirtualServers("namespace-1").Delete(context.Background(), "vs-1", metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: "namespace-1/vs-1",
		},
		{
			name: "virtualserver is re-queued when an 'Added' event is received for its child Certificate",
			givenCall: func(t *testing.T, c cmclient.Interface, _ k8s_nginx.Interface) {
				_, err := c.CertmanagerV1().Certificates("namespace-1").Create(context.Background(), &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "cert-1",
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&vsapi.VirtualServer{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "vs-2",
					}}, vsGVK)},
				}}, metav1.CreateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: "namespace-1/vs-2",
		},
		{
			name: "virtualserver is re-queued when an 'Updated' event is received for its child Certificate",
			existingCMObjects: []runtime.Object{&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "cert-1",
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&vsapi.VirtualServer{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "vs-2",
				}}, vsGVK)},
			}}},
			givenCall: func(t *testing.T, c cmclient.Interface, _ k8s_nginx.Interface) {
				_, err := c.CertmanagerV1().Certificates("namespace-1").Update(context.Background(), &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "cert-1",
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&vsapi.VirtualServer{ObjectMeta: metav1.ObjectMeta{
						Namespace: "namespace-1", Name: "vs-2",
					}}, vsGVK)},
				}}, metav1.UpdateOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: "namespace-1/vs-2",
		},
		{
			name: "virtualserver is re-queued when a 'Deleted' event is received for its child Certificate",
			existingCMObjects: []runtime.Object{&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace-1", Name: "cert-1",
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&vsapi.VirtualServer{ObjectMeta: metav1.ObjectMeta{
					Namespace: "namespace-1", Name: "vs-2",
				}}, vsGVK)},
			}}},
			givenCall: func(t *testing.T, c cmclient.Interface, _ k8s_nginx.Interface) {
				err := c.CertmanagerV1().Certificates("namespace-1").Delete(context.Background(), "cert-1", metav1.DeleteOptions{})
				require.NoError(t, err)
			},
			expectRequeueKey: "namespace-1/vs-2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &testpkg.Builder{T: t, CertManagerObjects: test.existingCMObjects, VSObjects: test.existingVsObjects}
			b.Init()

			// We don't care about the HasSynced functions since we already know
			// whether they have been properly "used": if no Gateway or
			// Certificate event is received then HasSynced has not been setup
			// properly.

			ig := make(map[string]*namespacedInformer)

			nsi := &namespacedInformer{
				cmSharedInformerFactory:   b.Context.SharedInformerFactory,
				kubeSharedInformerFactory: b.Context.KubeSharedInformerFactory,
				vsSharedInformerFactory:   b.VsSharedInformerFactory,
			}

			ig[""] = nsi

			cm := &CmController{
				ctx:           b.RootContext,
				queue:         workqueue.NewTypedRateLimitingQueueWithConfig(controllerpkg.DefaultItemBasedRateLimiter(), workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{Name: ControllerName}),
				informerGroup: ig,
				recorder:      b.Recorder,
				kubeClient:    b.Client,
				vsClient:      b.VSClient,
			}

			cm.addHandlers(nsi)

			queue := cm.register()

			b.Start()
			defer b.Stop()

			test.givenCall(t, b.CMClient, b.VSClient)

			// We have no way of knowing when the informers will be done adding
			// items to the queue due to the "shared informer" architecture:
			// Start(stop) does not allow you to wait for the informers to be
			// done. To work around that, we do a second queue.Get and expect it
			// to be nil.
			time.AfterFunc(50*time.Millisecond, queue.ShutDown)

			var gotKeys []string
			for {
				// Get blocks until either (1) a key is returned, or (2) the
				// queue is shut down.
				gotKey, done := queue.Get()
				if done {
					break
				}
				gotKeys = append(gotKeys, fmt.Sprintf("%s/%s", gotKey.Namespace, gotKey.Name))
			}
			assert.Equal(t, 0, queue.Len(), "queue should be empty")

			// We only expect 0 or 1 keys received in the queue.
			if test.expectRequeueKey != "" {
				assert.Equal(t, []string{test.expectRequeueKey}, gotKeys)
			} else {
				assert.Nil(t, gotKeys)
			}
		})
	}
}

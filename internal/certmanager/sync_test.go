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
	"errors"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coretesting "k8s.io/client-go/testing"

	testpkg "github.com/nginx/kubernetes-ingress/internal/certmanager/test_files"
	vsapi "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

func TestSync(t *testing.T) {
	clusterIssuer := gen.ClusterIssuer("cluster-issuer-name")
	issuer := gen.Issuer("issuer-name")
	type testT struct {
		Name                string
		VirtualServer       vsapi.VirtualServer
		Issuer              cmapi.GenericIssuer
		IssuerLister        []runtime.Object
		ClusterIssuerLister []runtime.Object
		CertificateLister   []runtime.Object
		Err                 bool
		ExpectedCreate      []*cmapi.Certificate
		ExpectedUpdate      []*cmapi.Certificate
		ExpectedDelete      []*cmapi.Certificate
		ExpectedEvents      []string
	}
	testVsShim := []testT{
		{
			Name:   "return a single Certificate for a virtual server with a single valid TLS entry and common-name field",
			Issuer: clusterIssuer,
			VirtualServer: *buildVirtualServer("vs-name", gen.DefaultTestNamespace, "secret-name", vsapi.CertManager{
				ClusterIssuer: "cluster-issuer-name", CommonName: "my-cn",
			}),
			ClusterIssuerLister: []runtime.Object{clusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "secret-name"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "secret-name",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "secret-name"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						CommonName: "my-cn",
						SecretName: "secret-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "cluster-issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		// {
		// 	Name: "should error if the specified issuer is not found",
		// 	VirtualServer: *buildVirtualServer("vs-name", gen.DefaultTestNamespace, "a-secret-name", vsapi.CertManager{
		// 		Issuer: "invalid-issuer-name"}),
		// 	IssuerLister: []runtime.Object{issuer},
		// },
		{
			Name:         "should not return any certificates if a correct Certificate already exists",
			Issuer:       issuer,
			IssuerLister: []runtime.Object{issuer},
			VirtualServer: *buildVirtualServer("vs-name", gen.DefaultTestNamespace, "existing-crt", vsapi.CertManager{
				Issuer: "issuer-name",
			}),
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "existing-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "existing-crt"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "existing-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should update a certificate if an incorrect Certificate exists",
			Issuer:       issuer,
			IssuerLister: []runtime.Object{issuer},
			VirtualServer: *buildVirtualServer("vs-name", gen.DefaultTestNamespace, "incorrect-cert", vsapi.CertManager{
				Issuer: "issuer-name", CommonName: "my-cn",
			}),
			CertificateLister: []runtime.Object{
				buildCertificate("incorrect-cert",
					gen.DefaultTestNamespace,
					buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "incorrect-cert"),
				),
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "incorrect-cert"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "incorrect-cert",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "incorrect-cert"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "incorrect-cert",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						CommonName: "my-cn",
						Usages:     cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should update an existing Certificate resource with new labels if they do not match those specified on the IngressLike",
			Issuer:       issuer,
			IssuerLister: []runtime.Object{issuer},
			VirtualServer: vsapi.VirtualServer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vs-name",
					Namespace: gen.DefaultTestNamespace,
					Labels: map[string]string{
						"my-test-label": "should be copied",
					},
					UID: types.UID("vs-name"),
				},
				Spec: vsapi.VirtualServerSpec{
					Host: "cafe.example.com",
					TLS: &vsapi.TLS{
						Secret: "update-cert",
						CertManager: &vsapi.CertManager{
							Issuer: "issuer-name",
						},
					},
				},
			},
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "update-cert",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"a-different-value": "should be removed",
						},
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "update-cert"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "update-cert",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "update-cert"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "update-cert",
						Namespace: gen.DefaultTestNamespace,
						Labels: map[string]string{
							"my-test-label": "should be copied",
						},
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "update-cert"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "update-cert",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should not update certificate if it does not belong to any virtual server",
			Issuer:       issuer,
			IssuerLister: []runtime.Object{issuer},
			VirtualServer: *buildVirtualServer("vs-name", gen.DefaultTestNamespace, "no-owner", vsapi.CertManager{
				Issuer: "issuer-name",
			}),
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "no-owner",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: []metav1.OwnerReference{},
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "no-owner",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should not update certificate if it does not belong to the virtualserver",
			Issuer:       issuer,
			IssuerLister: []runtime.Object{issuer},
			VirtualServer: *buildVirtualServer("vs-name", gen.DefaultTestNamespace, "wrong-owner", vsapi.CertManager{
				Issuer: "issuer-name",
			}),
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "wrong-owner",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildVsOwnerReferences("not-vs-name", gen.DefaultTestNamespace, "wrong-owner"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "wrong-owner",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:         "should delete a Certificate if its SecretName is not present in the virtual server",
			Issuer:       issuer,
			IssuerLister: []runtime.Object{issuer},
			VirtualServer: *buildVirtualServer("vs-name", gen.DefaultTestNamespace, "different-secret", vsapi.CertManager{
				Issuer: "issuer-name",
			}),
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "delete-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "delete-crt"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "delete-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "different-secret",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "different-secret"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "different-secret",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
			ExpectedEvents: []string{
				`Normal CreateCertificate Successfully created Certificate "different-secret"`,
				`Normal DeleteCertificate Successfully deleted unrequired Certificate "delete-crt"`,
			},
			ExpectedDelete: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "delete-crt",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "delete-crt"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "delete-crt",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
					},
				},
			},
		},
		{
			Name:         "should update a Certificate if is contains a Common Name that is not defined in the virtual server spec",
			Issuer:       issuer,
			IssuerLister: []runtime.Object{issuer},
			VirtualServer: *buildVirtualServer("vs-name", gen.DefaultTestNamespace, "no-cn", vsapi.CertManager{
				Issuer: "issuer-name",
			}),
			CertificateLister: []runtime.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "no-cn",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "no-cn"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "no-cn",
						CommonName: "example-common-name",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
			ExpectedEvents: []string{`Normal UpdateCertificate Successfully updated Certificate "no-cn"`},
			ExpectedUpdate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "no-cn",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "no-cn"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						SecretName: "no-cn",
						IssuerRef: cmmeta.ObjectReference{
							Name: "issuer-name",
							Kind: "Issuer",
						},
						Usages: cmapi.DefaultKeyUsages(),
					},
				},
			},
		},
		{
			Name:   "Failure to translateVsCmSpec",
			Issuer: issuer,
			VirtualServer: *buildVirtualServer("vs-name", gen.DefaultTestNamespace, "failed-cert", vsapi.CertManager{
				Issuer: "issuer-name", RenewBefore: "invalid renew before",
			}),
			Err:            true,
			ExpectedEvents: []string{`Warning BadConfig Incorrect cert-manager configuration for VirtualServer resource: invalid cert manager field "tls.cert-manager.renew-before": time: invalid duration "invalid renew before"`},
		},
		{
			Name:   "No TLS block specified",
			Issuer: issuer,
			VirtualServer: vsapi.VirtualServer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vs-name",
					Namespace: gen.DefaultTestNamespace,
					UID:       types.UID("vs-name"),
				},
				Spec: vsapi.VirtualServerSpec{
					Host: "cafe.example.com",
				},
			},
		},
		{
			Name:   "No CM block specified",
			Issuer: issuer,
			VirtualServer: vsapi.VirtualServer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vs-name",
					Namespace: gen.DefaultTestNamespace,
					UID:       types.UID("vs-name"),
				},
				Spec: vsapi.VirtualServerSpec{
					Host: "cafe.example.com",
					TLS: &vsapi.TLS{
						Secret: "secret-name",
					},
				},
			},
		},
		{
			Name:   "return a single Certificate for an ingress with a single valid TLS entry with common-name and keyusage annotation",
			Issuer: clusterIssuer,
			VirtualServer: *buildVirtualServer("vs-name", gen.DefaultTestNamespace, "my-cert", vsapi.CertManager{
				ClusterIssuer: "cluster-issuer-name", CommonName: "my-cn", Usages: "signing,digital signature,content commitment",
			}),
			ClusterIssuerLister: []runtime.Object{clusterIssuer},
			ExpectedEvents:      []string{`Normal CreateCertificate Successfully created Certificate "my-cert"`},
			ExpectedCreate: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "my-cert",
						Namespace:       gen.DefaultTestNamespace,
						OwnerReferences: buildVsOwnerReferences("vs-name", gen.DefaultTestNamespace, "my-cert"),
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:   []string{"cafe.example.com"},
						CommonName: "my-cn",
						SecretName: "my-cert",
						IssuerRef: cmmeta.ObjectReference{
							Name: "cluster-issuer-name",
							Kind: "ClusterIssuer",
						},
						Usages: []cmapi.KeyUsage{
							cmapi.UsageSigning,
							cmapi.UsageDigitalSignature,
							cmapi.UsageContentCommitment,
						},
					},
				},
			},
		},
	}

	testFn := func(test testT) func(t *testing.T) {
		return func(t *testing.T) {
			var allCMObjects []runtime.Object
			allCMObjects = append(allCMObjects, test.IssuerLister...)
			allCMObjects = append(allCMObjects, test.ClusterIssuerLister...)
			allCMObjects = append(allCMObjects, test.CertificateLister...)
			var expectedActions []testpkg.Action
			for _, cr := range test.ExpectedCreate {
				expectedActions = append(expectedActions,
					testpkg.NewAction(coretesting.NewCreateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						cr.Namespace,
						cr,
					)),
				)
			}
			for _, cr := range test.ExpectedUpdate {
				expectedActions = append(expectedActions,
					testpkg.NewAction(coretesting.NewUpdateAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						cr.Namespace,
						cr,
					)),
				)
			}
			for _, cr := range test.ExpectedDelete {
				expectedActions = append(expectedActions,
					testpkg.NewAction(coretesting.NewDeleteAction(
						cmapi.SchemeGroupVersion.WithResource("certificates"),
						cr.Namespace,
						cr.Name,
					)))
			}
			b := &testpkg.Builder{
				T:                  t,
				CertManagerObjects: allCMObjects,
				ExpectedActions:    expectedActions,
				ExpectedEvents:     test.ExpectedEvents,
			}
			b.Init()
			defer b.Stop()

			ig := make(map[string]*namespacedInformer)

			nsi := &namespacedInformer{
				cmSharedInformerFactory:   b.FakeCMInformerFactory(),
				kubeSharedInformerFactory: b.FakeKubeInformerFactory(),
				vsSharedInformerFactory:   b.VsSharedInformerFactory,
				cmLister:                  b.SharedInformerFactory.Certmanager().V1().Certificates().Lister(),
			}

			ig[""] = nsi

			sync := SyncFnFor(b.Recorder, b.CMClient, ig)
			b.Start()

			err := sync(context.Background(), &test.VirtualServer)

			// If test.Err == true, err should not be nil and vice versa
			if test.Err == (err == nil) {
				t.Errorf("Expected error: %v, but got: %v", test.Err, err)
			}

			if err := b.AllEventsCalled(); err != nil {
				t.Error(err)
			}
			if err := b.AllReactorsCalled(); err != nil {
				t.Errorf("Not all expected reactors were called: %v", err)
			}
			if err := b.AllActionsExecuted(); err != nil {
				t.Error(err.Error())
			}
		}
	}
	t.Run("vs-shim", func(t *testing.T) {
		for _, test := range testVsShim {
			t.Run(test.Name, testFn(test))
		}
	})
}

func TestIssuerForVirtualServer(t *testing.T) {
	type testT struct {
		VirtualServer *vsapi.VirtualServer
		DefaultName   string
		DefaultKind   string
		DefaultGroup  string
		ExpectedName  string
		ExpectedKind  string
		ExpectedGroup string
		ExpectedError error
	}
	tests := []testT{
		{
			VirtualServer: buildVirtualServer("name", "namespace", "secret-name", vsapi.CertManager{
				Issuer:      "issuer",
				IssuerGroup: "foo.bar",
			}),
			ExpectedName:  "issuer",
			ExpectedKind:  "Issuer",
			ExpectedGroup: "foo.bar",
		},
		{
			VirtualServer: buildVirtualServer("name", "namespace", "secret-name", vsapi.CertManager{
				ClusterIssuer: "clusterissuer",
			}),
			ExpectedName: "clusterissuer",
			ExpectedKind: "ClusterIssuer",
		},
		{
			VirtualServer: buildVirtualServer("name", "namespace", "secret-name", vsapi.CertManager{}),
			ExpectedError: errors.New("failed to determine Issuer name to be used for VirtualServer resource"),
		},
		{
			VirtualServer: buildVirtualServer("name", "namespace", "secret-name", vsapi.CertManager{
				ClusterIssuer: "clusterissuer",
				Issuer:        "issuer",
				IssuerGroup:   "group.io",
			}),
			ExpectedError: errors.New(`both "tls.cert-manager.issuer" and "tls.cert-manager.cluster-issuer" may not be set, both "tls.cert-manager.cluster-issuer" and "tls.cert-manager.issuer-group" may not be set`),
		},
	}
	for _, test := range tests {
		name, kind, group, err := issuerForVirtualServer(test.VirtualServer)
		if err != nil {
			if test.ExpectedError == nil || err.Error() != test.ExpectedError.Error() {
				t.Errorf("unexpected error, exp=%v got=%s", test.ExpectedError, err)
			}
		} else if test.ExpectedError != nil {
			t.Errorf("expected error but got nil: %s", test.ExpectedError)
		}

		if name != test.ExpectedName {
			t.Errorf("expected name to be %q but got %q", test.ExpectedName, name)
		}

		if kind != test.ExpectedKind {
			t.Errorf("expected kind to be %q but got %q", test.ExpectedKind, kind)
		}

		if group != test.ExpectedGroup {
			t.Errorf("expected group to be %q but got %q", test.ExpectedGroup, group)
		}
	}
}

func buildCertificate(name, namespace string, ownerReferences []metav1.OwnerReference) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			OwnerReferences: ownerReferences,
		},
		Spec: cmapi.CertificateSpec{
			SecretName: name,
		},
	}
}

func buildVirtualServer(name string, namespace string, secretName string, vsCmSpec vsapi.CertManager) *vsapi.VirtualServer {
	return &vsapi.VirtualServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID(name),
		},
		Spec: vsapi.VirtualServerSpec{
			Host: "cafe.example.com",
			TLS: &vsapi.TLS{
				Secret:      secretName,
				CertManager: &vsCmSpec,
			},
		},
	}
}

func buildVsOwnerReferences(name, namespace string, secretName string) []metav1.OwnerReference {
	return []metav1.OwnerReference{
		*metav1.NewControllerRef(buildVirtualServer(name, namespace, secretName, vsapi.CertManager{}), vsGVK),
	}
}

func Test_findCertificatesToBeRemoved(t *testing.T) {
	tests := []struct {
		name            string
		givenCerts      []*cmapi.Certificate
		virtualServer   *vsapi.VirtualServer
		wantToBeRemoved []string
	}{
		{
			name: "should not remove Certificate when not owned by the VirtualServer",
			givenCerts: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-1",
						Namespace:       "default",
						OwnerReferences: buildVsOwnerReferences("vs-1", "default", "secret-name"),
					}, Spec: cmapi.CertificateSpec{
						SecretName: "secret-name",
					},
				},
			},
			virtualServer: &vsapi.VirtualServer{
				ObjectMeta: metav1.ObjectMeta{Name: "vs-2", Namespace: "default", UID: "vs-2"},
				Spec:       vsapi.VirtualServerSpec{TLS: &vsapi.TLS{Secret: "secret-name"}},
			},
			wantToBeRemoved: nil,
		},
		{
			name: "should not remove Certificate when VirtualServer references the secretName of the Certificate",
			givenCerts: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-1",
						Namespace:       "default",
						OwnerReferences: buildVsOwnerReferences("vs-1", "default", "secret-name"),
					}, Spec: cmapi.CertificateSpec{
						SecretName: "secret-name",
					},
				},
			},
			virtualServer: &vsapi.VirtualServer{
				ObjectMeta: metav1.ObjectMeta{Name: "vs-1", Namespace: "default", UID: "vs-1"},
				Spec:       vsapi.VirtualServerSpec{TLS: &vsapi.TLS{Secret: "secret-name"}},
			},
			wantToBeRemoved: nil,
		},
		{
			name: "should remove Certificate when VirtualServer does not reference the secretName of the Certificate",
			givenCerts: []*cmapi.Certificate{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "cert-1",
						Namespace:       "default",
						OwnerReferences: buildVsOwnerReferences("vs-1", "default", "secret-name"),
					}, Spec: cmapi.CertificateSpec{
						SecretName: "secret-name",
					},
				},
			},
			virtualServer: &vsapi.VirtualServer{
				ObjectMeta: metav1.ObjectMeta{Name: "vs-1", Namespace: "default", UID: "vs-1"},
				Spec:       vsapi.VirtualServerSpec{TLS: &vsapi.TLS{Secret: "secret-name2"}},
			},
			wantToBeRemoved: []string{"cert-1"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotCerts := findCertificatesToBeRemoved(test.givenCerts, test.virtualServer)
			assert.Equal(t, test.wantToBeRemoved, gotCerts)
		})
	}
}

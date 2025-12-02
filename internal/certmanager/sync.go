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
	"errors"
	"fmt"
	"reflect"
	"strings"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	vsapi "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

var vsGVK = vsapi.SchemeGroupVersion.WithKind("VirtualServer")

// SyncFn is the reconciliation function passed to cert manager VS controller.
type SyncFn func(context.Context, *vsapi.VirtualServer) error

// SyncFnFor contains logic to reconcile VirtualServer objects.
//
// Reconciling a VirtualServer object with respect to Certificates means looking at its annotations
// and creating a Certificate with matching DNS names and secretNames from the
// TLS configuration of the VirtualServer object.
func SyncFnFor(
	rec record.EventRecorder,
	cmClient clientset.Interface,
	ig map[string]*namespacedInformer,
) SyncFn {
	return func(ctx context.Context, vs *vsapi.VirtualServer) error {
		var err error
		if vs.Spec.TLS == nil || vs.Spec.TLS.CertManager == nil {
			return nil
		}
		l := nl.LoggerFromContext(ctx)
		issuerName, issuerKind, issuerGroup, err := issuerForVirtualServer(vs)
		if err != nil {
			nl.Errorf(l, "Failed to determine issuer to be used for VirtualServer resource: %v", err)
			rec.Eventf(vs, corev1.EventTypeWarning, nl.EventReasonBadConfig, "Could not determine issuer for virtual server due to bad config: %s",
				err)
			return err
		}

		nsi := getNamespacedInformer(vs.GetNamespace(), ig)

		newCrts, updateCrts, err := buildCertificates(ctx, nsi.cmLister, vs, issuerName, issuerKind, issuerGroup)
		if err != nil {
			nl.Errorf(l, "Incorrect cert-manager configuration for VirtualServer resource: %v", err)
			rec.Eventf(vs, corev1.EventTypeWarning, nl.EventReasonBadConfig, "Incorrect cert-manager configuration for VirtualServer resource: %s",
				err)
			return err
		}

		for _, crt := range newCrts {
			_, err := cmClient.CertmanagerV1().Certificates(crt.Namespace).Create(ctx, crt, metav1.CreateOptions{})
			if err != nil {
				nl.Errorf(l, "Error issuing Certificate for VirtualServer resource: %v", err)
				rec.Eventf(vs, corev1.EventTypeWarning, nl.EventReasonBadConfig, "Error issuing Certificate for VirtualServer resource: %s",
					err)
				return err
			}
			rec.Eventf(vs, corev1.EventTypeNormal, nl.EventReasonCreateCertificate, "Successfully created Certificate %q", crt.Name)
		}

		for _, crt := range updateCrts {
			_, err := cmClient.CertmanagerV1().Certificates(crt.Namespace).Update(ctx, crt, metav1.UpdateOptions{})
			if err != nil {
				nl.Errorf(l, "Error updating Certificate for VirtualServer resource: %v", err)
				rec.Eventf(vs, corev1.EventTypeWarning, nl.EventReasonBadConfig, "Error updating Certificate for VirtualServer resource: %s",
					err)
				return err
			}
			rec.Eventf(vs, corev1.EventTypeNormal, nl.EventReasonUpdateCertificate, "Successfully updated Certificate %q", crt.Name)
		}
		var certs []*cmapi.Certificate

		certs, err = nsi.cmLister.Certificates(vs.GetNamespace()).List(labels.Everything())
		if err != nil {
			return err
		}
		unrequiredCertNames := findCertificatesToBeRemoved(certs, vs)

		for _, certName := range unrequiredCertNames {
			err = cmClient.CertmanagerV1().Certificates(vs.GetNamespace()).Delete(ctx, certName, metav1.DeleteOptions{})
			if err != nil {
				nl.Errorf(l, "Error deleting Certificate for VirtualServer resource: %v", err)
				return err
			}
			rec.Eventf(vs, corev1.EventTypeNormal, nl.EventReasonDeleteCertificate, "Successfully deleted unrequired Certificate %q", certName)
		}

		return nil
	}
}

func buildCertificates(
	ctx context.Context,
	cmLister cmlisters.CertificateLister,
	vs *vsapi.VirtualServer,
	issuerName, issuerKind, issuerGroup string,
) (newCert, update []*cmapi.Certificate, _ error) {
	var newCrts []*cmapi.Certificate
	var updateCrts []*cmapi.Certificate
	var existingCrt *cmapi.Certificate
	var err error

	existingCrt, err = cmLister.Certificates(vs.Namespace).Get(vs.Spec.TLS.Secret)

	if !apierrors.IsNotFound(err) && err != nil {
		return nil, nil, err
	}

	var controllerGVK schema.GroupVersionKind = vsGVK
	hosts := []string{vs.Spec.Host}

	crt := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:            vs.Spec.TLS.Secret,
			Namespace:       vs.Namespace,
			Labels:          vs.Labels,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(vs, controllerGVK)},
		},
		Spec: cmapi.CertificateSpec{
			DNSNames:   hosts,
			SecretName: vs.Spec.TLS.Secret,
			IssuerRef: cmmeta.ObjectReference{
				Name:  issuerName,
				Kind:  issuerKind,
				Group: issuerGroup,
			},
			Usages: cmapi.DefaultKeyUsages(),
		},
	}

	l := nl.LoggerFromContext(ctx)

	vs = vs.DeepCopy()

	if err := translateVsSpec(crt, vs.Spec.TLS.CertManager); err != nil {
		return nil, nil, err
	}

	// check if a Certificate for this TLS entry already exists, and if it
	// does then skip this entry
	if existingCrt != nil {
		nl.Debugf(l, "certificate already exists for this object, ensuring it is up to date")

		if metav1.GetControllerOf(existingCrt) == nil {
			nl.Debugf(l, "certificate resource has no owner. refusing to update non-owned certificate resource for object")
			return nil, nil, nil
		}

		if !metav1.IsControlledBy(existingCrt, vs) {
			nl.Debugf(l, "certificate resource is not owned by this object. refusing to update non-owned certificate resource for object")
			return nil, nil, nil
		}

		if !certNeedsUpdate(existingCrt, crt) {
			nl.Debugf(l, "certificate resource is already up to date for object")
			return nil, nil, nil
		}

		updateCrt := existingCrt.DeepCopy()

		updateCrt.Spec = crt.Spec
		updateCrt.Labels = crt.Labels

		updateCrts = append(updateCrts, updateCrt)
	} else {
		newCrts = append(newCrts, crt)
	}
	return newCrts, updateCrts, nil
}

func findCertificatesToBeRemoved(certs []*cmapi.Certificate, vs *vsapi.VirtualServer) []string {
	var toBeRemoved []string
	for _, crt := range certs {
		if !metav1.IsControlledBy(crt, vs) {
			continue
		}
		if !secretNameUsedIn(crt.Spec.SecretName, *vs) {
			toBeRemoved = append(toBeRemoved, crt.Name)
		}
	}
	return toBeRemoved
}

func secretNameUsedIn(secretName string, vs vsapi.VirtualServer) bool {
	return secretName == vs.Spec.TLS.Secret
}

// certNeedsUpdate checks and returns true if two Certificates differ.
func certNeedsUpdate(a, b *cmapi.Certificate) bool {
	if a.Name != b.Name {
		return true
	}

	// TODO: we may need to allow users to edit the managed Certificate resources
	// to add their own labels directly.
	// Right now, we'll reset/remove the label values back automatically.
	// Let's hope no other controllers do this automatically, else we'll start fighting...
	if !reflect.DeepEqual(a.Labels, b.Labels) {
		return true
	}

	if a.Spec.CommonName != b.Spec.CommonName {
		return true
	}

	if len(a.Spec.DNSNames) != len(b.Spec.DNSNames) {
		return true
	}

	for i := range a.Spec.DNSNames {
		if a.Spec.DNSNames[i] != b.Spec.DNSNames[i] {
			return true
		}
	}

	if a.Spec.SecretName != b.Spec.SecretName {
		return true
	}

	if a.Spec.IssuerRef.Name != b.Spec.IssuerRef.Name {
		return true
	}

	if a.Spec.IssuerRef.Kind != b.Spec.IssuerRef.Kind {
		return true
	}

	return false
}

// issuerForVirtualServer determines the Issuer that should be specified on a
// Certificate created for the given VirtualServer resource. We look up the following
// VS TLS Cert-Manager fields:
//
//	cluster-issuer
//	issuer
//	issuer-kind
//	issuer-group
func issuerForVirtualServer(vs *vsapi.VirtualServer) (name, kind, group string, err error) {
	var errs []string
	vsCmSpec := vs.Spec.TLS.CertManager
	var issuerNameOK, clusterIssuerNameOK, groupNameOK, kindNameOK bool

	if vsCmSpec.Issuer != "" {
		name = vsCmSpec.Issuer
		kind, issuerNameOK = cmapi.IssuerKind, true
	}

	if vsCmSpec.ClusterIssuer != "" {
		name = vsCmSpec.ClusterIssuer
		kind, clusterIssuerNameOK = cmapi.ClusterIssuerKind, true
	}

	if vsCmSpec.IssuerKind != "" {
		kind, kindNameOK = vsCmSpec.IssuerKind, true
	}

	if vsCmSpec.IssuerGroup != "" {
		group, groupNameOK = vsCmSpec.IssuerGroup, true
	}

	if len(name) == 0 {
		errs = append(errs, "failed to determine Issuer name to be used for VirtualServer resource")
	}

	if issuerNameOK && clusterIssuerNameOK {
		errs = append(errs,
			fmt.Sprintf("both %q and %q may not be set", issuerCmField, clusterIssuerCmField))
	}

	if clusterIssuerNameOK && groupNameOK {
		errs = append(errs,
			fmt.Sprintf("both %q and %q may not be set", clusterIssuerCmField, issuerGroupCmField))
	}

	if clusterIssuerNameOK && kindNameOK {
		errs = append(errs,
			fmt.Sprintf("both %q and %q may not be set", clusterIssuerCmField, issuerKindCmField))
	}

	if len(errs) > 0 {
		return "", "", "", errors.New(strings.Join(errs, ", "))
	}

	return name, kind, group, nil
}

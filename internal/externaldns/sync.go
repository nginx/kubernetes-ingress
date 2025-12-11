package externaldns

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-cmp/cmp"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	vsapi "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	extdnsapi "github.com/nginx/kubernetes-ingress/pkg/apis/externaldns/v1"
	clientset "github.com/nginx/kubernetes-ingress/pkg/client/clientset/versioned"
	extdnslisters "github.com/nginx/kubernetes-ingress/pkg/client/listers/externaldns/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	validators "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	netutils "k8s.io/utils/net"
)

const (
	recordTypeA     = "A"
	recordTypeAAAA  = "AAAA"
	recordTypeCNAME = "CNAME"
)

var vsGVK = vsapi.SchemeGroupVersion.WithKind("VirtualServer")

// SyncFn is the reconciliation function passed to externaldns controller.
type SyncFn func(context.Context, *vsapi.VirtualServer) error

// SyncFnFor knows how to reconcile VirtualServer DNSEndpoint object.
func SyncFnFor(rec record.EventRecorder, client clientset.Interface, ig map[string]*namespacedInformer) SyncFn {
	return func(ctx context.Context, vs *vsapi.VirtualServer) error {
		// Do nothing if ExternalDNS is not present (nil) in VS or is not enabled.
		if !vs.Spec.ExternalDNS.Enable {
			return nil
		}
		l := nl.LoggerFromContext(ctx)

		if vs.Status.ExternalEndpoints == nil {
			// It can take time for the external endpoints to sync - kick it back to the queue
			nl.Info(l, "Failed to determine external endpoints - retrying")
			return fmt.Errorf("failed to determine external endpoints")
		}

		targets, recordType, err := getValidTargets(ctx, vs.Status.ExternalEndpoints)
		if err != nil {
			nl.Error(l, "Invalid external endpoint")
			rec.Eventf(vs, corev1.EventTypeWarning, nl.EventReasonBadConfig, "Invalid external endpoint")
			return err
		}

		nsi := getNamespacedInformer(vs.Namespace, ig)

		newDNSEndpoint, updateDNSEndpoint, err := buildDNSEndpoint(ctx, nsi.extdnslister, vs, targets, recordType)
		if err != nil {
			nl.Errorf(l, "incorrect DNSEndpoint config for VirtualServer resource: %s", err)
			rec.Eventf(vs, corev1.EventTypeWarning, nl.EventReasonBadConfig, "Incorrect DNSEndpoint config for VirtualServer resource: %s", err)
			return err
		}

		var dep *extdnsapi.DNSEndpoint

		// Create new DNSEndpoint object
		if newDNSEndpoint != nil {
			nl.Debugf(l, "Creating DNSEndpoint for VirtualServer resource: %v", vs.Name)
			dep, err = client.ExternaldnsV1().DNSEndpoints(newDNSEndpoint.Namespace).Create(ctx, newDNSEndpoint, metav1.CreateOptions{})
			if err != nil {
				if apierrors.IsAlreadyExists(err) {
					// Another replica likely created the DNSEndpoint since we last checked - kick it back to the queue
					nl.Debugf(l, "DNSEndpoint has been created since we last checked - retrying")
					return fmt.Errorf("DNSEndpoint has already been created")
				}
				nl.Errorf(l, "Error creating DNSEndpoint for VirtualServer resource: %v", err)
				rec.Eventf(vs, corev1.EventTypeWarning, nl.EventReasonBadConfig, "Error creating DNSEndpoint for VirtualServer resource %s", err)
				return err
			}
			rec.Eventf(vs, corev1.EventTypeNormal, nl.EventReasonCreateDNSEndpoint, "Successfully created DNSEndpoint %q", newDNSEndpoint.Name)
			rec.Eventf(dep, corev1.EventTypeNormal, nl.EventReasonCreateDNSEndpoint, "Successfully created DNSEndpoint for VirtualServer %q", vs.Name)
		}

		// Update existing DNSEndpoint object
		if updateDNSEndpoint != nil {
			nl.Debugf(l, "Updating DNSEndpoint for VirtualServer resource: %v", vs.Name)
			dep, err = client.ExternaldnsV1().DNSEndpoints(updateDNSEndpoint.Namespace).Update(ctx, updateDNSEndpoint, metav1.UpdateOptions{})
			if err != nil {
				nl.Errorf(l, "Error updating DNSEndpoint endpoint for VirtualServer resource: %v", err)
				rec.Eventf(vs, corev1.EventTypeWarning, nl.EventReasonBadConfig, "Error updating DNSEndpoint for VirtualServer resource: %s", err)
				return err
			}
			rec.Eventf(vs, corev1.EventTypeNormal, nl.EventReasonUpdateDNSEndpoint, "Successfully updated DNSEndpoint %q", updateDNSEndpoint.Name)
			rec.Eventf(dep, corev1.EventTypeNormal, nl.EventReasonUpdateDNSEndpoint, "Successfully updated DNSEndpoint for VirtualServer %q", vs.Name)
		}
		return nil
	}
}

func getValidTargets(ctx context.Context, endpoints []vsapi.ExternalEndpoint) (extdnsapi.Targets, string, error) {
	var targets extdnsapi.Targets
	var recordType string
	var recordA bool
	var recordCNAME bool
	var recordAAAA bool
	var err error
	l := nl.LoggerFromContext(ctx)
	nl.Debugf(l, "Going through endpoints %v", endpoints)
	for _, e := range endpoints {
		if e.IP != "" {
			nl.Debugf(l, "IP is defined: %v", e.IP)
			if errMsg := validators.IsValidIPForLegacyField(field.NewPath(""), e.IP, false, nil); len(errMsg) > 0 {
				continue
			}
			ip := netutils.ParseIPSloppy(e.IP)
			if ip.To4() != nil {
				recordA = true
			} else {
				recordAAAA = true
			}
			targets = append(targets, e.IP)
		} else if e.Hostname != "" {
			nl.Debugf(l, "Hostname is defined: %v", e.Hostname)
			targets = append(targets, e.Hostname)
			recordCNAME = true
		}
	}
	if len(targets) == 0 {
		return targets, recordType, errors.New("valid targets not defined")
	}
	if recordA {
		recordType = recordTypeA
	} else if recordAAAA {
		recordType = recordTypeAAAA
	} else if recordCNAME {
		recordType = recordTypeCNAME
	} else {
		err = errors.New("recordType could not be determined")
	}
	return targets, recordType, err
}

func buildDNSEndpoint(ctx context.Context, extdnsLister extdnslisters.DNSEndpointLister, vs *vsapi.VirtualServer, targets extdnsapi.Targets, recordType string) (*extdnsapi.DNSEndpoint, *extdnsapi.DNSEndpoint, error) {
	var updateDNSEndpoint *extdnsapi.DNSEndpoint
	var newDNSEndpoint *extdnsapi.DNSEndpoint
	var existingDNSEndpoint *extdnsapi.DNSEndpoint
	var err error
	l := nl.LoggerFromContext(ctx)

	existingDNSEndpoint, err = extdnsLister.DNSEndpoints(vs.Namespace).Get(vs.ObjectMeta.Name)

	if !apierrors.IsNotFound(err) && err != nil {
		return nil, nil, err
	}
	var controllerGVK schema.GroupVersionKind = vsGVK
	ownerRef := *metav1.NewControllerRef(vs, controllerGVK)
	blockOwnerDeletion := false
	ownerRef.BlockOwnerDeletion = &blockOwnerDeletion

	dnsEndpoint := &extdnsapi.DNSEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:            vs.ObjectMeta.Name,
			Namespace:       vs.Namespace,
			Labels:          vs.Labels,
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
		Spec: extdnsapi.DNSEndpointSpec{
			Endpoints: []*extdnsapi.Endpoint{
				{
					DNSName:          vs.Spec.Host,
					Targets:          targets,
					RecordType:       buildRecordType(vs.Spec.ExternalDNS, recordType),
					RecordTTL:        buildTTL(vs.Spec.ExternalDNS),
					Labels:           buildLabels(vs.Spec.ExternalDNS),
					ProviderSpecific: buildProviderSpecificProperties(vs.Spec.ExternalDNS),
				},
			},
		},
	}

	vs = vs.DeepCopy()

	if existingDNSEndpoint != nil {
		nl.Debugf(l, "DNSEndpoint already exists for this object, ensuring it is up to date")
		if metav1.GetControllerOf(existingDNSEndpoint) == nil {
			nl.Debugf(l, "DNSEndpoint has no owner. refusing to update non-owned resource")
			return nil, nil, nil
		}
		if !metav1.IsControlledBy(existingDNSEndpoint, vs) {
			nl.Debugf(l, "external DNS endpoint resource is not owned by this object. refusing to update non-owned resource")
			return nil, nil, nil
		}
		if !extdnsendpointNeedsUpdate(existingDNSEndpoint, dnsEndpoint) {
			nl.Debugf(l, "external DNS resource is already up to date for object")
			return nil, nil, nil
		}

		updateDNSEndpoint = existingDNSEndpoint.DeepCopy()
		updateDNSEndpoint.Spec = dnsEndpoint.Spec
		updateDNSEndpoint.Labels = dnsEndpoint.Labels
		updateDNSEndpoint.Name = dnsEndpoint.Name
	} else {
		newDNSEndpoint = dnsEndpoint
	}
	return newDNSEndpoint, updateDNSEndpoint, nil
}

func buildTTL(extdnsSpec vsapi.ExternalDNS) extdnsapi.TTL {
	return extdnsapi.TTL(extdnsSpec.RecordTTL)
}

func buildRecordType(extdnsSpec vsapi.ExternalDNS, recordType string) string {
	if extdnsSpec.RecordType == "" {
		return recordType
	}
	return extdnsSpec.RecordType
}

func buildLabels(extdnsSpec vsapi.ExternalDNS) extdnsapi.Labels {
	if extdnsSpec.Labels == nil {
		return nil
	}
	labels := make(extdnsapi.Labels)
	for k, v := range extdnsSpec.Labels {
		labels[k] = v
	}
	return labels
}

func buildProviderSpecificProperties(extdnsSpec vsapi.ExternalDNS) extdnsapi.ProviderSpecific {
	if extdnsSpec.ProviderSpecific == nil {
		return nil
	}
	var providerSpecific extdnsapi.ProviderSpecific
	for _, pspecific := range extdnsSpec.ProviderSpecific {
		p := extdnsapi.ProviderSpecificProperty{
			Name:  pspecific.Name,
			Value: pspecific.Value,
		}
		providerSpecific = append(providerSpecific, p)
	}
	return providerSpecific
}

func extdnsendpointNeedsUpdate(dnsA, dnsB *extdnsapi.DNSEndpoint) bool {
	if !cmp.Equal(dnsA.ObjectMeta.Name, dnsB.ObjectMeta.Name) {
		return true
	}
	if !cmp.Equal(dnsA.Labels, dnsB.Labels) {
		return true
	}
	if !cmp.Equal(dnsA.Spec, dnsB.Spec) {
		return true
	}
	return false
}

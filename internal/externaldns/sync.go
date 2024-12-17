package externaldns

import (
	"context"
	"fmt"

	"github.com/google/go-cmp/cmp"
	nl "github.com/nginxinc/kubernetes-ingress/internal/logger"
	vsapi "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	extdnsapi "github.com/nginxinc/kubernetes-ingress/pkg/apis/externaldns/v1"
	externaldns_validation "github.com/nginxinc/kubernetes-ingress/pkg/apis/externaldns/validation"
	clientset "github.com/nginxinc/kubernetes-ingress/pkg/client/clientset/versioned"
	extdnslisters "github.com/nginxinc/kubernetes-ingress/pkg/client/listers/externaldns/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	netutils "k8s.io/utils/net"
)

const (
	reasonBadConfig         = "BadConfig"
	reasonCreateDNSEndpoint = "CreateDNSEndpoint"
	reasonUpdateDNSEndpoint = "UpdateDNSEndpoint"
	recordTypeA             = "A"
	recordTypeAAAA          = "AAAA"
	recordTypeCNAME         = "CNAME"
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

		if vs.Status.ExternalEndpoints == nil && len(vs.Spec.ExternalDNS.Targets) == 0 {
			// It can take time for the external endpoints to sync - kick it back to the queue
			nl.Info(l, "Failed to determine external endpoints - retrying")
			return fmt.Errorf("failed to determine external endpoints")
		}

		targets, recordType, err := getValidTargets(vs.Status.ExternalEndpoints, vs.Spec.ExternalDNS.Targets)
		if err != nil {
			errorText := fmt.Sprintf("Invalid targets: %v", err)
			nl.Error(l, errorText)
			rec.Event(vs, corev1.EventTypeWarning, reasonBadConfig, errorText)
			return err
		}

		nsi := getNamespacedInformer(vs.Namespace, ig)

		newDNSEndpoint, updateDNSEndpoint, err := buildDNSEndpoint(ctx, nsi.extdnslister, vs, targets, recordType)
		if err != nil {
			nl.Errorf(l, "incorrect DNSEndpoint config for VirtualServer resource: %s", err)
			rec.Eventf(vs, corev1.EventTypeWarning, reasonBadConfig, "Incorrect DNSEndpoint config for VirtualServer resource: %s", err)
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
				rec.Eventf(vs, corev1.EventTypeWarning, reasonBadConfig, "Error creating DNSEndpoint for VirtualServer resource %s", err)
				return err
			}
			rec.Eventf(vs, corev1.EventTypeNormal, reasonCreateDNSEndpoint, "Successfully created DNSEndpoint %q", newDNSEndpoint.Name)
			rec.Eventf(dep, corev1.EventTypeNormal, reasonCreateDNSEndpoint, "Successfully created DNSEndpoint for VirtualServer %q", vs.Name)
		}

		// Update existing DNSEndpoint object
		if updateDNSEndpoint != nil {
			nl.Debugf(l, "Updating DNSEndpoint for VirtualServer resource: %v", vs.Name)
			dep, err = client.ExternaldnsV1().DNSEndpoints(updateDNSEndpoint.Namespace).Update(ctx, updateDNSEndpoint, metav1.UpdateOptions{})
			if err != nil {
				nl.Errorf(l, "Error updating DNSEndpoint endpoint for VirtualServer resource: %v", err)
				rec.Eventf(vs, corev1.EventTypeWarning, reasonBadConfig, "Error updating DNSEndpoint for VirtualServer resource: %s", err)
				return err
			}
			rec.Eventf(vs, corev1.EventTypeNormal, reasonUpdateDNSEndpoint, "Successfully updated DNSEndpoint %q", updateDNSEndpoint.Name)
			rec.Eventf(dep, corev1.EventTypeNormal, reasonUpdateDNSEndpoint, "Successfully updated DNSEndpoint for VirtualServer %q", vs.Name)
		}
		return nil
	}
}

func getValidTargets(endpoints []vsapi.ExternalEndpoint, chosenTargets extdnsapi.Targets) (extdnsapi.Targets, string, error) {
	if len(chosenTargets) > 0 {
		return externaldns_validation.ValidateTargetsAndDetermineRecordType(chosenTargets)
	}

	var ipv4Targets, ipv6Targets, cnameTargets []string
	for _, e := range endpoints {
		if e.IP != "" {
			ip := netutils.ParseIPSloppy(e.IP)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				ipv4Targets = append(ipv4Targets, e.IP)
			} else {
				ipv6Targets = append(ipv6Targets, e.IP)
			}
		} else if e.Hostname != "" {
			cnameTargets = append(cnameTargets, e.Hostname)
		}
	}

	//priority: prefer IPv4 > IPv6 > CNAME
	if len(ipv4Targets) > 0 {
		if err := externaldns_validation.IsUnique(ipv4Targets); err != nil {
			return nil, "", err
		}
		return ipv4Targets, "A", nil
	} else if len(ipv6Targets) > 0 {
		if err := externaldns_validation.IsUnique(ipv6Targets); err != nil {
			return nil, "", err
		}
		return ipv6Targets, "AAAA", nil
	} else if len(cnameTargets) > 0 {
		if err := externaldns_validation.IsUnique(cnameTargets); err != nil {
			return nil, "", err
		}
		for _, h := range cnameTargets {
			if err := externaldns_validation.IsFullyQualifiedDomainName(h); err != nil {
				return nil, "", fmt.Errorf("%w: target %q is invalid: %v", externaldns_validation.ErrTypeInvalid, h, err)
			}
		}
		return cnameTargets, "CNAME", nil
	}

	return nil, "", fmt.Errorf("no valid external endpoints found")
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

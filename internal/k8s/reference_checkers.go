package k8s

import (
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	networking "k8s.io/api/networking/v1"
)

type resourceReferenceChecker interface {
	IsReferencedByIngress(namespace string, name string, ing *networking.Ingress) bool
	IsReferencedByMinion(namespace string, name string, ing *networking.Ingress) bool
	IsReferencedByVirtualServer(namespace string, name string, vs *conf_v1.VirtualServer) bool
	IsReferencedByVirtualServerRoute(namespace string, name string, vsr *conf_v1.VirtualServerRoute) bool
	IsReferencedByTransportServer(namespace string, name string, ts *conf_v1.TransportServer) bool
}

type secretReferenceChecker struct {
	isPlus bool
}

func newSecretReferenceChecker(isPlus bool) *secretReferenceChecker {
	return &secretReferenceChecker{isPlus}
}

func (rc *secretReferenceChecker) IsReferencedByIngress(secretNamespace string, secretName string, ing *networking.Ingress) bool {
	if ing.Namespace != secretNamespace {
		return false
	}

	for _, tls := range ing.Spec.TLS {
		if tls.SecretName == secretName {
			return true
		}
	}

	if rc.isPlus {
		if jwtKey, exists := ing.Annotations[configs.JWTKeyAnnotation]; exists {
			if jwtKey == secretName {
				return true
			}
		}
	}

	if basicAuth, exists := ing.Annotations[configs.BasicAuthSecretAnnotation]; exists {
		if basicAuth == secretName {
			return true
		}
	}

	return false
}

func (rc *secretReferenceChecker) IsReferencedByMinion(secretNamespace string, secretName string, ing *networking.Ingress) bool {
	if ing.Namespace != secretNamespace {
		return false
	}

	if rc.isPlus {
		if jwtKey, exists := ing.Annotations[configs.JWTKeyAnnotation]; exists {
			if jwtKey == secretName {
				return true
			}
		}
	}

	if basicAuth, exists := ing.Annotations[configs.BasicAuthSecretAnnotation]; exists {
		if basicAuth == secretName {
			return true
		}
	}

	return false
}

func (rc *secretReferenceChecker) IsReferencedByVirtualServer(secretNamespace string, secretName string, vs *conf_v1.VirtualServer) bool {
	if vs.Namespace != secretNamespace {
		return false
	}

	if vs.Spec.TLS != nil && vs.Spec.TLS.Secret == secretName {
		return true
	}

	return false
}

func (rc *secretReferenceChecker) IsReferencedByVirtualServerRoute(_ string, _ string, _ *conf_v1.VirtualServerRoute) bool {
	return false
}

func (rc *secretReferenceChecker) IsReferencedByTransportServer(secretNamespace string, secretName string, ts *conf_v1.TransportServer) bool {
	if ts.Namespace != secretNamespace {
		return false
	}

	if ts.Spec.TLS != nil && ts.Spec.TLS.Secret == secretName {
		return true
	}

	return false
}

type serviceReferenceChecker struct {
	hasClusterIP bool
}

func newServiceReferenceChecker(hasClusterIP bool) *serviceReferenceChecker {
	return &serviceReferenceChecker{hasClusterIP}
}

func (rc *serviceReferenceChecker) IsReferencedByIngress(svcNamespace string, svcName string, ing *networking.Ingress) bool {
	if ing.Namespace != svcNamespace {
		return false
	}

	if ing.Spec.DefaultBackend != nil {
		if ing.Spec.DefaultBackend.Service.Name == svcName {
			return true
		}
	}
	for _, rules := range ing.Spec.Rules {
		if rules.IngressRuleValue.HTTP == nil {
			continue
		}
		for _, p := range rules.IngressRuleValue.HTTP.Paths {
			if p.Backend.Service.Name == svcName {
				return true
			}
		}
	}

	return false
}

func (rc *serviceReferenceChecker) IsReferencedByMinion(svcNamespace string, svcName string, ing *networking.Ingress) bool {
	return rc.IsReferencedByIngress(svcNamespace, svcName, ing)
}

func (rc *serviceReferenceChecker) IsReferencedByVirtualServer(svcNamespace string, svcName string, vs *conf_v1.VirtualServer) bool {
	if vs.Namespace != svcNamespace {
		return false
	}

	for _, u := range vs.Spec.Upstreams {
		if rc.hasClusterIP && u.UseClusterIP {
			continue
		}
		if u.Service == svcName || u.Backup == svcName {
			return true
		}
	}

	return false
}

func (rc *serviceReferenceChecker) IsReferencedByVirtualServerRoute(svcNamespace string, svcName string, vsr *conf_v1.VirtualServerRoute) bool {
	if vsr.Namespace != svcNamespace {
		return false
	}

	for _, u := range vsr.Spec.Upstreams {
		if rc.hasClusterIP && u.UseClusterIP {
			continue
		}
		if u.Service == svcName {
			return true
		}
	}

	return false
}

func (rc *serviceReferenceChecker) IsReferencedByTransportServer(svcNamespace string, svcName string, ts *conf_v1.TransportServer) bool {
	if ts.Namespace != svcNamespace {
		return false
	}

	for _, u := range ts.Spec.Upstreams {
		if u.Service == svcName || u.Backup == svcName {
			return true
		}
	}

	return false
}

type policyReferenceChecker struct{}

func newPolicyReferenceChecker() *policyReferenceChecker {
	return &policyReferenceChecker{}
}

func (rc *policyReferenceChecker) IsReferencedByIngress(_ string, _ string, _ *networking.Ingress) bool {
	return false
}

func (rc *policyReferenceChecker) IsReferencedByMinion(_ string, _ string, _ *networking.Ingress) bool {
	return false
}

func (rc *policyReferenceChecker) IsReferencedByVirtualServer(policyNamespace string, policyName string, vs *conf_v1.VirtualServer) bool {
	if isPolicyReferenced(vs.Spec.Policies, vs.Namespace, policyNamespace, policyName) {
		return true
	}

	for _, r := range vs.Spec.Routes {
		if isPolicyReferenced(r.Policies, vs.Namespace, policyNamespace, policyName) {
			return true
		}
	}

	return false
}

func (rc *policyReferenceChecker) IsReferencedByVirtualServerRoute(policyNamespace string, policyName string, vsr *conf_v1.VirtualServerRoute) bool {
	for _, r := range vsr.Spec.Subroutes {
		if isPolicyReferenced(r.Policies, vsr.Namespace, policyNamespace, policyName) {
			return true
		}
	}

	return false
}

func (rc *policyReferenceChecker) IsReferencedByTransportServer(_ string, _ string, _ *conf_v1.TransportServer) bool {
	return false
}

// appProtectResourceReferenceChecker is a reference checker for AppProtect related resources.
// Only Regular/Master Ingress can reference those resources.
type appProtectResourceReferenceChecker struct {
	annotation string
}

func newAppProtectResourceReferenceChecker(annotation string) *appProtectResourceReferenceChecker {
	return &appProtectResourceReferenceChecker{annotation}
}

func (rc *appProtectResourceReferenceChecker) IsReferencedByIngress(namespace string, name string, ing *networking.Ingress) bool {
	if resName, exists := ing.Annotations[rc.annotation]; exists {
		resNames := strings.Split(resName, ",")
		for _, res := range resNames {
			if res == namespace+"/"+name || (namespace == ing.Namespace && res == name) {
				return true
			}
		}
	}
	return false
}

func (rc *appProtectResourceReferenceChecker) IsReferencedByMinion(_ string, _ string, _ *networking.Ingress) bool {
	return false
}

func (rc *appProtectResourceReferenceChecker) IsReferencedByVirtualServer(_ string, _ string, _ *conf_v1.VirtualServer) bool {
	return false
}

func (rc *appProtectResourceReferenceChecker) IsReferencedByVirtualServerRoute(_ string, _ string, _ *conf_v1.VirtualServerRoute) bool {
	return false
}

func (rc *appProtectResourceReferenceChecker) IsReferencedByTransportServer(_ string, _ string, _ *conf_v1.TransportServer) bool {
	return false
}

func isPolicyReferenced(policies []conf_v1.PolicyReference, resourceNamespace string, policyNamespace string, policyName string) bool {
	for _, p := range policies {
		namespace := p.Namespace
		if namespace == "" {
			namespace = resourceNamespace
		}

		if p.Name == policyName && namespace == policyNamespace {
			return true
		}
	}

	return false
}

type dosResourceReferenceChecker struct {
	annotation string
}

func newDosResourceReferenceChecker(annotation string) *dosResourceReferenceChecker {
	return &dosResourceReferenceChecker{annotation}
}

func (rc *dosResourceReferenceChecker) IsReferencedByIngress(namespace string, name string, ing *networking.Ingress) bool {
	res, exists := ing.Annotations[rc.annotation]
	if !exists {
		return false
	}
	return res == namespace+"/"+name || (namespace == ing.Namespace && res == name)
}

func (rc *dosResourceReferenceChecker) IsReferencedByMinion(_ string, _ string, _ *networking.Ingress) bool {
	return false
}

func (rc *dosResourceReferenceChecker) IsReferencedByVirtualServer(namespace string, name string, vs *conf_v1.VirtualServer) bool {
	if vs.Spec.Dos == namespace+"/"+name || (namespace == vs.Namespace && vs.Spec.Dos == name) {
		return true
	}
	for _, route := range vs.Spec.Routes {
		if route.Dos == namespace+"/"+name || (namespace == vs.Namespace && route.Dos == name) {
			return true
		}
	}
	return false
}

func (rc *dosResourceReferenceChecker) IsReferencedByVirtualServerRoute(namespace string, name string, vsr *conf_v1.VirtualServerRoute) bool {
	for _, route := range vsr.Spec.Subroutes {
		if route.Dos == namespace+"/"+name || (namespace == vsr.Namespace && route.Dos == name) {
			return true
		}
	}
	return false
}

func (rc *dosResourceReferenceChecker) IsReferencedByTransportServer(_ string, _ string, _ *conf_v1.TransportServer) bool {
	return false
}

type ratelimitScalingAnnotationChecker struct{}

func (rc *ratelimitScalingAnnotationChecker) IsReferencedByIngress(_ string, _ string, ing *networking.Ingress) bool {
	for key, value := range ing.Annotations {
		if key == "nginx.org/limit-req-scale" && value == "true" {
			return true
		}
	}

	return false
}

func (rc *ratelimitScalingAnnotationChecker) IsReferencedByMinion(svcNamespace string, svcName string, ing *networking.Ingress) bool {
	return rc.IsReferencedByIngress(svcNamespace, svcName, ing)
}

func (rc *ratelimitScalingAnnotationChecker) IsReferencedByVirtualServer(_ string, _ string, _ *conf_v1.VirtualServer) bool {
	return false
}

func (rc *ratelimitScalingAnnotationChecker) IsReferencedByVirtualServerRoute(_ string, _ string, _ *conf_v1.VirtualServerRoute) bool {
	return false
}

func (rc *ratelimitScalingAnnotationChecker) IsReferencedByTransportServer(_ string, _ string, _ *conf_v1.TransportServer) bool {
	return false
}

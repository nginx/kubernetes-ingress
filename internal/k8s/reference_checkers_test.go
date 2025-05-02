package k8s

import (
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	networking "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSecretIsReferencedByIngress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ing             *networking.Ingress
		secretNamespace string
		secretName      string
		isPlus          bool
		expected        bool
		msg             string
	}{
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: networking.IngressSpec{
					TLS: []networking.IngressTLS{
						{
							SecretName: "test-secret",
						},
					},
				},
			},
			secretNamespace: "default",
			secretName:      "test-secret",
			isPlus:          false,
			expected:        true,
			msg:             "tls secret is referenced",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: networking.IngressSpec{
					TLS: []networking.IngressTLS{
						{
							SecretName: "test-secret",
						},
					},
				},
			},
			secretNamespace: "default",
			secretName:      "some-secret",
			isPlus:          false,
			expected:        false,
			msg:             "wrong name for tls secret",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: networking.IngressSpec{
					TLS: []networking.IngressTLS{
						{
							SecretName: "test-secret",
						},
					},
				},
			},
			secretNamespace: "some-namespace",
			secretName:      "test-secret",
			isPlus:          false,
			expected:        false,
			msg:             "wrong namespace for tls secret",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.JWTKeyAnnotation: "test-secret",
					},
				},
			},
			secretNamespace: "default",
			secretName:      "test-secret",
			isPlus:          true,
			expected:        true,
			msg:             "jwt secret is referenced for Plus",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.JWTKeyAnnotation: "test-secret",
					},
				},
			},
			secretNamespace: "default",
			secretName:      "some-secret",
			isPlus:          true,
			expected:        false,
			msg:             "wrong namespace for jwt secret for Plus",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.JWTKeyAnnotation: "test-secret",
					},
				},
			},
			secretNamespace: "default",
			secretName:      "some-secret",
			isPlus:          true,
			expected:        false,
			msg:             "wrong name for jwt secret for Plus",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.JWTKeyAnnotation: "test-secret",
					},
				},
			},
			secretNamespace: "some-namespace",
			secretName:      "test-secret",
			isPlus:          false,
			expected:        false,
			msg:             "jwt secret for NGINX OSS is ignored",
		},
	}

	for _, test := range tests {
		rc := newSecretReferenceChecker(test.isPlus)

		result := rc.IsReferencedByIngress(test.secretNamespace, test.secretName, test.ing)
		if result != test.expected {
			t.Errorf("IsReferencedByIngress() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestSecretIsReferencedByMinion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ing             *networking.Ingress
		secretNamespace string
		secretName      string
		isPlus          bool
		expected        bool
		msg             string
	}{
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.JWTKeyAnnotation: "test-secret",
					},
				},
			},
			secretNamespace: "default",
			secretName:      "test-secret",
			isPlus:          true,
			expected:        true,
			msg:             "jwt secret is referenced for Plus",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.JWTKeyAnnotation: "test-secret",
					},
				},
			},
			secretNamespace: "default",
			secretName:      "some-secret",
			isPlus:          true,
			expected:        false,
			msg:             "wrong namespace for jwt secret for Plus",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.JWTKeyAnnotation: "test-secret",
					},
				},
			},
			secretNamespace: "default",
			secretName:      "some-secret",
			isPlus:          true,
			expected:        false,
			msg:             "wrong name for jwt secret for Plus",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.JWTKeyAnnotation: "test-secret",
					},
				},
			},
			secretNamespace: "default",
			secretName:      "test-secret",
			isPlus:          false,
			expected:        false,
			msg:             "jwt secret for NGINX OSS is ignored",
		},
	}

	for _, test := range tests {
		rc := newSecretReferenceChecker(test.isPlus)

		result := rc.IsReferencedByMinion(test.secretNamespace, test.secretName, test.ing)
		if result != test.expected {
			t.Errorf("IsReferencedByMinion() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestSecretIsReferencedByVirtualServer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		vs              *conf_v1.VirtualServer
		secretNamespace string
		secretName      string
		expected        bool
		msg             string
	}{
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					TLS: &conf_v1.TLS{
						Secret: "test-secret",
					},
				},
			},
			secretNamespace: "default",
			secretName:      "test-secret",
			expected:        true,
			msg:             "tls secret is referenced",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					TLS: &conf_v1.TLS{
						Secret: "test-secret",
					},
				},
			},
			secretNamespace: "default",
			secretName:      "some-secret",
			expected:        false,
			msg:             "wrong name for tls secret",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					TLS: &conf_v1.TLS{
						Secret: "test-secret",
					},
				},
			},
			secretNamespace: "some-namespace",
			secretName:      "test-secret",
			expected:        false,
			msg:             "wrong namespace for tls secret",
		},
	}

	for _, test := range tests {
		isPlus := false // doesn't matter for VirtualServer
		rc := newSecretReferenceChecker(isPlus)

		result := rc.IsReferencedByVirtualServer(test.secretNamespace, test.secretName, test.vs)
		if result != test.expected {
			t.Errorf("IsReferencedByVirtualServer() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestSecretIsReferencedByVirtualServerRoute(t *testing.T) {
	t.Parallel()
	isPlus := false // doesn't matter for VirtualServerRoute
	rc := newSecretReferenceChecker(isPlus)

	result := rc.IsReferencedByVirtualServerRoute("", "", nil)
	if result != false {
		t.Error("IsReferencedByVirtualServer() returned true but expected false")
	}
}

func TestSecretIsReferencedByTransportServer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ts              *conf_v1.TransportServer
		secretNamespace string
		secretName      string
		expected        bool
		msg             string
	}{
		{
			ts: &conf_v1.TransportServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.TransportServerSpec{
					TLS: &conf_v1.TransportServerTLS{
						Secret: "test-secret",
					},
				},
			},
			secretNamespace: "default",
			secretName:      "test-secret",
			expected:        true,
			msg:             "tls secret is referenced",
		},
		{
			ts: &conf_v1.TransportServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.TransportServerSpec{
					TLS: &conf_v1.TransportServerTLS{
						Secret: "test-secret",
					},
				},
			},
			secretNamespace: "other-namespace",
			secretName:      "test-secret",
			expected:        false,
			msg:             "tls secret is referenced but in another namespace",
		},
		{
			ts: &conf_v1.TransportServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.TransportServerSpec{},
			},
			secretNamespace: "other-namespace",
			secretName:      "test-secret",
			expected:        false,
			msg:             "tls secret is not but in another namespace",
		},
	}

	for _, test := range tests {
		isPlus := false // doesn't matter for TransportServer
		rc := newSecretReferenceChecker(isPlus)

		// always returns false
		result := rc.IsReferencedByTransportServer(test.secretNamespace, test.secretName, test.ts)
		if result != test.expected {
			t.Errorf("IsReferencedByTransportServer() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestServiceIsReferencedByIngressAndMinion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ing              *networking.Ingress
		serviceNamespace string
		serviceName      string
		expected         bool
		msg              string
	}{
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: networking.IngressSpec{
					DefaultBackend: &networking.IngressBackend{
						Service: &networking.IngressServiceBackend{
							Name: "test-service",
						},
					},
				},
			},
			serviceNamespace: "default",
			serviceName:      "test-service",
			expected:         true,
			msg:              "service is referenced in the default backend",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							IngressRuleValue: networking.IngressRuleValue{
								HTTP: &networking.HTTPIngressRuleValue{
									Paths: []networking.HTTPIngressPath{
										{
											Backend: networking.IngressBackend{
												Service: &networking.IngressServiceBackend{
													Name: "test-service",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			serviceNamespace: "default",
			serviceName:      "test-service",
			expected:         true,
			msg:              "service is referenced in a path",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							IngressRuleValue: networking.IngressRuleValue{
								HTTP: &networking.HTTPIngressRuleValue{
									Paths: []networking.HTTPIngressPath{
										{
											Backend: networking.IngressBackend{
												Service: &networking.IngressServiceBackend{
													Name: "test-service",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			serviceNamespace: "default",
			serviceName:      "some-service",
			expected:         false,
			msg:              "wrong name for service in a path",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							IngressRuleValue: networking.IngressRuleValue{
								HTTP: &networking.HTTPIngressRuleValue{
									Paths: []networking.HTTPIngressPath{
										{
											Backend: networking.IngressBackend{
												Service: &networking.IngressServiceBackend{
													Name: "test-service",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			serviceNamespace: "some-namespace",
			serviceName:      "test-service",
			expected:         false,
			msg:              "wrong namespace for service in a path",
		},
	}

	for _, test := range tests {
		rc := newServiceReferenceChecker(false)

		result := rc.IsReferencedByIngress(test.serviceNamespace, test.serviceName, test.ing)
		if result != test.expected {
			t.Errorf("IsReferencedByIngress() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}

		// same cases for Minions
		result = rc.IsReferencedByMinion(test.serviceNamespace, test.serviceName, test.ing)
		if result != test.expected {
			t.Errorf("IsReferencedByMinion() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestBackupServiceIsReferencedByVirtualServer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		vs                *conf_v1.VirtualServer
		serviceNamespace  string
		backupServiceName string
		expected          bool
		msg               string
	}{
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Backup: "test-backup-service",
						},
					},
				},
			},
			serviceNamespace:  "default",
			backupServiceName: "test-backup-service",
			expected:          true,
			msg:               "Backup service is referenced by this VirtualServer",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Backup: "test-backup-service-does-not-exist",
						},
					},
				},
			},
			serviceNamespace:  "default",
			backupServiceName: "test-backup-service",
			expected:          false,
			msg:               "Backup service is not referenced by this VirtualServer",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Backup: "test-backup-service",
						},
					},
				},
			},
			serviceNamespace:  "non-default-namespace",
			backupServiceName: "test-backup-service",
			expected:          false,
			msg:               "Backup service is in different namespace",
		},
	}
	for _, test := range tests {
		rc := newServiceReferenceChecker(false)

		result := rc.IsReferencedByVirtualServer(test.serviceNamespace, test.backupServiceName, test.vs)
		if result != test.expected {
			t.Errorf("IsReferencedByVirtualServer() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestServiceIsReferencedByVirtualServerAndVirtualServerRoutes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		vs               *conf_v1.VirtualServer
		vsr              *conf_v1.VirtualServerRoute
		serviceNamespace string
		serviceName      string
		expected         bool
		msg              string
	}{
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			vsr: &conf_v1.VirtualServerRoute{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			serviceNamespace: "default",
			serviceName:      "test-service",
			expected:         true,
			msg:              "service is referenced in an upstream",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			vsr: &conf_v1.VirtualServerRoute{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			serviceNamespace: "some-namespace",
			serviceName:      "test-service",
			expected:         false,
			msg:              "wrong namespace for service in an upstream",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			vsr: &conf_v1.VirtualServerRoute{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			serviceNamespace: "default",
			serviceName:      "some-service",
			expected:         false,
			msg:              "wrong name for service in an upstream",
		},
	}

	for _, test := range tests {
		rc := newServiceReferenceChecker(false)

		result := rc.IsReferencedByVirtualServer(test.serviceNamespace, test.serviceName, test.vs)
		if result != test.expected {
			t.Errorf("IsReferencedByVirtualServer() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}

		result = rc.IsReferencedByVirtualServerRoute(test.serviceNamespace, test.serviceName, test.vsr)
		if result != test.expected {
			t.Errorf("IsReferencedByVirtualServerRoute() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestServiceIsReferencedByTransportServer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ts               *conf_v1.TransportServer
		serviceNamespace string
		serviceName      string
		expected         bool
		msg              string
	}{
		{
			ts: &conf_v1.TransportServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.TransportServerSpec{
					Upstreams: []conf_v1.TransportServerUpstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			serviceNamespace: "default",
			serviceName:      "test-service",
			expected:         true,
			msg:              "service is referenced in an upstream",
		},
		{
			ts: &conf_v1.TransportServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.TransportServerSpec{
					Upstreams: []conf_v1.TransportServerUpstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			serviceNamespace: "some-namespace",
			serviceName:      "test-service",
			expected:         false,
			msg:              "wrong namespace for service in an upstream",
		},
		{
			ts: &conf_v1.TransportServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.TransportServerSpec{
					Upstreams: []conf_v1.TransportServerUpstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			serviceNamespace: "default",
			serviceName:      "some-service",
			expected:         false,
			msg:              "wrong name for service in an upstream",
		},
	}

	for _, test := range tests {
		rc := newServiceReferenceChecker(false)

		result := rc.IsReferencedByTransportServer(test.serviceNamespace, test.serviceName, test.ts)
		if result != test.expected {
			t.Errorf("IsReferencedByTransportServer() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestBackupServiceIsReferencedByTransportServer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ts                     *conf_v1.TransportServer
		backupServiceNamespace string
		backupServiceName      string
		expected               bool
		msg                    string
	}{
		{
			ts: &conf_v1.TransportServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.TransportServerSpec{
					Upstreams: []conf_v1.TransportServerUpstream{
						{
							Backup: "test-backup-service",
						},
					},
				},
			},
			backupServiceNamespace: "default",
			backupServiceName:      "test-backup-service",
			expected:               true,
			msg:                    "Backup Service is referenced by this TransportService",
		},
		{
			ts: &conf_v1.TransportServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.TransportServerSpec{
					Upstreams: []conf_v1.TransportServerUpstream{
						{
							Backup: "test-backup-service",
						},
					},
				},
			},
			backupServiceNamespace: "some-namespace",
			backupServiceName:      "test-backup-service",
			expected:               false,
			msg:                    "wrong namespace for service in an upstream",
		},
		{
			ts: &conf_v1.TransportServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.TransportServerSpec{
					Upstreams: []conf_v1.TransportServerUpstream{
						{
							Service: "test-backup-service",
						},
					},
				},
			},
			backupServiceNamespace: "default",
			backupServiceName:      "random-backup-service",
			expected:               false,
			msg:                    "wrong name for service in an upstream",
		},
	}

	for _, test := range tests {
		rc := newServiceReferenceChecker(false)

		result := rc.IsReferencedByTransportServer(test.backupServiceNamespace, test.backupServiceName, test.ts)
		if result != test.expected {
			t.Errorf("IsReferencedByTransportServer() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestPolicyIsReferencedByIngressesAndTransportServers(t *testing.T) {
	t.Parallel()
	rc := newPolicyReferenceChecker()

	result := rc.IsReferencedByIngress("", "", nil)
	if result {
		t.Error("IsReferencedByIngress() returned true but expected false")
	}

	result = rc.IsReferencedByMinion("", "", nil)
	if result {
		t.Error("IsReferencedByMinion() returned true but expected false")
	}

	result = rc.IsReferencedByTransportServer("", "", nil)
	if result {
		t.Error("IsReferencedByTransportServer() returned true but expected false")
	}
}

func TestPolicyIsReferencedByVirtualServerAndVirtualServerRoute(t *testing.T) {
	t.Parallel()
	tests := []struct {
		vs              *conf_v1.VirtualServer
		vsr             *conf_v1.VirtualServerRoute
		policyNamespace string
		policyName      string
		expected        bool
		msg             string
	}{
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Policies: []conf_v1.PolicyReference{
						{
							Name:      "test-policy",
							Namespace: "default",
						},
					},
				},
			},
			policyNamespace: "default",
			policyName:      "test-policy",
			expected:        true,
			msg:             "policy is referenced at the spec level",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Policies: []conf_v1.PolicyReference{
						{
							Name:      "test-policy",
							Namespace: "default",
						},
					},
				},
			},
			policyNamespace: "some-namespace",
			policyName:      "test-policy",
			expected:        false,
			msg:             "wrong namespace for policy at the spec level",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Policies: []conf_v1.PolicyReference{
						{
							Name:      "test-policy",
							Namespace: "default",
						},
					},
				},
			},
			policyNamespace: "default",
			policyName:      "some-policy",
			expected:        false,
			msg:             "wrong name for policy at the spec level",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Routes: []conf_v1.Route{
						{
							Policies: []conf_v1.PolicyReference{
								{
									Name:      "test-policy",
									Namespace: "default",
								},
							},
						},
					},
				},
			},
			vsr: &conf_v1.VirtualServerRoute{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Subroutes: []conf_v1.Route{
						{
							Policies: []conf_v1.PolicyReference{
								{
									Name:      "test-policy",
									Namespace: "default",
								},
							},
						},
					},
				},
			},
			policyNamespace: "default",
			policyName:      "test-policy",
			expected:        true,
			msg:             "policy is referenced in a route",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Routes: []conf_v1.Route{
						{
							Policies: []conf_v1.PolicyReference{
								{
									Name:      "test-policy",
									Namespace: "default",
								},
							},
						},
					},
				},
			},
			vsr: &conf_v1.VirtualServerRoute{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Subroutes: []conf_v1.Route{
						{
							Policies: []conf_v1.PolicyReference{
								{
									Name:      "test-policy",
									Namespace: "default",
								},
							},
						},
					},
				},
			},
			policyNamespace: "some-namespace",
			policyName:      "test-policy",
			expected:        false,
			msg:             "wrong namespace for policy in a route",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Routes: []conf_v1.Route{
						{
							Policies: []conf_v1.PolicyReference{
								{
									Name:      "test-policy",
									Namespace: "default",
								},
							},
						},
					},
				},
			},
			vsr: &conf_v1.VirtualServerRoute{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Subroutes: []conf_v1.Route{
						{
							Policies: []conf_v1.PolicyReference{
								{
									Name:      "test-policy",
									Namespace: "default",
								},
							},
						},
					},
				},
			},
			policyNamespace: "default",
			policyName:      "some-policy",
			expected:        false,
			msg:             "wrong name for policy in a route",
		},
	}

	for _, test := range tests {
		rc := newPolicyReferenceChecker()

		result := rc.IsReferencedByVirtualServer(test.policyNamespace, test.policyName, test.vs)
		if result != test.expected {
			t.Errorf("IsReferencedByVirtualServer() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}

		if test.vsr == nil {
			continue
		}

		result = rc.IsReferencedByVirtualServerRoute(test.policyNamespace, test.policyName, test.vsr)
		if result != test.expected {
			t.Errorf("IsReferencedByVirtualServerRoute() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestAppProtectResourceIsReferencedByIngresses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ing               *networking.Ingress
		resourceNamespace string
		resourceName      string
		expected          bool
		msg               string
	}{
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						"test-annotation": "default/test-resource",
					},
				},
			},
			resourceNamespace: "default",
			resourceName:      "test-resource",
			expected:          true,
			msg:               "resource is referenced",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						"test-annotation": "test-resource",
					},
				},
			},
			resourceNamespace: "default",
			resourceName:      "test-resource",
			expected:          true,
			msg:               "resource is referenced with implicit namespace",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						"test-annotation": "default/test-resource",
					},
				},
			},
			resourceNamespace: "default",
			resourceName:      "some-resource",
			expected:          false,
			msg:               "wrong name",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						"test-annotation": "default/test-resource",
					},
				},
			},
			resourceNamespace: "some-namespace",
			resourceName:      "test-resource",
			expected:          false,
			msg:               "wrong namespace",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						"test-annotation": "test-resource",
					},
				},
			},
			resourceNamespace: "some-namespace",
			resourceName:      "test-resource",
			expected:          false,
			msg:               "wrong namespace with implicit namespace",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						"test-annotation": "some-namespace/test-resource,some-namespace/different-resource",
					},
				},
			},
			resourceNamespace: "some-namespace",
			resourceName:      "test-resource",
			expected:          true,
			msg:               "resource is referenced with namespace within multiple resources",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						"test-annotation": "test-resource,some-namespace/different-resource",
					},
				},
			},
			resourceNamespace: "default",
			resourceName:      "test-resource",
			expected:          true,
			msg:               "resource is referenced with implicit namespace within multiple resources",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						"test-annotation": "test-resource,some-namespace/different-resource",
					},
				},
			},
			resourceNamespace: "some-namespace",
			resourceName:      "test-resource",
			expected:          false,
			msg:               "wrong namespace within multiple resources",
		},
	}

	for _, test := range tests {
		rc := newAppProtectResourceReferenceChecker("test-annotation")

		result := rc.IsReferencedByIngress(test.resourceNamespace, test.resourceName, test.ing)
		if result != test.expected {
			t.Errorf("IsReferencedByIngress() returned '%v' but expected '%v' for the case of '%s'", result, test.expected, test.msg)
		}

		result = rc.IsReferencedByMinion(test.resourceNamespace, test.resourceName, test.ing)
		if result != false {
			t.Errorf("IsReferencedByMinion() returned true but expected false for the case of %s", test.msg)
		}
	}
}

func TestAppProtectResourceIsReferenced(t *testing.T) {
	t.Parallel()
	rc := newAppProtectResourceReferenceChecker("test")

	result := rc.IsReferencedByVirtualServer("", "", nil)
	if result {
		t.Error("IsReferencedByVirtualServer() returned true but expected false")
	}

	result = rc.IsReferencedByVirtualServerRoute("", "", nil)
	if result {
		t.Error("IsReferencedByVirtualServer() returned true but expected false")
	}

	result = rc.IsReferencedByTransportServer("", "", nil)
	if result {
		t.Error("IsReferencedByTransportServer() returned true but expected false")
	}
}

func TestIsPolicyIsReferenced(t *testing.T) {
	t.Parallel()
	tests := []struct {
		policies          []conf_v1.PolicyReference
		resourceNamespace string
		policyNamespace   string
		policyName        string
		expected          bool
		msg               string
	}{
		{
			policies: []conf_v1.PolicyReference{
				{
					Name: "test-policy",
				},
			},
			resourceNamespace: "ns-1",
			policyNamespace:   "ns-1",
			policyName:        "test-policy",
			expected:          true,
			msg:               "reference with implicit namespace",
		},
		{
			policies: []conf_v1.PolicyReference{
				{
					Name:      "test-policy",
					Namespace: "ns-1",
				},
			},
			resourceNamespace: "ns-1",
			policyNamespace:   "ns-1",
			policyName:        "test-policy",
			expected:          true,
			msg:               "reference with explicit namespace",
		},
		{
			policies: []conf_v1.PolicyReference{
				{
					Name: "test-policy",
				},
			},
			resourceNamespace: "ns-2",
			policyNamespace:   "ns-1",
			policyName:        "test-policy",
			expected:          false,
			msg:               "wrong namespace with implicit namespace",
		},
		{
			policies: []conf_v1.PolicyReference{
				{
					Name:      "test-policy",
					Namespace: "ns-2",
				},
			},
			resourceNamespace: "ns-2",
			policyNamespace:   "ns-1",
			policyName:        "test-policy",
			expected:          false,
			msg:               "wrong namespace with explicit namespace",
		},
	}

	for _, test := range tests {
		result := isPolicyReferenced(test.policies, test.resourceNamespace, test.policyNamespace, test.policyName)
		if result != test.expected {
			t.Errorf("isPolicyReferenced() returned %v but expected %v for the case of %s", result,
				test.expected, test.msg)
		}
	}
}

func TestEndpointIsReferencedByVirtualServerAndVirtualServerRoutes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		vs               *conf_v1.VirtualServer
		vsr              *conf_v1.VirtualServerRoute
		serviceNamespace string
		serviceName      string
		expected         bool
		msg              string
	}{
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			vsr: &conf_v1.VirtualServerRoute{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service: "test-service",
						},
					},
				},
			},
			serviceNamespace: "default",
			serviceName:      "test-service",
			expected:         true,
			msg:              "service is referenced in an upstream",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service:      "test-service",
							UseClusterIP: true,
						},
					},
				},
			},
			vsr: &conf_v1.VirtualServerRoute{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service:      "test-service",
							UseClusterIP: true,
						},
					},
				},
			},
			serviceNamespace: "default",
			serviceName:      "test-service",
			expected:         false,
			msg:              "upstream uses clusterIP",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service:      "test-service",
							UseClusterIP: true,
						},
						{
							Service: "test-service",
						},
					},
				},
			},
			vsr: &conf_v1.VirtualServerRoute{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerRouteSpec{
					Upstreams: []conf_v1.Upstream{
						{
							Service:      "test-service",
							UseClusterIP: true,
						},
						{
							Service: "test-service",
						},
					},
				},
			},
			serviceNamespace: "default",
			serviceName:      "test-service",
			expected:         true,
			msg:              "one upstream without Cluster IP",
		},
	}

	for _, test := range tests {
		rc := newServiceReferenceChecker(true)

		result := rc.IsReferencedByVirtualServer(test.serviceNamespace, test.serviceName, test.vs)
		if result != test.expected {
			t.Errorf("IsReferencedByVirtualServer() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}

		result = rc.IsReferencedByVirtualServerRoute(test.serviceNamespace, test.serviceName, test.vsr)
		if result != test.expected {
			t.Errorf("IsReferencedByVirtualServerRoute() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestDosProtectedIsReferencedByIngresses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ing               *networking.Ingress
		resourceNamespace string
		resourceName      string
		expected          bool
		msg               string
	}{
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.AppProtectDosProtectedAnnotation: "default/test-resource",
					},
				},
			},
			resourceNamespace: "default",
			resourceName:      "test-resource",
			expected:          true,
			msg:               "resource is referenced",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.AppProtectDosProtectedAnnotation: "test-resource",
					},
				},
			},
			resourceNamespace: "default",
			resourceName:      "test-resource",
			expected:          true,
			msg:               "resource is referenced with implicit namespace",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.AppProtectDosProtectedAnnotation: "default/test-resource",
					},
				},
			},
			resourceNamespace: "default",
			resourceName:      "some-resource",
			expected:          false,
			msg:               "wrong name",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.AppProtectDosProtectedAnnotation: "default/test-resource",
					},
				},
			},
			resourceNamespace: "some-namespace",
			resourceName:      "test-resource",
			expected:          false,
			msg:               "wrong namespace",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.AppProtectDosProtectedAnnotation: "test-resource",
					},
				},
			},
			resourceNamespace: "some-namespace",
			resourceName:      "test-resource",
			expected:          false,
			msg:               "wrong namespace with implicit namespace",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.AppProtectDosProtectedAnnotation: "some-namespace/test-resource,some-namespace/different-resource",
					},
				},
			},
			resourceNamespace: "some-namespace",
			resourceName:      "test-resource",
			expected:          false,
			msg:               "resource is referenced with namespace within multiple resources",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.AppProtectDosProtectedAnnotation: "test-resource,some-namespace/different-resource",
					},
				},
			},
			resourceNamespace: "default",
			resourceName:      "test-resource",
			expected:          false,
			msg:               "resource is referenced with implicit namespace within multiple resources",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
					Annotations: map[string]string{
						configs.AppProtectDosProtectedAnnotation: "test-resource,some-namespace/different-resource",
					},
				},
			},
			resourceNamespace: "some-namespace",
			resourceName:      "test-resource",
			expected:          false,
			msg:               "wrong namespace within multiple resources",
		},
	}

	for _, test := range tests {
		rc := newDosResourceReferenceChecker(configs.AppProtectDosProtectedAnnotation)

		result := rc.IsReferencedByIngress(test.resourceNamespace, test.resourceName, test.ing)
		if result != test.expected {
			t.Errorf("IsReferencedByIngress() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}

		result = rc.IsReferencedByMinion(test.resourceNamespace, test.resourceName, test.ing)
		if result != false {
			t.Errorf("IsReferencedByMinion() returned true but expected false for the case of %s", test.msg)
		}
	}
}

func TestDosProtectedIsReferencedByVirtualServer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		vs                 *conf_v1.VirtualServer
		protectedNamespace string
		protectedName      string
		expected           bool
		msg                string
	}{
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Dos: "test-dos",
				},
			},
			protectedNamespace: "default",
			protectedName:      "test-dos",
			expected:           true,
			msg:                "dos protected is referenced",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Dos: "test-dos",
				},
			},
			protectedNamespace: "default",
			protectedName:      "some-dos",
			expected:           false,
			msg:                "wrong name for dos protected",
		},
		{
			vs: &conf_v1.VirtualServer{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "default",
				},
				Spec: conf_v1.VirtualServerSpec{
					Dos: "test-dos",
				},
			},
			protectedNamespace: "some-namespace",
			protectedName:      "test-dos",
			expected:           false,
			msg:                "wrong namespace for dos protected",
		},
	}

	for _, test := range tests {
		rc := newDosResourceReferenceChecker(configs.AppProtectDosProtectedAnnotation)

		result := rc.IsReferencedByVirtualServer(test.protectedNamespace, test.protectedName, test.vs)
		if result != test.expected {
			t.Errorf("IsReferencedByVirtualServer() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
		}
	}
}

func TestReplicaReferenceChecker(t *testing.T) {
	tests := []struct {
		Ingress  *networking.Ingress
		Expected bool
	}{
		{
			Ingress: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						"foo": "bar",
					},
				},
			},
			Expected: false,
		},
		{
			Ingress: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/limit-req-scale": "false",
					},
				},
			},
			Expected: false,
		},
		{
			Ingress: &networking.Ingress{
				ObjectMeta: v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/limit-req-scale": "true",
					},
				},
			},
			Expected: true,
		},
	}

	var checker ratelimitScalingAnnotationChecker
	for i, testcase := range tests {
		result := checker.IsReferencedByIngress("foo", "bar", testcase.Ingress)
		if result != testcase.Expected {
			t.Errorf("replicaReferenceChecker did not work for case %d", i)
		}
	}
}

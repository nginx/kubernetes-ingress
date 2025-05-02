package validation

import (
	"reflect"
	"testing"

	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateVirtualServer(t *testing.T) {
	t.Parallel()

	virtualServer := v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe",
			Namespace: "default",
		},
		Spec: v1.VirtualServerSpec{
			Host: "example.com",
			TLS: &v1.TLS{
				Secret: "abc",
			},
			ExternalDNS: v1.ExternalDNS{
				Enable: false,
			},
			Upstreams: []v1.Upstream{
				{
					Name:      "first",
					Service:   "service-1",
					LBMethod:  "random",
					Port:      80,
					MaxFails:  createPointerFromInt(8),
					MaxConns:  createPointerFromInt(16),
					Keepalive: createPointerFromInt(32),
					Type:      "grpc",
				},
				{
					Name:    "second",
					Service: "service-2",
					Port:    80,
				},
			},
			Routes: []v1.Route{
				{
					Path: "/first",
					Action: &v1.Action{
						Pass: "first",
					},
				},
				{
					Path: "/second",
					Action: &v1.Action{
						Pass: "second",
					},
				},
			},
			Dos: "some-ns/some-name",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false, isDosEnabled: true}

	err := vsv.ValidateVirtualServer(&virtualServer)
	if err != nil {
		t.Errorf("ValidateVirtualServer() returned error %v for valid input %v", err, virtualServer)
	}
}

func makeVirtualServer() v1.VirtualServer {
	return v1.VirtualServer{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "cafe",
			Namespace: "default",
		},
		Spec: v1.VirtualServerSpec{
			Host: "example.com",
			TLS: &v1.TLS{
				Secret: "abc",
			},
			ExternalDNS: v1.ExternalDNS{
				Enable: false,
			},
			Upstreams: []v1.Upstream{
				{
					Name:      "first",
					Service:   "service-1",
					LBMethod:  "random",
					Port:      80,
					MaxFails:  createPointerFromInt(8),
					MaxConns:  createPointerFromInt(16),
					Keepalive: createPointerFromInt(32),
					Type:      "grpc",
				},
				{
					Name:    "second",
					Service: "service-2",
					Port:    80,
				},
			},
			Routes: []v1.Route{
				{
					Path: "/first",
					Action: &v1.Action{
						Pass: "first",
					},
				},
				{
					Path: "/second",
					Action: &v1.Action{
						Pass: "second",
					},
				},
			},
			Dos: "some-ns/some-name",
		},
	}
}

func TestValidateFailsOnMissingBackupPort(t *testing.T) {
	t.Parallel()

	vs := makeVirtualServer()
	// setup only backup name, missing backup port
	vs.Spec.Upstreams[1].Backup = "backup-service"

	vsv := &VirtualServerValidator{isPlus: true, isDosEnabled: true}
	err := vsv.ValidateVirtualServer(&vs)
	if err == nil {
		t.Error("want error for missing backup port, got nil", err)
	}
}

func createPointerFromUInt16(port uint16) *uint16 {
	return &port
}

func TestValidateFailsOnMissingBackupName(t *testing.T) {
	t.Parallel()

	vs := makeVirtualServer()
	// setup only backup port, missing backup name
	vs.Spec.Upstreams[1].BackupPort = createPointerFromUInt16(8080)

	vsv := &VirtualServerValidator{isPlus: true, isDosEnabled: true}
	err := vsv.ValidateVirtualServer(&vs)
	if err == nil {
		t.Error("want error for missing backup name, got nil", err)
	}
}

func TestValidateFailsOnNotSupportedLBMethodForBackup(t *testing.T) {
	t.Parallel()

	notSupportedLBMethods := []string{"hash", "hash_ip", "random", "random two least_conn"}
	for _, lbMethod := range notSupportedLBMethods {
		lbMethod := lbMethod
		t.Run(lbMethod, func(t *testing.T) {
			t.Parallel()

			vs := makeVirtualServer()
			vs.Spec.Upstreams[1].Backup = "backup-service"
			vs.Spec.Upstreams[1].BackupPort = createPointerFromUInt16(8080)

			// Not supported load balancing method
			vs.Spec.Upstreams[1].LBMethod = lbMethod

			vsv := &VirtualServerValidator{isPlus: true, isDosEnabled: true}
			err := vsv.ValidateVirtualServer(&vs)
			if err == nil {
				t.Errorf("want error for not supported load balancing method: %s", lbMethod)
			}
		})
	}
}

func TestValidateBackup(t *testing.T) {
	t.Parallel()

	vs := makeVirtualServer()
	vs.Spec.Upstreams[1].Backup = "backup-service"
	vs.Spec.Upstreams[1].BackupPort = createPointerFromUInt16(8080)

	vsv := &VirtualServerValidator{isPlus: true, isDosEnabled: true}
	err := vsv.ValidateVirtualServer(&vs)
	if err != nil {
		t.Error(err)
	}
}

func TestValidateHost(t *testing.T) {
	t.Parallel()
	validHosts := []string{
		"hello",
		"example.com",
		"hello-world-1",
		"*.example.com",
	}

	for _, h := range validHosts {
		allErrs := validateHost(h, field.NewPath("host"))
		if len(allErrs) > 0 {
			t.Errorf("validateHost(%q) returned errors %v for valid input", h, allErrs)
		}
	}

	invalidHosts := []string{
		"",
		"*",
		"..",
		".example.com",
		"-hello-world-1",
		"*.-example.com",
	}

	for _, h := range invalidHosts {
		allErrs := validateHost(h, field.NewPath("host"))
		if len(allErrs) == 0 {
			t.Errorf("validateHost(%q) returned no errors for invalid input", h)
		}
	}
}

func TestValidateDos(t *testing.T) {
	t.Parallel()
	validDosResources := []string{
		"hello",
		"ns/hello",
		"hello-world-1",
	}

	for _, h := range validDosResources {
		allErrs := validateDos(true, h, field.NewPath("dos"))
		if len(allErrs) > 0 {
			t.Errorf("validateDos(%q) returned errors %v for valid input", h, allErrs)
		}
	}

	invalidDos := []string{
		"*",
		"..",
		".example.com",
		"-hello-world-1",
		"/hello/world-1",
		"hello/world/other",
	}

	for _, h := range invalidDos {
		allErrs := validateDos(true, h, field.NewPath("dos"))
		if len(allErrs) == 0 {
			t.Errorf("validateDos(%q) returned no errors for invalid input", h)
		}
	}
}

func TestValidateDosDisabled(t *testing.T) {
	t.Parallel()
	invalidDos := []string{
		"hello",
		"ns/hello",
		"hello-world-1",
		"*",
		"..",
		".example.com",
		"-hello-world-1",
		"/hello/world-1",
		"hello/world/other",
	}

	for _, h := range invalidDos {
		allErrs := validateDos(false, h, field.NewPath("dos"))
		if len(allErrs) == 0 {
			t.Errorf("validateDos(%q) returned no errors for invalid input", h)
		}
	}
}

func TestValidatePolicies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		policies []v1.PolicyReference
		msg      string
	}{
		{
			policies: []v1.PolicyReference{
				{
					Name: "my-policy",
				},
			},
			msg: "name without namespace",
		},
		{
			policies: []v1.PolicyReference{
				{
					Name:      "my-policy",
					Namespace: "nginx-ingress",
				},
			},
			msg: "name with namespace",
		},
		{
			policies: []v1.PolicyReference{
				{
					Name:      "my-policy",
					Namespace: "default",
				},
				{
					Name:      "my-policy",
					Namespace: "test",
				},
			},
			msg: "same name different namespaces",
		},
	}

	for _, test := range tests {
		allErrs := validatePolicies(test.policies, field.NewPath("policies"), "default")
		if len(allErrs) > 0 {
			t.Errorf("validatePolicies() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidatePoliciesFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		policies []v1.PolicyReference
		msg      string
	}{
		{
			policies: []v1.PolicyReference{
				{
					Name: "",
				},
			},
			msg: "missing name",
		},
		{
			policies: []v1.PolicyReference{
				{
					Name: "-invalid",
				},
			},
			msg: "invalid name",
		},
		{
			policies: []v1.PolicyReference{
				{
					Name:      "my-policy",
					Namespace: "-invalid",
				},
			},
			msg: "invalid namespace",
		},
		{
			policies: []v1.PolicyReference{
				{
					Name:      "my-policy",
					Namespace: "default",
				},
				{
					Name:      "my-policy",
					Namespace: "default",
				},
			},
			msg: "duplicated policies",
		},
		{
			policies: []v1.PolicyReference{
				{
					Name:      "my-policy",
					Namespace: "default",
				},
				{
					Name: "my-policy",
				},
			},
			msg: "duplicated policies with inferred namespace",
		},
	}

	for _, test := range tests {
		allErrs := validatePolicies(test.policies, field.NewPath("policies"), "default")
		if len(allErrs) == 0 {
			t.Errorf("validatePolicies() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestValidateTLS(t *testing.T) {
	t.Parallel()
	validTLSes := []*v1.TLS{
		nil,
		{
			Secret: "",
		},
		{
			Secret: "my-secret",
		},
		{
			Secret:   "my-secret",
			Redirect: &v1.TLSRedirect{},
		},
		{
			Secret: "my-secret",
			Redirect: &v1.TLSRedirect{
				Enable: true,
			},
		},
		{
			Secret: "my-secret",
			Redirect: &v1.TLSRedirect{
				Enable:  true,
				Code:    createPointerFromInt(302),
				BasedOn: "scheme",
			},
		},
		{
			Secret: "my-secret",
			Redirect: &v1.TLSRedirect{
				Enable: true,
				Code:   createPointerFromInt(307),
			},
		},
		{
			Secret: "my-secret",
			CertManager: &v1.CertManager{
				Issuer: "my-issuer",
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false, isCertManagerEnabled: true}

	for _, tls := range validTLSes {
		allErrs := vsv.validateTLS(tls, field.NewPath("tls"))
		if len(allErrs) > 0 {
			t.Errorf("validateTLS() returned errors %v for valid input %v", allErrs, tls)
		}
	}

	invalidTLSes := []*v1.TLS{
		{
			Secret: "-",
		},
		{
			Secret: "a/b",
		},
		{
			Secret: "my-secret",
			Redirect: &v1.TLSRedirect{
				Enable:  true,
				Code:    createPointerFromInt(305),
				BasedOn: "scheme",
			},
		},
		{
			Secret: "my-secret",
			Redirect: &v1.TLSRedirect{
				Enable:  true,
				Code:    createPointerFromInt(301),
				BasedOn: "invalidScheme",
			},
		},
		{
			CertManager: &v1.CertManager{
				Issuer: "my-issuer",
			},
		},
	}

	for _, tls := range invalidTLSes {
		allErrs := vsv.validateTLS(tls, field.NewPath("tls"))
		if len(allErrs) == 0 {
			t.Errorf("validateTLS() returned no errors for invalid input %v", tls)
		}
	}

	vsv2 := &VirtualServerValidator{isPlus: false}
	tls := v1.TLS{
		Secret: "my-secret",
		CertManager: &v1.CertManager{
			Issuer: "my-issuer",
		},
	}
	err := vsv2.validateTLS(&tls, field.NewPath("tls"))
	if err == nil {
		t.Errorf("validateTLS() returned no errors for invalid input %v", tls)
	}
}

func TestValidateExternalDNSEnabled(t *testing.T) {
	vsv := &VirtualServerValidator{isPlus: false, isExternalDNSEnabled: true}

	extDNS := &v1.ExternalDNS{
		Enable: true,
	}
	allErrs := vsv.validateExternalDNS(extDNS, field.NewPath("externalDNS"))
	if len(allErrs) > 0 {
		t.Errorf("validateExternalDNS() returned errors %v for valid input %v", allErrs, extDNS)
	}

	vsv = &VirtualServerValidator{isPlus: false, isExternalDNSEnabled: false}

	extDNS = &v1.ExternalDNS{
		Enable: true,
	}
	allErrs = vsv.validateExternalDNS(extDNS, field.NewPath("externalDNS"))
	if len(allErrs) == 0 {
		t.Errorf("validateExternalDNS() returned no errors for invalid input %v", extDNS)
	}
}

func TestValidateUpstreams(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstreams             []v1.Upstream
		expectedUpstreamNames sets.Set[string]
		msg                   string
	}{
		{
			upstreams:             []v1.Upstream{},
			expectedUpstreamNames: sets.Set[string]{},
			msg:                   "no upstreams",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:                     "upstream1",
					Service:                  "test-1",
					Port:                     80,
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "10s",
					ProxyNextUpstreamTries:   5,
					MaxConns:                 createPointerFromInt(16),
					Type:                     "grpc",
				},
				{
					Name:                     "upstream2",
					Subselector:              map[string]string{"version": "test"},
					Service:                  "test-2",
					Port:                     80,
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "10s",
					ProxyNextUpstreamTries:   5,
					Type:                     "http",
				},
				{
					Name:         "upstream3",
					Service:      "test-3",
					Port:         80,
					UseClusterIP: true,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
				"upstream2": {},
				"upstream3": {},
			},
			msg: "2 valid upstreams",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs, resultUpstreamNames := vsv.validateUpstreams(test.upstreams, field.NewPath("upstreams"))
		if len(allErrs) > 0 {
			t.Errorf("validateUpstreams() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
		if !resultUpstreamNames.Equal(test.expectedUpstreamNames) {
			t.Errorf("validateUpstreams() returned %v expected %v for the case of %s", resultUpstreamNames, test.expectedUpstreamNames, test.msg)
		}
	}
}

func TestValidateUpstreamsFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstreams             []v1.Upstream
		expectedUpstreamNames sets.Set[string]
		msg                   string
	}{
		{
			upstreams: []v1.Upstream{
				{
					Name:                     "@upstream1",
					Service:                  "test-1",
					Port:                     80,
					ProxyNextUpstream:        "http_502",
					ProxyNextUpstreamTimeout: "10s",
					ProxyNextUpstreamTries:   5,
				},
			},
			expectedUpstreamNames: sets.Set[string]{},
			msg:                   "invalid upstream name",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:                     "upstream1",
					Service:                  "@test-1",
					Port:                     80,
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "10s",
					ProxyNextUpstreamTries:   5,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid service",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:                     "upstream1",
					Service:                  "test-1",
					Port:                     0,
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "10s",
					ProxyNextUpstreamTries:   5,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid port",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:                     "upstream1",
					Service:                  "test-1",
					Port:                     80,
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "10s",
					ProxyNextUpstreamTries:   5,
				},
				{
					Name:                     "upstream1",
					Service:                  "test-2",
					Port:                     80,
					ProxyNextUpstream:        "error timeout",
					ProxyNextUpstreamTimeout: "10s",
					ProxyNextUpstreamTries:   5,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "duplicated upstreams",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:                     "upstream1",
					Service:                  "test-1",
					Port:                     80,
					ProxyNextUpstream:        "https_504",
					ProxyNextUpstreamTimeout: "10s",
					ProxyNextUpstreamTries:   5,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid next upstream syntax",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:                     "upstream1",
					Service:                  "test-1",
					Port:                     80,
					ProxyNextUpstream:        "http_504",
					ProxyNextUpstreamTimeout: "-2s",
					ProxyNextUpstreamTries:   5,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid upstream timeout value",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:                     "upstream1",
					Service:                  "test-1",
					Port:                     80,
					ProxyNextUpstream:        "https_504",
					ProxyNextUpstreamTimeout: "10s",
					ProxyNextUpstreamTries:   -1,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid upstream tries value",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:     "upstream1",
					Service:  "test-1",
					Port:     80,
					MaxConns: createPointerFromInt(-1),
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "negative value for MaxConns",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:              "upstream1",
					Service:           "test-1",
					Port:              80,
					ClientMaxBodySize: "7mins",
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid value for ClientMaxBodySize",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:    "upstream1",
					Service: "test-1",
					Port:    80,
					ProxyBuffers: &v1.UpstreamBuffers{
						Number: -1,
						Size:   "1G",
					},
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid value for ProxyBuffers",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:            "upstream1",
					Service:         "test-1",
					Port:            80,
					ProxyBufferSize: "1G",
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid value for ProxyBufferSize",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:        "upstream1",
					Service:     "test-1",
					Subselector: map[string]string{"\\$invalidkey": "test"},
					Port:        80,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid key for subselector",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:        "upstream1",
					Service:     "test-1",
					Subselector: map[string]string{"version": "test=fail"},
					Port:        80,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid value for subselector",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:         "upstream1",
					Service:      "test-1",
					Subselector:  map[string]string{"version": "test"},
					UseClusterIP: true,
					Port:         80,
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "invalid use of subselector with use-cluster-ip",
		},
		{
			upstreams: []v1.Upstream{
				{
					Name:         "upstream1",
					Service:      "test-1",
					UseClusterIP: true,
					Port:         80,
					Type:         "unsupported",
				},
			},
			expectedUpstreamNames: map[string]sets.Empty{
				"upstream1": {},
			},
			msg: "Invalid upstream type - must be one of `grpc` or `http`",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs, resultUpstreamNames := vsv.validateUpstreams(test.upstreams, field.NewPath("upstreams"))
		if len(allErrs) == 0 {
			t.Errorf("validateUpstreams() returned no errors for the case of %s", test.msg)
		}
		if !resultUpstreamNames.Equal(test.expectedUpstreamNames) {
			t.Errorf("validateUpstreams() returned %v expected %v for the case of %s", resultUpstreamNames, test.expectedUpstreamNames, test.msg)
		}
	}
}

func TestValidateNextUpstream(t *testing.T) {
	t.Parallel()
	tests := []struct {
		inputS string
	}{
		{
			inputS: "error timeout",
		},
		{
			inputS: "http_404 timeout",
		},
	}
	for _, test := range tests {
		allErrs := validateNextUpstream(test.inputS, field.NewPath("next-upstreams"))
		if len(allErrs) > 0 {
			t.Errorf("validateNextUpstream(%q) returned errors %v for valid input.", test.inputS, allErrs)
		}
	}
}

func TestValidateNextUpstreamFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		inputS string
	}{
		{
			inputS: "error error",
		},
		{
			inputS: "https_404",
		},
	}
	for _, test := range tests {
		allErrs := validateNextUpstream(test.inputS, field.NewPath("next-upstreams"))
		if len(allErrs) == 0 {
			t.Errorf("validateNextUpstream(%q) didn't return errors %v for invalid input.", test.inputS, allErrs)
		}
	}
}

func TestValidateDNS1035Label(t *testing.T) {
	t.Parallel()
	validNames := []string{
		"test",
		"test-123",
	}

	for _, name := range validNames {
		allErrs := validateDNS1035Label(name, field.NewPath("name"))
		if len(allErrs) > 0 {
			t.Errorf("validateDNS1035Label(%q) returned errors %v for valid input", name, allErrs)
		}
	}

	invalidNames := []string{
		"",
		"123",
		"test.123",
	}

	for _, name := range invalidNames {
		allErrs := validateDNS1035Label(name, field.NewPath("name"))
		if len(allErrs) == 0 {
			t.Errorf("validateDNS1035Label(%q) returned no errors for invalid input", name)
		}
	}
}

func TestValidateVirtualServerRoutes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		routes        []v1.Route
		upstreamNames sets.Set[string]
		msg           string
	}{
		{
			routes:        []v1.Route{},
			upstreamNames: sets.Set[string]{},
			msg:           "no routes",
		},
		{
			routes: []v1.Route{
				{
					Path: "/",
					Action: &v1.Action{
						Pass: "test",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			msg: "valid route",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateVirtualServerRoutes(test.routes, field.NewPath("routes"), test.upstreamNames, "default")
		if len(allErrs) > 0 {
			t.Errorf("validateVirtualServerRoutes() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidateVirtualServerRoutesFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		routes        []v1.Route
		upstreamNames sets.Set[string]
		msg           string
	}{
		{
			routes: []v1.Route{
				{
					Path: "/test",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Path: "/test",
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "duplicated paths",
		},

		{
			routes: []v1.Route{
				{
					Path:   "",
					Action: nil,
				},
			},
			upstreamNames: map[string]sets.Empty{},
			msg:           "invalid route",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateVirtualServerRoutes(test.routes, field.NewPath("routes"), test.upstreamNames, "default")
		if len(allErrs) == 0 {
			t.Errorf("validateVirtualServerRoutes() returned no errors for the case of %s", test.msg)
		}
	}
}

func TestValidateRoute(t *testing.T) {
	t.Parallel()
	tests := []struct {
		route                 v1.Route
		upstreamNames         sets.Set[string]
		isRouteFieldForbidden bool
		msg                   string
	}{
		{
			route: v1.Route{
				Path: "/",
				Action: &v1.Action{
					Pass: "test",
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			isRouteFieldForbidden: false,
			msg:                   "valid route with upstream",
		},
		{
			route: v1.Route{
				Path: "/",
				Splits: []v1.Split{
					{
						Weight: 90,
						Action: &v1.Action{
							Pass: "test-1",
						},
					},
					{
						Weight: 10,
						Action: &v1.Action{
							Pass: "test-2",
						},
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			isRouteFieldForbidden: false,
			msg:                   "valid upstream with splits",
		},
		{
			route: v1.Route{
				Path: "/",
				Matches: []v1.Match{
					{
						Conditions: []v1.Condition{
							{
								Header: "x-version",
								Value:  "test-1",
							},
						},
						Action: &v1.Action{
							Pass: "test-1",
						},
					},
				},
				Action: &v1.Action{
					Pass: "test-2",
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			isRouteFieldForbidden: false,
			msg:                   "valid action with matches",
		},
		{
			route: v1.Route{
				Path:  "/",
				Route: "default/test",
			},
			upstreamNames:         map[string]sets.Empty{},
			isRouteFieldForbidden: false,
			msg:                   "valid route with route",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateRoute(test.route, field.NewPath("route"), test.upstreamNames, test.isRouteFieldForbidden, "default")
		if len(allErrs) > 0 {
			t.Errorf("validateRoute() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidateRouteFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		route                 v1.Route
		upstreamNames         sets.Set[string]
		isRouteFieldForbidden bool
		msg                   string
	}{
		{
			route: v1.Route{
				Path: "",
				Action: &v1.Action{
					Pass: "test",
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			isRouteFieldForbidden: false,
			msg:                   "empty path",
		},
		{
			route: v1.Route{
				Path: "/test",
				Action: &v1.Action{
					Pass: "-test",
				},
			},
			upstreamNames:         sets.Set[string]{},
			isRouteFieldForbidden: false,
			msg:                   "invalid pass action",
		},
		{
			route: v1.Route{
				Path: "/",
				Action: &v1.Action{
					Pass: "test",
				},
			},
			upstreamNames:         sets.Set[string]{},
			isRouteFieldForbidden: false,
			msg:                   "non-existing upstream in pass action",
		},
		{
			route: v1.Route{
				Path: "/",
				Action: &v1.Action{
					Pass: "test",
				},
				Splits: []v1.Split{
					{
						Weight: 90,
						Action: &v1.Action{
							Pass: "test-1",
						},
					},
					{
						Weight: 10,
						Action: &v1.Action{
							Pass: "test-2",
						},
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test":   {},
				"test-1": {},
				"test-2": {},
			},
			isRouteFieldForbidden: false,
			msg:                   "both action and splits exist",
		},
		{
			route: v1.Route{
				Path: "/",
				Splits: []v1.Split{
					{
						Weight: 90,
						Action: &v1.Action{
							Pass: "test-1",
						},
					},
					{
						Weight: 10,
						Action: &v1.Action{
							Pass: "test-2",
						},
					},
				},
				Matches: []v1.Match{
					{
						Conditions: []v1.Condition{
							{
								Header: "x-version",
								Value:  "test-1",
							},
						},
						Action: &v1.Action{
							Pass: "test-1",
						},
					},
				},
				Action: &v1.Action{
					Pass: "test-2",
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			isRouteFieldForbidden: false,
			msg:                   "both splits and matches exist",
		},
		{
			route: v1.Route{
				Path:  "/",
				Route: "default/test",
			},
			upstreamNames:         map[string]sets.Empty{},
			isRouteFieldForbidden: true,
			msg:                   "route field exists but is forbidden",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateRoute(test.route, field.NewPath("route"), test.upstreamNames, test.isRouteFieldForbidden, "default")
		if len(allErrs) == 0 {
			t.Errorf("validateRoute() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestValidateAction(t *testing.T) {
	t.Parallel()
	upstreamNames := map[string]sets.Empty{
		"test": {},
	}
	tests := []struct {
		action *v1.Action
		msg    string
	}{
		{
			action: &v1.Action{
				Pass: "test",
			},
			msg: "base pass action",
		},
		{
			action: &v1.Action{
				Redirect: &v1.ActionRedirect{
					URL: "http://www.nginx.com",
				},
			},
			msg: "base redirect action",
		},
		{
			action: &v1.Action{
				Redirect: &v1.ActionRedirect{
					URL:  "http://www.nginx.com",
					Code: 302,
				},
			},
			msg: "redirect action with status code set",
		},
		{
			action: &v1.Action{
				Proxy: &v1.ActionProxy{
					Upstream:    "test",
					RewritePath: "/rewrite",
					RequestHeaders: &v1.ProxyRequestHeaders{
						Set: []v1.Header{
							{
								Name:  "Header-Name",
								Value: "value",
							},
						},
					},
					ResponseHeaders: &v1.ProxyResponseHeaders{
						Hide:   []string{"header-name"},
						Pass:   []string{"header-name"},
						Ignore: []string{"Expires"},
						Add: []v1.AddHeader{
							{
								Header: v1.Header{
									Name:  "Header-Name",
									Value: "value",
								},
								Always: true,
							},
						},
					},
				},
			},
			msg: "proxy action with rewritePath, requestHeaders and responseHeaders",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateAction(test.action, field.NewPath("action"), upstreamNames, "", false)
		if len(allErrs) > 0 {
			t.Errorf("validateAction() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidateActionFails(t *testing.T) {
	t.Parallel()
	upstreamNames := map[string]sets.Empty{}

	tests := []struct {
		action *v1.Action
		msg    string
	}{
		{
			action: &v1.Action{},
			msg:    "empty action",
		},
		{
			action: &v1.Action{
				Redirect: &v1.ActionRedirect{},
			},
			msg: "missing required field url",
		},
		{
			action: &v1.Action{
				Pass: "test",
				Redirect: &v1.ActionRedirect{
					URL: "http://www.nginx.com",
				},
			},
			msg: "multiple actions defined",
		},
		{
			action: &v1.Action{
				Redirect: &v1.ActionRedirect{
					URL:  "http://www.nginx.com",
					Code: 305,
				},
			},
			msg: "redirect action with invalid status code set",
		},
		{
			action: &v1.Action{
				Proxy: &v1.ActionProxy{
					Upstream: "",
				},
			},
			msg: "proxy action with missing upstream field",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateAction(test.action, field.NewPath("action"), upstreamNames, "", false)
		if len(allErrs) == 0 {
			t.Errorf("validateAction() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestCaptureVariables(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s        string
		expected []string
	}{
		{
			"${scheme}://${host}",
			[]string{"scheme", "host"},
		},
		{
			"http://www.nginx.org",
			nil,
		},
		{
			"${}",
			[]string{""},
		},
	}
	for _, test := range tests {
		result := captureVariables(test.s)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("captureVariables(%s) returned %v but expected %v", test.s, result, test.expected)
		}
	}
}

func TestValidateRedirectURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		redirectURL string
		msg         string
	}{
		{
			redirectURL: "http://www.nginx.com",
			msg:         "base redirect url",
		},
		{
			redirectURL: "${scheme}://${host}/sorry",
			msg:         "multi variable redirect url",
		},
		{
			redirectURL: "${http_x_forwarded_proto}://${host}/sorry",
			msg:         "x-forwarded-proto redirect url use case",
		},
		{
			redirectURL: "http://${host}${request_uri}",
			msg:         "use multi variables, no scheme set",
		},
		{
			redirectURL: "${scheme}://www.${host}${request_uri}",
			msg:         "use multi variables",
		},
		{
			redirectURL: "http://example.com/redirect?source=abc",
			msg:         "arg variable use",
		},
		{
			redirectURL: `\"${scheme}://${host}\"`,
			msg:         "url with escaped quotes",
		},
		{
			redirectURL: "http://{abc}",
			msg:         "url with curly braces with no $ prefix",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateRedirectURL(test.redirectURL, field.NewPath("url"), validRedirectVariableNames)
		if len(allErrs) > 0 {
			t.Errorf("validateRedirectURL(%s) returned errors %v for valid input for the case of %s", test.redirectURL, allErrs, test.msg)
		}
	}
}

func TestValidateRedirectURLFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		redirectURL string
		msg         string
	}{
		{
			redirectURL: "",
			msg:         "url is blank",
		},
		{
			redirectURL: "/uri",
			msg:         "url does not start with http://, https:// or ${scheme}://",
		},
		{
			redirectURL: "$scheme://www.$host.com",
			msg:         "usage of nginx variable in url without ${}",
		},
		{
			redirectURL: "${scheme}://www.${invalid}.com",
			msg:         "invalid nginx variable in url",
		},
		{
			redirectURL: "${scheme}://www.${{host}.com",
			msg:         "leading curly brace",
		},
		{
			redirectURL: "${host.abc}.com",
			msg:         "multi var in curly brace",
		},
		{
			redirectURL: "${scheme}://www.${host{host}}.com",
			msg:         "nested nginx vars",
		},
		{
			redirectURL: `"${scheme}://${host}"`,
			msg:         "url in unescaped quotes",
		},
		{
			redirectURL: `"${scheme}://${host}`,
			msg:         "url with unescaped quote prefix",
		},
		{
			redirectURL: `\\"${scheme}://${host}\\"`,
			msg:         "url with escaped backslash",
		},
		{
			redirectURL: `${scheme}://${host}$`,
			msg:         "url with ending $",
		},
		{
			redirectURL: `http://${}`,
			msg:         "url containing blank var",
		},
		{
			redirectURL: `http://${abca`,
			msg:         "url containing a var without ending }",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateRedirectURL(test.redirectURL, field.NewPath("action"), validRedirectVariableNames)
		if len(allErrs) == 0 {
			t.Errorf("validateRedirectURL(%s) returned no errors for invalid input for the case of %s", test.redirectURL, test.msg)
		}
	}
}

func TestValidateRouteField(t *testing.T) {
	t.Parallel()
	validRouteFields := []string{
		"coffee",
		"default/coffee",
	}

	for _, rf := range validRouteFields {
		allErrs := validateRouteField(rf, field.NewPath("route"))
		if len(allErrs) > 0 {
			t.Errorf("validRouteField(%q) returned errors %v for valid input", rf, allErrs)
		}
	}

	invalidRouteFields := []string{
		"-",
		"/coffee",
		"-/coffee",
	}

	for _, rf := range invalidRouteFields {
		allErrs := validateRouteField(rf, field.NewPath("route"))
		if len(allErrs) == 0 {
			t.Errorf("validRouteField(%q) returned no errors for invalid input", rf)
		}
	}
}

func TestValidateReferencedUpstream(t *testing.T) {
	t.Parallel()
	upstream := "test"
	upstreamNames := map[string]sets.Empty{
		"test": {},
	}

	allErrs := validateReferencedUpstream(upstream, field.NewPath("upstream"), upstreamNames)
	if len(allErrs) > 0 {
		t.Errorf("validateReferencedUpstream() returned errors %v for valid input", allErrs)
	}
}

func TestValidateUpstreamFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstream      string
		upstreamNames sets.Set[string]
		msg           string
	}{
		{
			upstream:      "",
			upstreamNames: map[string]sets.Empty{},
			msg:           "empty upstream",
		},
		{
			upstream:      "-test",
			upstreamNames: map[string]sets.Empty{},
			msg:           "invalid upstream",
		},
		{
			upstream:      "test",
			upstreamNames: map[string]sets.Empty{},
			msg:           "non-existing upstream",
		},
	}

	for _, test := range tests {
		allErrs := validateReferencedUpstream(test.upstream, field.NewPath("upstream"), test.upstreamNames)
		if len(allErrs) == 0 {
			t.Errorf("validateReferencedUpstream() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestValidateRegexPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		regexPath string
		msg       string
	}{
		{
			regexPath: "~ ^/foo.*\\.jpg",
			msg:       "case sensitive regexp",
		},
		{
			regexPath: "~* ^/Bar.*\\.jpg",
			msg:       "case insensitive regexp",
		},
		{
			regexPath: `~ ^/f\"oo.*\\.jpg`,
			msg:       "regexp with escaped double quotes",
		},
		{
			regexPath: "~ [0-9a-z]{4}[0-9]+",
			msg:       "regexp with curly braces",
		},
		{
			regexPath: "~ ^/coffee/(?!.*\\/latte)(?!.*\\/americano)(.*)",
			msg:       "regex with backtracking",
		},
	}

	for _, test := range tests {
		allErrs := validateRegexPath(test.regexPath, field.NewPath("path"))
		if len(allErrs) != 0 {
			t.Errorf("validateRegexPath(%v) returned errors for valid input for the case of %v", test.regexPath, test.msg)
		}
	}
}

func TestValidateRegexPathFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		regexPath string
		msg       string
	}{
		{
			regexPath: "~ [{",
			msg:       "invalid regexp",
		},
		{
			regexPath: `~ /foo"`,
			msg:       "unescaped double quotes",
		},
		{
			regexPath: `~"`,
			msg:       "empty regex",
		},
		{
			regexPath: `~ /foo\`,
			msg:       "ending in backslash",
		},
	}

	for _, test := range tests {
		allErrs := validateRegexPath(test.regexPath, field.NewPath("path"))
		if len(allErrs) == 0 {
			t.Errorf("validateRegexPath(%v) returned no errors for invalid input for the case of %v", test.regexPath, test.msg)
		}
	}
}

func TestValidateRoutePath(t *testing.T) {
	t.Parallel()
	validPaths := []string{
		"/",
		"~ /^foo.*\\.jpg",
		"~* /^Bar.*\\.jpg",
		"=/exact/match",
	}

	for _, path := range validPaths {
		allErrs := validateRoutePath(path, field.NewPath("path"))
		if len(allErrs) != 0 {
			t.Errorf("validateRoutePath(%v) returned errors for valid input", path)
		}
	}

	invalidPaths := []string{
		"",
		"invalid",
		// regex without preceding "~*" modifier
		"^/foo.*\\.jpg",
	}

	for _, path := range invalidPaths {
		allErrs := validateRoutePath(path, field.NewPath("path"))
		if len(allErrs) == 0 {
			t.Errorf("validateRoutePath(%v) returned no errors for invalid input", path)
		}
	}
}

func TestValidatePath(t *testing.T) {
	t.Parallel()
	validPaths := []string{
		"/",
		"/path",
		"/a-1/_A/",
	}

	for _, path := range validPaths {
		allErrs := validatePath(path, field.NewPath("path"))
		if len(allErrs) > 0 {
			t.Errorf("validatePath(%q) returned errors %v for valid input", path, allErrs)
		}
	}

	invalidPaths := []string{
		"",
		" /",
		"/ ",
		"/{",
		"/}",
		"/abc;",
		`/path\`,
		`/path\n`,
	}

	for _, path := range invalidPaths {
		allErrs := validatePath(path, field.NewPath("path"))
		if len(allErrs) == 0 {
			t.Errorf("validatePath(%q) returned no errors for invalid input", path)
		}
	}
}

func TestValidateSplits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		splits        []v1.Split
		upstreamNames sets.Set[string]
		msg           string
	}{
		{
			splits: []v1.Split{
				{
					Weight: 90,
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Weight: 10,
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "valid weights",
		},
		{
			splits: []v1.Split{
				{
					Weight: 0,
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Weight: 100,
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "valid weights with 0 and 100",
		},
		{
			splits: []v1.Split{
				{
					Weight: 0,
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Weight: 50,
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
				{
					Weight: 50,
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "valid weights with 0",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateSplits(test.splits, field.NewPath("splits"), test.upstreamNames, "")
		if len(allErrs) > 0 {
			t.Errorf("validateSplits() returned errors %v for valid input", allErrs)
		}
	}
}

func TestValidateSplitsFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		splits        []v1.Split
		upstreamNames sets.Set[string]
		msg           string
	}{
		{
			splits: []v1.Split{
				{
					Weight: 90,
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
			},
			msg: "only one split",
		},
		{
			splits: []v1.Split{
				{
					Weight: 123,
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Weight: 10,
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "invalid weight",
		},
		{
			splits: []v1.Split{
				{
					Weight: 99,
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Weight: 99,
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "invalid total weight",
		},
		{
			splits: []v1.Split{
				{
					Weight: 90,
					Action: &v1.Action{
						Pass: "",
					},
				},
				{
					Weight: 10,
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "invalid action",
		},
		{
			splits: []v1.Split{
				{
					Weight: 90,
					Action: &v1.Action{
						Pass: "some-upstream",
					},
				},
				{
					Weight: 10,
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "invalid action with non-existing upstream",
		},
		{
			splits: []v1.Split{
				{
					Weight: 100,
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Weight: -2,
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "invalid negative weight",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateSplits(test.splits, field.NewPath("splits"), test.upstreamNames, "")
		if len(allErrs) == 0 {
			t.Errorf("validateSplits() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestValidateCondition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		condition v1.Condition
		msg       string
	}{
		{
			condition: v1.Condition{
				Header: "x-version",
				Value:  "v1",
			},
			msg: "valid header",
		},
		{
			condition: v1.Condition{
				Cookie: "my_cookie",
				Value:  "",
			},
			msg: "valid cookie",
		},
		{
			condition: v1.Condition{
				Argument: "arg",
				Value:    "yes",
			},
			msg: "valid argument",
		},
		{
			condition: v1.Condition{
				Variable: "$request_method",
				Value:    "POST",
			},
			msg: "valid variable",
		},
	}

	for _, test := range tests {
		allErrs := validateCondition(test.condition, field.NewPath("condition"))
		if len(allErrs) > 0 {
			t.Errorf("validateCondition() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidateConditionFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		condition v1.Condition
		msg       string
	}{
		{
			condition: v1.Condition{},
			msg:       "empty condition",
		},
		{
			condition: v1.Condition{
				Header:   "x-version",
				Cookie:   "user",
				Argument: "answer",
				Variable: "$request_method",
				Value:    "something",
			},
			msg: "invalid condition",
		},
		{
			condition: v1.Condition{
				Header: "x_version",
			},
			msg: "invalid header",
		},
		{
			condition: v1.Condition{
				Cookie: "my-cookie",
			},
			msg: "invalid cookie",
		},
		{
			condition: v1.Condition{
				Argument: "my-arg",
			},
			msg: "invalid argument",
		},
		{
			condition: v1.Condition{
				Variable: "request_method",
			},
			msg: "invalid variable",
		},
	}

	for _, test := range tests {
		allErrs := validateCondition(test.condition, field.NewPath("condition"))
		if len(allErrs) == 0 {
			t.Errorf("validateCondition() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestIsCookieName_ErrorsOnInvalidInput(t *testing.T) {
	t.Parallel()

	invalidCookieNames := []string{
		"",
		"my-cookie",
		"cookie!",
	}

	for _, name := range invalidCookieNames {
		errs := isCookieName(name)
		if len(errs) == 0 {
			t.Errorf("isCookieName(%q) returned no errors for invalid input", name)
		}
	}
}

func TestIsCookieName_IsValidOnValidInput(t *testing.T) {
	t.Parallel()

	validCookieNames := []string{
		"123",
		"my_cookie",
	}

	for _, name := range validCookieNames {
		errs := isCookieName(name)
		if len(errs) > 0 {
			t.Errorf("isCookieName(%q) returned errors %v for valid input", name, errs)
		}
	}
}

func TestIsArgumentName(t *testing.T) {
	t.Parallel()
	validArgumentNames := []string{
		"123",
		"my_arg",
	}

	for _, name := range validArgumentNames {
		errs := isArgumentName(name)
		if len(errs) > 0 {
			t.Errorf("isArgumentName(%q) returned errors %v for valid input", name, errs)
		}
	}

	invalidArgumentNames := []string{
		"",
		"my-arg",
		"arg!",
	}

	for _, name := range invalidArgumentNames {
		errs := isArgumentName(name)
		if len(errs) == 0 {
			t.Errorf("isArgumentName(%q) returned no errors for invalid input", name)
		}
	}
}

func TestValidateVariableName(t *testing.T) {
	t.Parallel()
	validNames := []string{
		"$request_method",
	}

	for _, name := range validNames {
		allErrs := validateVariableName(name, field.NewPath("variable"))
		if len(allErrs) > 0 {
			t.Errorf("validateVariableName(%q) returned errors %v for valid input", name, allErrs)
		}
	}

	invalidNames := []string{
		"request_method",
		"$request_id",
	}

	for _, name := range invalidNames {
		allErrs := validateVariableName(name, field.NewPath("variable"))
		if len(allErrs) == 0 {
			t.Errorf("validateVariableName(%q) returned no errors for invalid input", name)
		}
	}
}

func TestValidateMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		match         v1.Match
		upstreamNames sets.Set[string]
		msg           string
	}{
		{
			match: v1.Match{
				Conditions: []v1.Condition{
					{
						Cookie: "version",
						Value:  "v1",
					},
				},
				Action: &v1.Action{
					Pass: "test",
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			msg: "valid match with action",
		},
		{
			match: v1.Match{
				Conditions: []v1.Condition{
					{
						Cookie: "version",
						Value:  "v1",
					},
				},
				Splits: []v1.Split{
					{
						Weight: 90,
						Action: &v1.Action{
							Pass: "test-1",
						},
					},
					{
						Weight: 10,
						Action: &v1.Action{
							Pass: "test-2",
						},
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "valid match with splits",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateMatch(test.match, field.NewPath("match"), test.upstreamNames, "")
		if len(allErrs) > 0 {
			t.Errorf("validateMatch() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidateMatchFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		match         v1.Match
		upstreamNames sets.Set[string]
		msg           string
	}{
		{
			match: v1.Match{
				Conditions: []v1.Condition{},
				Action: &v1.Action{
					Pass: "test",
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			msg: "invalid number of conditions",
		},
		{
			match: v1.Match{
				Conditions: []v1.Condition{
					{
						Cookie: "version",
						Value:  `v1"`,
					},
				},
				Action: &v1.Action{
					Pass: "test",
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			msg: "invalid condition",
		},
		{
			match: v1.Match{
				Conditions: []v1.Condition{
					{
						Cookie: "version",
						Value:  "v1",
					},
				},
				Action: &v1.Action{},
			},
			upstreamNames: map[string]sets.Empty{},
			msg:           "invalid  action",
		},
		{
			match: v1.Match{
				Conditions: []v1.Condition{
					{
						Cookie: "version",
						Value:  "v1",
					},
				},
				Action: &v1.Action{
					Pass: "test-1",
				},
				Splits: []v1.Split{
					{
						Weight: 90,
						Action: &v1.Action{
							Pass: "test-1",
						},
					},
					{
						Weight: 10,
						Action: &v1.Action{
							Pass: "test-2",
						},
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			msg: "both splits and action are set",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateMatch(test.match, field.NewPath("match"), test.upstreamNames, "")
		if len(allErrs) == 0 {
			t.Errorf("validateMatch() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestIsValidMatchValue(t *testing.T) {
	t.Parallel()
	validValues := []string{
		"abc",
		"123",
		`\"
		abc\"`,
		`\"`,
	}

	for _, value := range validValues {
		errs := isValidMatchValue(value)
		if len(errs) > 0 {
			t.Errorf("isValidMatchValue(%q) returned errors %v for valid input", value, errs)
		}
	}

	invalidValues := []string{
		`"`,
		`\`,
		`abc"`,
		`abc\\\`,
		`a"b`,
	}

	for _, value := range invalidValues {
		errs := isValidMatchValue(value)
		if len(errs) == 0 {
			t.Errorf("isValidMatchValue(%q) returned no errors for invalid input", value)
		}
	}
}

func TestValidateVirtualServerRoute(t *testing.T) {
	t.Parallel()
	virtualServerRoute := v1.VirtualServerRoute{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "coffee",
			Namespace: "default",
		},
		Spec: v1.VirtualServerRouteSpec{
			Host: "example.com",
			Upstreams: []v1.Upstream{
				{
					Name:    "first",
					Service: "service-1",
					Port:    80,
				},
				{
					Name:    "second",
					Service: "service-2",
					Port:    80,
				},
			},
			Subroutes: []v1.Route{
				{
					Path: "/test/first",
					Action: &v1.Action{
						Pass: "first",
					},
				},
				{
					Path: "/test/second",
					Action: &v1.Action{
						Pass: "second",
					},
				},
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	err := vsv.ValidateVirtualServerRoute(&virtualServerRoute)
	if err != nil {
		t.Errorf("ValidateVirtualServerRoute() returned error %v for valid input %v", err, virtualServerRoute)
	}
}

func TestValidateVirtualServerRouteForVirtualServer(t *testing.T) {
	t.Parallel()
	virtualServerRoute := v1.VirtualServerRoute{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "coffee",
			Namespace: "default",
		},
		Spec: v1.VirtualServerRouteSpec{
			Host: "example.com",
			Upstreams: []v1.Upstream{
				{
					Name:    "first",
					Service: "service-1",
					Port:    80,
				},
				{
					Name:    "second",
					Service: "service-2",
					Port:    80,
				},
			},
			Subroutes: []v1.Route{
				{
					Path: "/test/first",
					Action: &v1.Action{
						Pass: "first",
					},
				},
				{
					Path: "/test/second",
					Action: &v1.Action{
						Pass: "second",
					},
				},
			},
		},
	}
	virtualServerHost := "example.com"
	pathPrefix := "/test"

	vsv := &VirtualServerValidator{isPlus: false}

	err := vsv.ValidateVirtualServerRouteForVirtualServer(&virtualServerRoute, virtualServerHost, pathPrefix)
	if err != nil {
		t.Errorf("ValidateVirtualServerRouteForVirtualServer() returned error %v for valid input %v", err, virtualServerRoute)
	}
}

func TestValidateVirtualServerRouteHost(t *testing.T) {
	t.Parallel()
	virtualServerHost := "example.com"

	validHost := "example.com"

	allErrs := validateVirtualServerRouteHost(validHost, virtualServerHost, field.NewPath("host"))
	if len(allErrs) > 0 {
		t.Errorf("validateVirtualServerRouteHost() returned errors %v for valid input", allErrs)
	}

	invalidHost := "foo.example.com"

	allErrs = validateVirtualServerRouteHost(invalidHost, virtualServerHost, field.NewPath("host"))
	if len(allErrs) == 0 {
		t.Errorf("validateVirtualServerRouteHost() returned no errors for invalid input")
	}
}

func TestValidateVirtualServerRouteSubroutes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		routes        []v1.Route
		upstreamNames sets.Set[string]
		vsPath        string
		msg           string
	}{
		{
			routes:        []v1.Route{},
			upstreamNames: sets.Set[string]{},
			vsPath:        "/",
			msg:           "no routes",
		},
		{
			routes: []v1.Route{
				{
					Path: "/",
					Action: &v1.Action{
						Pass: "test",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			vsPath: "/",
			msg:    "valid prefix route",
		},
		{
			routes: []v1.Route{
				{
					Path: "/",
					Action: &v1.Action{
						Pass: "test",
					},
				},
				{
					Path: "/test",
					Action: &v1.Action{
						Pass: "test",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			vsPath: "/",
			msg:    "valid route prefix with two paths",
		},
		{
			routes: []v1.Route{
				{
					Path: "~/test",
					Action: &v1.Action{
						Pass: "test",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			vsPath: "~/test",
			msg:    "valid regex route",
		},
		{
			routes: []v1.Route{
				{
					Path: "~ /regex1/?(.*)",
					Action: &v1.Action{
						Pass: "test",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			vsPath: "~ /regex1/?(.*)",
			msg:    "valid regex route",
		},
		{
			routes: []v1.Route{
				{
					Path: "=/test",
					Action: &v1.Action{
						Pass: "test",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test": {},
			},
			vsPath: "=/test",
			msg:    "valid exact route",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateVirtualServerRouteSubroutes(test.routes, field.NewPath("subroutes"), test.upstreamNames,
			test.vsPath, "default")
		if len(allErrs) > 0 {
			t.Errorf("validateVirtualServerRouteSubroutes() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidateVirtualServerRouteSubroutesFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		routes        []v1.Route
		upstreamNames sets.Set[string]
		vsPath        string
		msg           string
	}{
		{
			routes: []v1.Route{
				{
					Path: "/test",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Path: "/test",
					Action: &v1.Action{
						Pass: "test-2",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
				"test-2": {},
			},
			vsPath: "/",
			msg:    "duplicated paths",
		},
		{
			routes: []v1.Route{
				{
					Path:   "",
					Action: nil,
				},
			},
			upstreamNames: map[string]sets.Empty{},
			vsPath:        "",
			msg:           "invalid route",
		},
		{
			routes: []v1.Route{
				{
					Path: "/",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
			},
			vsPath: "/abc",
			msg:    "invalid prefix",
		},
		{
			routes: []v1.Route{
				{
					Path: "/abc",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Path: "~^/test",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
			},
			vsPath: "/abc",
			msg:    "prefix vs path with both matching prefix and mismatching regex subroute path",
		},
		{
			routes: []v1.Route{
				{
					Path: "~/test",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
			},
			vsPath: "/test",
			msg:    "prefix vs path with matching regex subroute path",
		},
		{
			routes: []v1.Route{
				{
					Path: "=/test",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
			},
			vsPath: "/test",
			msg:    "prefix vs path with matching exact subroute path",
		},
		{
			routes: []v1.Route{
				{
					Path: "/test",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
			},
			vsPath: "=/test",
			msg:    "exact vs path with prefix subroute path",
		},
		{
			routes: []v1.Route{
				{
					Path: "=/test",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
			},
			vsPath: "~/test",
			msg:    "regex vs path with exact subroute path",
		},
		{
			routes: []v1.Route{
				{
					Path: "=/test",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Path: "/abc",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
			},
			vsPath: "/abc",
			msg:    "prefix vs path with both exact and matching prefix subroute path",
		},
		{
			routes: []v1.Route{
				{
					Path: "~/abc",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
				{
					Path: "/test",
					Action: &v1.Action{
						Pass: "test-1",
					},
				},
			},
			upstreamNames: map[string]sets.Empty{
				"test-1": {},
			},
			vsPath: "/test",
			msg:    "prefix vs path with both regex and matching prefix subroute path",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateVirtualServerRouteSubroutes(test.routes, field.NewPath("subroutes"), test.upstreamNames,
			test.vsPath, "default")
		if len(allErrs) == 0 {
			t.Errorf("validateVirtualServerRouteSubroutes() returned no errors for the case of %s", test.msg)
		}
	}
}

func TestValidateUpstreamLBMethod(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method string
		isPlus bool
	}{
		{
			method: "round_robin",
			isPlus: false,
		},
		{
			method: "",
			isPlus: false,
		},
		{
			method: "ip_hash",
			isPlus: true,
		},
		{
			method: "",
			isPlus: true,
		},
	}

	for _, test := range tests {
		allErrs := validateUpstreamLBMethod(test.method, field.NewPath("lb-method"), test.isPlus)

		if len(allErrs) != 0 {
			t.Errorf("validateUpstreamLBMethod(%q, %v) returned errors for method %s", test.method, test.isPlus, test.method)
		}
	}
}

func TestValidateUpstreamLBMethodFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method string
		isPlus bool
	}{
		{
			method: "wrong",
			isPlus: false,
		},
		{
			method: "wrong",
			isPlus: true,
		},
	}

	for _, test := range tests {
		allErrs := validateUpstreamLBMethod(test.method, field.NewPath("lb-method"), test.isPlus)

		if len(allErrs) == 0 {
			t.Errorf("validateUpstreamLBMethod(%q, %v) returned no errors for method %s", test.method, test.isPlus, test.method)
		}
	}
}

func TestValidatePositiveIntOrZeroFromPointer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		number *int
		msg    string
	}{
		{
			number: nil,
			msg:    "valid (nil)",
		},
		{
			number: createPointerFromInt(0),
			msg:    "valid (0)",
		},
		{
			number: createPointerFromInt(1),
			msg:    "valid (1)",
		},
	}

	for _, test := range tests {
		allErrs := validatePositiveIntOrZeroFromPointer(test.number, field.NewPath("int-field"))

		if len(allErrs) != 0 {
			t.Errorf("validatePositiveIntOrZeroFromPointer returned errors for case: %v", test.msg)
		}
	}
}

func TestValidatePositiveIntOrZeroFromPointerFails(t *testing.T) {
	t.Parallel()
	number := createPointerFromInt(-1)
	allErrs := validatePositiveIntOrZeroFromPointer(number, field.NewPath("int-field"))

	if len(allErrs) == 0 {
		t.Error("validatePositiveIntOrZeroFromPointer returned no errors for case: invalid (-1)")
	}
}

func TestValidatePositiveIntOrZero(t *testing.T) {
	t.Parallel()
	tests := []struct {
		number int
		msg    string
	}{
		{
			number: 0,
			msg:    "valid (0)",
		},
		{
			number: 1,
			msg:    "valid (1)",
		},
	}

	for _, test := range tests {
		allErrs := validatePositiveIntOrZero(test.number, field.NewPath("int-field"))

		if len(allErrs) != 0 {
			t.Errorf("validatePositiveIntOrZero returned errors for case: %v", test.msg)
		}
	}
}

func TestValidatePositiveIntOrZeroFails(t *testing.T) {
	t.Parallel()
	allErrs := validatePositiveIntOrZero(-1, field.NewPath("int-field"))

	if len(allErrs) == 0 {
		t.Error("validatePositiveIntOrZero returned no errors for case: invalid (-1)")
	}
}

func TestValidateBuffer(t *testing.T) {
	t.Parallel()
	validbuff := &v1.UpstreamBuffers{Number: 8, Size: "8k"}
	allErrs := validateBuffer(validbuff, field.NewPath("buffers-field"))

	if len(allErrs) != 0 {
		t.Errorf("validateBuffer returned errors %v valid input %v", allErrs, validbuff)
	}

	invalidbuff := []*v1.UpstreamBuffers{
		{
			Number: -8,
			Size:   "15m",
		},
		{
			Number: 8,
			Size:   "15G",
		},
		{
			Number: 8,
			Size:   "",
		},
	}
	for _, test := range invalidbuff {
		allErrs = validateBuffer(test, field.NewPath("buffers-field"))
		if len(allErrs) == 0 {
			t.Errorf("validateBuffer didn't return error for invalid input %v.", test)
		}
	}
}

func TestValidateUpstreamHealthCheck(t *testing.T) {
	t.Parallel()
	hc := &v1.HealthCheck{
		Enable:   true,
		Path:     "/healthz",
		Interval: "4s",
		Jitter:   "2s",
		Fails:    3,
		Passes:   2,
		Port:     8080,
		TLS: &v1.UpstreamTLS{
			Enable: true,
		},
		ConnectTimeout: "1s",
		ReadTimeout:    "1s",
		SendTimeout:    "1s",
		Headers: []v1.Header{
			{
				Name:  "Host",
				Value: "my.service",
			},
		},
		StatusMatch:   "! 500",
		Mandatory:     true,
		Persistent:    true,
		KeepaliveTime: "120s",
	}

	allErrs := validateUpstreamHealthCheck(hc, "", field.NewPath("healthCheck"))

	if len(allErrs) != 0 {
		t.Errorf("validateUpstreamHealthCheck() returned errors for valid input %v", hc)
	}
}

func TestValidateGrpcUpstreamHealthCheck(t *testing.T) {
	t.Parallel()
	tests := []struct {
		hc *v1.HealthCheck
	}{
		{
			hc: &v1.HealthCheck{
				Enable:   true,
				Interval: "4s",
				Jitter:   "2s",
				Fails:    3,
				Passes:   2,
				Port:     8080,
				TLS: &v1.UpstreamTLS{
					Enable: true,
				},
				ConnectTimeout: "1s",
				ReadTimeout:    "1s",
				SendTimeout:    "1s",
				Headers: []v1.Header{
					{
						Name:  "Host",
						Value: "my.service",
					},
				},
				GRPCStatus:  createPointerFromInt(12),
				GRPCService: "tea-servicev2",
			},
		},
		{
			hc: &v1.HealthCheck{
				Enable: true,
			},
		},
	}

	for _, test := range tests {
		allErrs := validateUpstreamHealthCheck(test.hc, "grpc", field.NewPath("healthCheck"))

		if len(allErrs) != 0 {
			t.Errorf("validateUpstreamHealthCheck() returned errors for valid input %v", test.hc)
		}
	}
}

func TestValidateUpstreamHealthCheckFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		hc *v1.HealthCheck
	}{
		{
			hc: &v1.HealthCheck{
				Enable: true,
				Path:   "/healthz//;",
			},
		},
		{
			hc: &v1.HealthCheck{
				Enable: false,
				Path:   "/healthz//;",
			},
		},
		{
			hc: &v1.HealthCheck{
				Enable:     true,
				Path:       "/healthz",
				GRPCStatus: createPointerFromInt(12),
			},
		},
		{
			hc: &v1.HealthCheck{
				Enable:      true,
				Path:        "/healthz",
				GRPCService: "tea-servicev2",
			},
		},
		{
			hc: &v1.HealthCheck{
				Enable:     true,
				Path:       "/healthz",
				Persistent: true,
			},
		},
	}

	for _, test := range tests {
		allErrs := validateUpstreamHealthCheck(test.hc, "", field.NewPath("healthCheck"))

		if len(allErrs) == 0 {
			t.Errorf("validateUpstreamHealthCheck() returned no errors for invalid input %v", test.hc)
		}
	}
}

func TestValidateGrpcUpstreamHealthCheckFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		hc *v1.HealthCheck
	}{
		{
			hc: &v1.HealthCheck{
				Enable: true,
				Path:   "/healthz",
			},
		},
		{
			hc: &v1.HealthCheck{
				Enable:      true,
				StatusMatch: "! 500",
			},
		},
		{
			hc: &v1.HealthCheck{
				Enable:     true,
				GRPCStatus: createPointerFromInt(400),
			},
		},
		{
			hc: &v1.HealthCheck{
				Enable:      true,
				GRPCService: "bh tyh",
			},
		},
	}

	for _, test := range tests {
		allErrs := validateUpstreamHealthCheck(test.hc, "grpc", field.NewPath("healthCheck"))

		if len(allErrs) == 0 {
			t.Errorf("validateUpstreamHealthCheck() returned no errors for invalid input %v", test.hc)
		}
	}
}

func TestValidateStatusMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status string
	}{
		{
			status: "200",
		},
		{
			status: "! 500",
		},
		{
			status: "200 204",
		},
		{
			status: "! 301 302",
		},
		{
			status: "200-399",
		},
		{
			status: "! 400-599",
		},
		{
			status: "301-303 307",
		},
	}
	for _, test := range tests {
		allErrs := validateStatusMatch(test.status, field.NewPath("statusMatch"))

		if len(allErrs) != 0 {
			t.Errorf("validateStatusMatch() returned errors %v for valid input %v", allErrs, test.status)
		}
	}
}

func TestValidateStatusMatchFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status string
		msg    string
	}{
		{
			status: "qwe",
			msg:    "Invalid: no digits",
		},
		{
			status: "!",
			msg:    "Invalid: `!` character only",
		},
		{
			status: "!500",
			msg:    "Invalid: no space after !",
		},
		{
			status: "0",
			msg:    "Invalid: status out of range (below 100)",
		},
		{
			status: "1000",
			msg:    "Invalid: status out of range (above 999)",
		},
		{
			status: "20-600",
			msg:    "Invalid: code in range is out of range",
		},
		{
			status: "! 200 ! 500",
			msg:    "Invalid: 2 exclamation symbols",
		},
		{
			status: "200 - 500",
			msg:    "Invalid: range with space around `-`",
		},
		{
			status: "500-200",
			msg:    "Invalid: range must be min < max",
		},
		{
			status: "200-200-400",
			msg:    "Invalid: range with more than 2 numbers",
		},
	}
	for _, test := range tests {
		allErrs := validateStatusMatch(test.status, field.NewPath("statusMatch"))

		if len(allErrs) == 0 {
			t.Errorf("validateStatusMatch() returned no errors for case %v", test.msg)
		}
	}
}

func TestValidateHeader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		header v1.Header
	}{
		{
			header: v1.Header{
				Name:  "Host",
				Value: "my.service",
			},
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: `\"my.service\"`,
			},
		},
	}

	for _, test := range tests {
		allErrs := validateHeader(test.header, field.NewPath("headers"))

		if len(allErrs) != 0 {
			t.Errorf("validateHeader() returned errors %v for valid input %v", allErrs, test.header)
		}
	}
}

func TestValidateHeaderFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		header v1.Header
		msg    string
	}{
		{
			header: v1.Header{
				Name:  "12378 qwe ",
				Value: "my.service",
			},
			msg: "Invalid name with spaces",
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: `"my.service`,
			},
			msg: `Invalid value with unescaped '"'`,
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: `my.service\`,
			},
			msg: "Invalid value with ending '\\'",
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: "$my.service",
			},
			msg: "Invalid value with '$' character",
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: "my.\\$service",
			},
			msg: "Invalid value with escaped '$' character",
		},
	}
	for _, test := range tests {
		allErrs := validateHeader(test.header, field.NewPath("headers"))

		if len(allErrs) == 0 {
			t.Errorf("validateHeader() returned no errors for case: %v", test.msg)
		}
	}
}

func TestValidateIntFromString(t *testing.T) {
	t.Parallel()
	input := "404"
	_, errMsg := validateIntFromString(input)

	if errMsg != "" {
		t.Errorf("validateIntFromString() returned errors %v for valid input %v", errMsg, input)
	}
}

func TestValidateIntFromStringFails(t *testing.T) {
	t.Parallel()
	input := "not a number"
	_, errMsg := validateIntFromString(input)

	if errMsg == "" {
		t.Errorf("validateIntFromString() returned no errors for invalid input %v", input)
	}
}

func TestRejectPlusResourcesInOSS(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstream *v1.Upstream
	}{
		{
			upstream: &v1.Upstream{
				SlowStart: "10s",
			},
		},
		{
			upstream: &v1.Upstream{
				HealthCheck: &v1.HealthCheck{},
			},
		},
		{
			upstream: &v1.Upstream{
				SessionCookie: &v1.SessionCookie{},
			},
		},
		{
			upstream: &v1.Upstream{
				Queue: &v1.UpstreamQueue{},
			},
		},
		{
			upstream: &v1.Upstream{
				NTLM: true,
			},
		},
	}

	for _, test := range tests {
		allErrsOSS := rejectPlusResourcesInOSS(*test.upstream, field.NewPath("upstreams"), false)

		if len(allErrsOSS) == 0 {
			t.Errorf("rejectPlusResourcesInOSS() returned no errors for upstream: %v", test.upstream)
		}

		allErrsPlus := rejectPlusResourcesInOSS(*test.upstream, field.NewPath("upstreams"), true)

		if len(allErrsPlus) != 0 {
			t.Errorf("rejectPlusResourcesInOSS() returned no errors for upstream: %v", test.upstream)
		}
	}
}

func TestValidateQueue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstreamQueue *v1.UpstreamQueue
		msg           string
	}{
		{
			upstreamQueue: &v1.UpstreamQueue{Size: 10, Timeout: "10s"},
			msg:           "valid upstream queue with size and timeout",
		},
		{
			upstreamQueue: nil,
			msg:           "upstream queue nil",
		},
		{
			upstreamQueue: nil,
			msg:           "upstream queue nil in OSS",
		},
	}

	for _, test := range tests {
		allErrs := validateQueue(test.upstreamQueue, field.NewPath("queue"))
		if len(allErrs) != 0 {
			t.Errorf("validateQueue() returned errors %v for valid input for the case of %s", allErrs, test.msg)
		}
	}
}

func TestValidateQueueFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		upstreamQueue *v1.UpstreamQueue
		msg           string
	}{
		{
			upstreamQueue: &v1.UpstreamQueue{Size: -1, Timeout: "10s"},
			msg:           "upstream queue with invalid size",
		},
		{
			upstreamQueue: &v1.UpstreamQueue{Size: 10, Timeout: "-10"},
			msg:           "upstream queue with invalid timeout",
		},
	}

	for _, test := range tests {
		allErrs := validateQueue(test.upstreamQueue, field.NewPath("queue"))
		if len(allErrs) == 0 {
			t.Errorf("validateQueue() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestValidateSessionCookie(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sc  *v1.SessionCookie
		msg string
	}{
		{
			sc:  &v1.SessionCookie{Enable: true, Name: "min"},
			msg: "min valid config",
		},
		{
			sc:  &v1.SessionCookie{Enable: true, Name: "test", Expires: "max"},
			msg: "valid config with expires max",
		},
		{
			sc: &v1.SessionCookie{
				Enable: true, Name: "test", Path: "/tea", Expires: "1", Domain: ".example.com", HTTPOnly: false, Secure: true,
			},
			msg: "max valid config",
		},
	}
	for _, test := range tests {
		allErrs := validateSessionCookie(test.sc, field.NewPath("sessionCookie"))
		if len(allErrs) != 0 {
			t.Errorf("validateSessionCookie() returned errors %v for valid input for the case of: %s", allErrs, test.msg)
		}
	}
}

func TestValidateSessionCookie_IsValidOnValidSameSiteInput(t *testing.T) {
	t.Parallel()

	samesites := []string{
		"strict",
		"Strict",
		"STRICT",
		"lax",
		"Lax",
		"LAX",
		"none",
		"None",
		"NONE",
	}
	for _, samesite := range samesites {
		sc := &v1.SessionCookie{Enable: true, Name: "ValidCookie", SameSite: samesite}
		allErr := validateSessionCookie(sc, field.NewPath("sessionCookie"))
		if len(allErr) != 0 {
			t.Errorf("validateSessionCookie() returned errors for valid input: %s", samesite)
		}
	}
}

func TestValidateSessionCookie_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sc  *v1.SessionCookie
		msg string
	}{
		{
			sc:  &v1.SessionCookie{Enable: true},
			msg: "missing required field: Name",
		},
		{
			sc:  &v1.SessionCookie{Enable: false},
			msg: "session cookie not enabled",
		},
		{
			sc:  &v1.SessionCookie{Enable: true, Name: "$ecret-Name"},
			msg: "invalid name format",
		},
		{
			sc:  &v1.SessionCookie{Enable: true, Name: "test", Expires: "EGGS"},
			msg: "invalid time format",
		},
		{
			sc:  &v1.SessionCookie{Enable: true, Name: "test", Path: "/ coffee"},
			msg: "invalid path format",
		},
		{
			sc:  &v1.SessionCookie{Enable: true, Name: "ValidCookie", SameSite: "bogus_value"},
			msg: "invalid samesite value",
		},
	}
	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			allErrs := validateSessionCookie(test.sc, field.NewPath("sessionCookie"))
			if len(allErrs) == 0 {
				t.Errorf("validateSessionCookie() did not return errors for invalid input for the case of: %s", test.msg)
			}
		})
	}
}

func TestValidateRedirectStatusCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code int
	}{
		{code: 301},
		{code: 302},
		{code: 307},
		{code: 308},
	}
	for _, test := range tests {
		allErrs := validateRedirectStatusCode(test.code, field.NewPath("code"))
		if len(allErrs) != 0 {
			t.Errorf("validateRedirectStatusCode(%v) returned errors %v for valid input", test.code, allErrs)
		}
	}
}

func TestValidateRedirectStatusCodeFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code int
	}{
		{code: 309},
		{code: 299},
		{code: 305},
	}
	for _, test := range tests {
		allErrs := validateRedirectStatusCode(test.code, field.NewPath("code"))
		if len(allErrs) == 0 {
			t.Errorf("validateRedirectStatusCode(%v) returned no errors for invalid input", test.code)
		}
	}
}

func TestIsRegexOrExactMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path     string
		expected bool
	}{
		{
			path:     "/path",
			expected: false,
		},
		{
			path:     "~ .*\\.jpg",
			expected: true,
		},
		{
			path:     "=/exact/match",
			expected: true,
		},
	}

	for _, test := range tests {
		result := isRegexOrExactMatch(test.path)
		if result != test.expected {
			t.Errorf("isRegexOrExactMatch(%v) returned %v but expected %v", test.path, result, test.expected)
		}
	}
}

func TestValidateEscapedStringWithVariables(t *testing.T) {
	t.Parallel()
	specialVariables := []string{"http_"}
	variables := map[string]bool{
		"request_uri": true,
		"host":        true,
	}

	tests := []struct {
		str string
		msg string
	}{
		{
			str: "Hello World",
			msg: "single string",
		},
		{
			str: "${host}${request_uri}",
			msg: "string with variables",
		},
		{
			str: "{abc} %&*()!@#",
			msg: "string with symbols",
		},
		{
			str: "${http_authorization}",
			msg: "special variable with name",
		},
		{
			str: `
				<html>
				<body>
				<h1>Hello</h1>
				</body>
				</html>`,
			msg: "string with multiple lines",
		},
	}

	isPlus := false

	for _, test := range tests {
		allErrs := validateEscapedStringWithVariables(test.str, field.NewPath("body"), specialVariables, variables, isPlus)
		if len(allErrs) != 0 {
			t.Errorf("validateEscapedStringWithVariables(%v) returned errors %v for valid input for the case of: %v", test.str, allErrs, test.msg)
		}
	}
}

func TestValidateEscapedStringWithVariablesFails(t *testing.T) {
	t.Parallel()
	specialVariables := []string{"http_"}
	variables := map[string]bool{
		"request_uri": true,
		"host":        true,
	}

	tests := []struct {
		str string
		msg string
	}{
		{
			str: "Request to $host",
			msg: "invalid variable format",
		},
		{
			str: "Request to ${host_uri}",
			msg: "invalid variable",
		},
		{
			str: "Request to ${https_authorization}",
			msg: "invalid special variable",
		},
		{
			str: `Request to host failed "`,
			msg: "unescaped double quotes",
		},
		{
			str: "Please access to ${something}.com",
			msg: "invalid variable",
		},
	}

	isPlus := false

	for _, test := range tests {
		allErrs := validateEscapedStringWithVariables(test.str, field.NewPath("string"), specialVariables, variables, isPlus)
		if len(allErrs) == 0 {
			t.Errorf("validateEscapedStringWithVariables(%v) returned no errors for invalid input for the case of: %v", test.str, test.msg)
		}
	}
}

func TestValidateActionReturnType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		defaultType string
		msg         string
	}{
		{
			defaultType: "application/json",
			msg:         "normal MIME type",
		},
		{
			defaultType: `\"application/json\"`,
			msg:         "double quotes escaped",
		},
	}

	for _, test := range tests {
		allErrs := validateActionReturnType(test.defaultType, field.NewPath("type"))
		if len(allErrs) != 0 {
			t.Errorf("validateActionReturnType(%v) returned errors %v for the case of: %v", test.defaultType, allErrs, test.msg)
		}
	}
}

func TestValidateActionReturnTypeFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		defaultType string
		msg         string
	}{
		{
			defaultType: "application/{json}",
			msg:         "use of forbidden symbols",
		},
		{
			defaultType: "application;json",
			msg:         "use of forbidden symbols",
		},
		{
			defaultType: `"application/json"`,
			msg:         "double quotes not escaped",
		},
	}

	for _, test := range tests {
		allErrs := validateActionReturnType(test.defaultType, field.NewPath("type"))
		if len(allErrs) == 0 {
			t.Errorf("validateActionReturnType(%v) returned no errors for the case of: %v", test.defaultType, test.msg)
		}
	}
}

func TestValidateActionReturn(t *testing.T) {
	t.Parallel()
	tests := []*v1.ActionReturn{
		{
			Body: "Hello World",
		},
		{
			Body: "The URI is ${request_uri}",
		},
		{
			Body: "The header abc is ${http_abc}",
		},
		{
			Type: "application/json",
			Body: "Hello World",
		},
		{
			Code: 200,
			Type: "application/json",
			Body: "Hello World",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateActionReturn(test, field.NewPath("return"), returnBodySpecialVariables, returnBodyVariables)
		if len(allErrs) != 0 {
			t.Errorf("validateActionReturn(%v) returned errors for valid input", test)
		}
	}
}

func TestValidateActionReturnFails(t *testing.T) {
	t.Parallel()
	tests := []*v1.ActionReturn{
		{},
		{
			Body: "Hello ${somevar}",
		},
		{
			Body: "Hello ${http_%}",
		},
		{
			Code: 301,
			Body: "Hello World",
		},
		{
			Code: 200,
			Type: `application/"json"`,
			Body: "Hello World",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateActionReturn(test, field.NewPath("return"), returnBodySpecialVariables, returnBodyVariables)
		if len(allErrs) == 0 {
			t.Errorf("validateActionReturn(%v) returned no errors for invalid input", test)
		}
	}
}

func TestValidateActionProxy(t *testing.T) {
	t.Parallel()
	upstreamNames := map[string]sets.Empty{
		"upstream1": {},
	}
	path := "/path"
	actionProxy := &v1.ActionProxy{
		Upstream:    "upstream1",
		RewritePath: "/test",
	}

	vsv := &VirtualServerValidator{isPlus: false}

	allErrs := vsv.validateActionProxy(actionProxy, field.NewPath("proxy"), upstreamNames, path, false)

	if len(allErrs) != 0 {
		t.Errorf("validateActionProxy(%+v, %v, %v) returned errors for valid input: %v", actionProxy, upstreamNames, path, allErrs)
	}
}

func TestValidateActionProxyFails(t *testing.T) {
	t.Parallel()
	upstreamNames := map[string]sets.Empty{
		"upstream1": {},
	}
	path := "/path"
	actionProxy := &v1.ActionProxy{
		Upstream: "",
	}

	vsv := &VirtualServerValidator{isPlus: false}

	allErrs := vsv.validateActionProxy(actionProxy, field.NewPath("proxy"), upstreamNames, path, false)

	if len(allErrs) == 0 {
		t.Errorf("validateActionProxy(%+v, %v, %v) returned no errors for invalid input", actionProxy, upstreamNames, path)
	}
}

func TestValidateActionProxyRewritePath(t *testing.T) {
	t.Parallel()
	tests := []string{"/rewrite", "/rewrite", `/$2`}
	for _, test := range tests {
		allErrs := validateActionProxyRewritePath(test, field.NewPath("rewritePath"))
		if len(allErrs) != 0 {
			t.Errorf("validateActionProxyRewritePath(%v) returned errors for valid input: %v", test, allErrs)
		}
	}
}

func TestValidateActionProxyRewritePathFails(t *testing.T) {
	t.Parallel()
	tests := []string{`/\d{3}`, `(`, "$request_uri"}
	for _, test := range tests {
		allErrs := validateActionProxyRewritePath(test, field.NewPath("rewritePath"))
		if len(allErrs) == 0 {
			t.Errorf("validateActionProxyRewritePath(%v) returned no errors for invalid input", test)
		}
	}
}

func TestValidateActionProxyRewritePathForRegexp(t *testing.T) {
	t.Parallel()
	tests := []string{"/rewrite$1", "test", `/$2`, `\"test\"`}
	for _, test := range tests {
		allErrs := validateActionProxyRewritePathForRegexp(test, field.NewPath("rewritePath"))
		if len(allErrs) != 0 {
			t.Errorf("validateActionProxyRewritePathForRegexp(%v) returned errors for valid input: %v", test, allErrs)
		}
	}
}

func TestValidateActionProxyRewritePathForRegexpFails(t *testing.T) {
	t.Parallel()
	tests := []string{"$request_uri", `"test"`, `test\`}
	for _, test := range tests {
		allErrs := validateActionProxyRewritePathForRegexp(test, field.NewPath("rewritePath"))
		if len(allErrs) == 0 {
			t.Errorf("validateActionProxyRewritePathForRegexp(%v) returned no errors for invalid input", test)
		}
	}
}

func TestValidateActionProxyHeader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		header v1.Header
	}{
		{
			header: v1.Header{
				Name:  "Host",
				Value: "my.service",
			},
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: `\"my.service\"`,
			},
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: "${request_uri}",
			},
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: "${http_some_header}",
			},
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: "${request_uri} and ${http_some_header}",
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateActionProxyHeader(test.header, field.NewPath("headers"))

		if len(allErrs) != 0 {
			t.Errorf("validateActionProxyHeader() returned errors %v for valid input %v", allErrs, test.header)
		}
	}
}

func TestValidateActionProxyHeaderFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		header v1.Header
		msg    string
	}{
		{
			header: v1.Header{
				Name:  "12378 qwe ",
				Value: "my.service",
			},
			msg: "Invalid name with spaces",
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: `"my.service`,
			},
			msg: `Invalid value with unescaped '"'`,
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: `my.service\`,
			},
			msg: "Invalid value with ending '\\'",
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: "${realpath_root}",
			},
			msg: "Invalid variable",
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: "${sent_http_name}",
			},
			msg: "Invalid special variable",
		},
		{
			header: v1.Header{
				Name:  "Host",
				Value: "my.\\$service",
			},
			msg: "Invalid value with escaped '$' character",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateActionProxyHeader(test.header, field.NewPath("headers"))

		if len(allErrs) == 0 {
			t.Errorf("validateActionProxyHeader() returned no errors for case: %v", test.msg)
		}
	}
}

func TestValidateActionProxyRequestHeaders(t *testing.T) {
	t.Parallel()
	requestHeaders := &v1.ProxyRequestHeaders{
		Set: []v1.Header{
			{
				Name:  "Host",
				Value: "nginx.org",
			},
			{
				Name:  "scheme",
				Value: "${scheme}",
			},
			{
				Name:  "user",
				Value: "${http_user}",
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	allErrs := vsv.validateActionProxyRequestHeaders(requestHeaders, field.NewPath("requestHeaders"))
	if len(allErrs) != 0 {
		t.Errorf("validateActionProxyRequestHeaders(%v) returned errors for valid input: %v", requestHeaders, allErrs)
	}
}

func TestValidateActionProxyRequestHeadersFails(t *testing.T) {
	t.Parallel()
	invalidHeaders := []*v1.ProxyRequestHeaders{
		{
			Set: []v1.Header{
				{
					Name:  "in va lid",
					Value: "",
				},
			},
		},
		{
			Set: []v1.Header{
				{
					Name:  "Host",
					Value: "$var",
				},
			},
		},
		{
			Set: []v1.Header{
				{
					Name:  "",
					Value: "nginx.org",
				},
			},
		},
		{
			Set: []v1.Header{
				{
					Name:  "Host",
					Value: "${http_%}",
				},
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, headers := range invalidHeaders {
		allErrs := vsv.validateActionProxyRequestHeaders(headers, field.NewPath("requestHeaders"))
		if len(allErrs) == 0 {
			t.Errorf("validateActionProxyRequestHeaders(%v) returned no errors for invalid input", headers)
		}
	}
}

func TestValidateActionProxyResponseHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		responseHeaders *v1.ProxyResponseHeaders
	}{
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Hide:   []string{"Header"},
				Pass:   []string{"Header"},
				Ignore: []string{"Expires"},
				Add: []v1.AddHeader{
					{
						Header: v1.Header{
							Name:  "Host",
							Value: "nginx.org",
						},
						Always: false,
					},
				},
			},
		},
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Hide: []string{"Header"},
			},
		},
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Pass: []string{"Header"},
			},
		},
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Ignore: []string{"Expires"},
			},
		},
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Add: []v1.AddHeader{
					{
						Header: v1.Header{
							Name:  "Host",
							Value: "nginx.org",
						},
						Always: false,
					},
					{
						Header: v1.Header{
							Name:  "uri",
							Value: "${request_uri}",
						},
					},
					{
						Header: v1.Header{
							Name:  "abc",
							Value: "${http_abc}",
						},
					},
				},
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateActionProxyResponseHeaders(test.responseHeaders, field.NewPath("responseHeaders"))
		if len(allErrs) != 0 {
			t.Errorf("validateActionProxyResponseHeaders(%v) returned errors for valid input: %v", test.responseHeaders, allErrs)
		}
	}
}

func TestValidateActionProxyResponseHeadersFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		responseHeaders *v1.ProxyResponseHeaders
		msg             string
	}{
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Hide:   []string{""},
				Pass:   []string{""},
				Ignore: []string{""},
				Add: []v1.AddHeader{
					{
						Header: v1.Header{
							Name:  "",
							Value: "nginx.org",
						},
					},
				},
			},
			msg: "all fields invalid",
		},
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Hide: []string{"invalid header"},
			},
			msg: "invalid hide headers",
		},
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Pass: []string{"$invalid"},
			},
			msg: "invalid pass headers",
		},
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Ignore: []string{"1234 invalid"},
			},
			msg: "invalid ignore headers",
		},
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Add: []v1.AddHeader{
					{
						Header: v1.Header{
							Name:  "$invalid 123",
							Value: "nginx.org",
						},
						Always: false,
					},
				},
			},
			msg: "invalid Add header name",
		},
		{
			responseHeaders: &v1.ProxyResponseHeaders{
				Add: []v1.AddHeader{
					{
						Header: v1.Header{
							Name:  "Host",
							Value: "${invalid}",
						},
						Always: false,
					},
				},
			},
			msg: "invalid Add header value",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateActionProxyResponseHeaders(test.responseHeaders, field.NewPath("responseHeaders"))
		if len(allErrs) == 0 {
			t.Errorf("validateActionProxyResponseHeaders(%v) returned no errors for invalid input for the case of %v", test.responseHeaders, test.msg)
		}
	}
}

func TestValidateIgnoreHeaders(t *testing.T) {
	t.Parallel()
	var ignoreHeaders []string

	for header := range validIgnoreHeaders {
		ignoreHeaders = append(ignoreHeaders, header)
	}

	allErrs := validateIgnoreHeaders(ignoreHeaders, field.NewPath("ignoreHeaders"))
	if len(allErrs) != 0 {
		t.Errorf("validateIgnoreHeaders(%v) returned errors for valid input: %v", ignoreHeaders, allErrs)
	}
}

func TestValidateIgnoreHeadersFails(t *testing.T) {
	t.Parallel()
	ignoreHeaders := []string{
		"Host",
		"Connection",
	}

	allErrs := validateIgnoreHeaders(ignoreHeaders, field.NewPath("ignoreHeaders"))
	if len(allErrs) == 0 {
		t.Errorf("validateIgnoreHeaders(%v) returned no errors for invalid input", ignoreHeaders)
	}
}

func TestValidateStringNoVariables(t *testing.T) {
	t.Parallel()
	tests := []string{
		"string",
		"endWith$",
		"withNumber$1",
		"abcййй",
		"abcййй$1",
		"",
	}

	for _, test := range tests {
		allErrs := validateStringNoVariables(test, field.NewPath("rewritePath"))
		if len(allErrs) != 0 {
			t.Errorf("validateStringNoVariables(%v) returned errors for valid input: %v", test, allErrs)
		}
	}
}

func TestValidateStringNoVariablesFails(t *testing.T) {
	t.Parallel()
	tests := []string{
		"$var",
		"abcйй$й",
		"$$",
	}

	for _, test := range tests {
		allErrs := validateStringNoVariables(test, field.NewPath("rewritePath"))
		if len(allErrs) == 0 {
			t.Errorf("validateStringNoVariables(%v) returned no errors for invalid input", test)
		}
	}
}

func TestValidateActionReturnCode(t *testing.T) {
	t.Parallel()
	codes := []int{200, 201, 400, 404, 500, 502, 599}
	for _, c := range codes {
		allErrs := validateActionReturnCode(c, field.NewPath("code"))
		if len(allErrs) != 0 {
			t.Errorf("validateActionReturnCode(%v) returned errors for valid input: %v", c, allErrs)
		}
	}
}

func TestValidateActionReturnCodeFails(t *testing.T) {
	t.Parallel()
	codes := []int{0, -1, 199, 300, 399, 600, 999}
	for _, c := range codes {
		allErrs := validateActionReturnCode(c, field.NewPath("code"))
		if len(allErrs) == 0 {
			t.Errorf("validateActionReturnCode(%v) returned no errors for invalid input", c)
		}
	}
}

func TestErrorPageHasRequiredFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		errorPage v1.ErrorPage
		expected  bool
	}{
		{
			errorPage: v1.ErrorPage{
				Codes:    nil,
				Return:   nil,
				Redirect: nil,
			},
			expected: false,
		},
		{
			errorPage: v1.ErrorPage{
				Codes:    nil,
				Return:   &v1.ErrorPageReturn{},
				Redirect: &v1.ErrorPageRedirect{},
			},
			expected: false,
		},
		{
			errorPage: v1.ErrorPage{
				Codes:    nil,
				Return:   &v1.ErrorPageReturn{},
				Redirect: nil,
			},
			expected: true,
		},
		{
			errorPage: v1.ErrorPage{
				Codes:    nil,
				Return:   nil,
				Redirect: &v1.ErrorPageRedirect{},
			},
			expected: true,
		},
	}

	for _, test := range tests {
		result := errorPageHasRequiredFields(test.errorPage)
		if result != test.expected {
			t.Errorf("errorPageHasRequiredFields(%v) returned %v but expected %v", test.errorPage, result, test.expected)
		}
	}
}

func TestValidateErrorPage(t *testing.T) {
	t.Parallel()
	tests := []v1.ErrorPage{
		{
			Codes: []int{400, 404},
			Return: &v1.ErrorPageReturn{
				ActionReturn: v1.ActionReturn{
					Body: "Hello World",
				},
			},
			Redirect: nil,
		},
		{
			Codes:  []int{400, 404},
			Return: nil,
			Redirect: &v1.ErrorPageRedirect{
				ActionRedirect: v1.ActionRedirect{
					URL: "http://nginx.com",
				},
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, ep := range tests {
		allErrs := vsv.validateErrorPage(ep, field.NewPath("errorPage"))
		if len(allErrs) != 0 {
			t.Errorf("validateErrorPage(%v) returned errors for valid input: %v", ep, allErrs)
		}
	}
}

func TestValidateErrorPageFails(t *testing.T) {
	t.Parallel()
	tests := []v1.ErrorPage{
		{},
		{
			Codes:    []int{400, 404},
			Return:   &v1.ErrorPageReturn{},
			Redirect: &v1.ErrorPageRedirect{},
		},
		{
			Codes:    []int{100, 700},
			Return:   &v1.ErrorPageReturn{},
			Redirect: nil,
		},
		{
			Codes:    nil,
			Return:   &v1.ErrorPageReturn{},
			Redirect: nil,
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, ep := range tests {
		allErrs := vsv.validateErrorPage(ep, field.NewPath("errorPage"))
		if len(allErrs) == 0 {
			t.Errorf("validateErrorPage(%v) returned no errors for invalid input", ep)
		}
	}
}

func TestValidateErrorPageReturn(t *testing.T) {
	t.Parallel()
	tests := []v1.ErrorPageReturn{
		{
			ActionReturn: v1.ActionReturn{
				Code:    200,
				Type:    "",
				Body:    "Could not process request, try again",
				Headers: nil,
			},
		},
		{
			ActionReturn: v1.ActionReturn{
				Code: 0,
				Type: "",
				Body: "Could not process request, try again. Upstream status ${upstream_status}",
				Headers: []v1.Header{
					{
						Name:  "Set-Cookie",
						Value: "mycookie=true",
					},
				},
			},
		},
		{
			ActionReturn: v1.ActionReturn{
				Code:    200,
				Type:    "application/json",
				Body:    `{\"message\": \"Could not process request, try again\", \"upstream_status\": \"${upstream_status}\"}`,
				Headers: nil,
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, epr := range tests {
		epr := epr // address gosec G601
		allErrs := vsv.validateErrorPageReturn(&epr, field.NewPath("return"))
		if len(allErrs) != 0 {
			t.Errorf("validateErrorPageReturn(%v) returned errors for valid input: %v", epr, allErrs)
		}
	}
}

func TestValidateErrorPageReturnFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		msg string
		epr v1.ErrorPageReturn
	}{
		{
			msg: "empty body",
			epr: v1.ErrorPageReturn{
				ActionReturn: v1.ActionReturn{
					Code: 200,
					Type: "application/json",
					Body: "",
				},
			},
		},
		{
			msg: "unescaped double quotes",
			epr: v1.ErrorPageReturn{
				ActionReturn: v1.ActionReturn{
					Code: 200,
					Type: "",
					Body: ` "Oops, Could not process request"`,
				},
			},
		},
		{
			msg: "invalid variable",
			epr: v1.ErrorPageReturn{
				ActionReturn: v1.ActionReturn{
					Code: 0,
					Type: "",
					Body: "Could not process request, response with invalid var: ${invalid}",
				},
			},
		},
		{
			msg: "invalid cookie name",
			epr: v1.ErrorPageReturn{
				ActionReturn: v1.ActionReturn{
					Code: 200,
					Type: "application/json",
					Body: `{\"message\": \"Could not process request, try again\", \"status\": \"${status}\"}`,
					Headers: []v1.Header{
						{
							Name:  "Set-Cookie$_%^$  -",
							Value: "mycookie=true",
						},
					},
				},
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		test := test // address gosec G601
		allErrs := vsv.validateErrorPageReturn(&test.epr, field.NewPath("return"))
		if len(allErrs) == 0 {
			t.Errorf("validateErrorPageReturn(%v) returned no errors for invalid input for the case of %v", test.epr, test.msg)
		}
	}
}

func TestValidateErrorPageRedirect(t *testing.T) {
	t.Parallel()
	tests := []v1.ErrorPageRedirect{
		{
			ActionRedirect: v1.ActionRedirect{
				URL:  "http://nginx.com",
				Code: 301,
			},
		},
		{
			ActionRedirect: v1.ActionRedirect{
				URL:  "${scheme}://nginx.com",
				Code: 302,
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, epr := range tests {
		epr := epr // address gosec G601
		allErrs := vsv.validateErrorPageRedirect(&epr, field.NewPath("redirect"))
		if len(allErrs) != 0 {
			t.Errorf("validateErrorPageRedirect(%v) returned errors for valid input: %v", epr, allErrs)
		}
	}
}

func TestValidateErrorPageRedirectFails(t *testing.T) {
	t.Parallel()
	tests := []v1.ErrorPageRedirect{
		{
			ActionRedirect: v1.ActionRedirect{
				URL:  "",
				Code: 301,
			},
		},
		{
			ActionRedirect: v1.ActionRedirect{
				URL:  `"http://nginx.com"`,
				Code: 301,
			},
		},
		{
			ActionRedirect: v1.ActionRedirect{
				URL:  "http://nginx.com",
				Code: 100,
			},
		},
		{
			ActionRedirect: v1.ActionRedirect{
				URL:  "$scheme://nginx.com",
				Code: 302,
			},
		},
		{
			ActionRedirect: v1.ActionRedirect{
				URL:  "https://${host}.com",
				Code: 302,
			},
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, epr := range tests {
		epr := epr // address gosec G601
		allErrs := vsv.validateErrorPageRedirect(&epr, field.NewPath("redirect"))
		if len(allErrs) == 0 {
			t.Errorf("validateErrorPageRedirect(%v) returned no errors for invalid input", epr)
		}
	}
}

func TestValidateErrorPageHeader(t *testing.T) {
	t.Parallel()
	tests := []v1.Header{
		{
			Name:  "Header-Name",
			Value: "",
		},
		{
			Name:  "Header-Name",
			Value: "Value",
		},
		{
			Name:  "Header-Name",
			Value: "${upstream_status}",
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateErrorPageHeader(test, field.NewPath("header"))
		if len(allErrs) != 0 {
			t.Errorf("validateErrorPageHeader(%v) returned errors for valid input", test)
		}
	}
}

func TestValidateErrorPageHeaderFails(t *testing.T) {
	t.Parallel()
	tests := []v1.Header{
		{
			Name:  "",
			Value: "",
		},
		{
			Name:  "Header-!!#Name",
			Value: "",
		},
		{
			Name:  "Header-Name",
			Value: "$novar",
		},
		{
			Name:  "Header-Name",
			Value: "${invalid_var}",
		},
		{
			Name:  "Header-Name",
			Value: `unescaped "`,
		},
	}

	vsv := &VirtualServerValidator{isPlus: false}

	for _, test := range tests {
		allErrs := vsv.validateErrorPageHeader(test, field.NewPath("header"))
		if len(allErrs) == 0 {
			t.Errorf("validateErrorPageHeader(%v) returned no errors for invalid input", test)
		}
	}
}

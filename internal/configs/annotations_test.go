package configs

import (
	"context"
	"reflect"
	"sort"
	"testing"

	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseRewrites(t *testing.T) {
	t.Parallel()
	serviceName := "coffee-svc"
	serviceNamePart := "serviceName=" + serviceName
	rewritePath := "/beans/"
	rewritePathPart := "rewrite=" + rewritePath
	rewriteService := serviceNamePart + " " + rewritePathPart

	serviceNameActual, rewritePathActual, err := parseRewrites(rewriteService)
	if serviceName != serviceNameActual || rewritePath != rewritePathActual || err != nil {
		t.Errorf("parseRewrites(%s) should return %q, %q, nil; got %q, %q, %v", rewriteService, serviceName, rewritePath, serviceNameActual, rewritePathActual, err)
	}
}

func TestParseRewritesWithLeadingAndTrailingWhitespace(t *testing.T) {
	t.Parallel()
	serviceName := "coffee-svc"
	serviceNamePart := "serviceName=" + serviceName
	rewritePath := "/beans/"
	rewritePathPart := "rewrite=" + rewritePath
	rewriteService := "\t\n " + serviceNamePart + " " + rewritePathPart + " \t\n"

	serviceNameActual, rewritePathActual, err := parseRewrites(rewriteService)
	if serviceName != serviceNameActual || rewritePath != rewritePathActual || err != nil {
		t.Errorf("parseRewrites(%s) should return %q, %q, nil; got %q, %q, %v", rewriteService, serviceName, rewritePath, serviceNameActual, rewritePathActual, err)
	}
}

func TestParseRewritesInvalidFormat(t *testing.T) {
	t.Parallel()
	rewriteService := "serviceNamecoffee-svc rewrite=/"

	_, _, err := parseRewrites(rewriteService)
	if err == nil {
		t.Errorf("parseRewrites(%s) should return error, got nil", rewriteService)
	}
}

func TestParseStickyService(t *testing.T) {
	t.Parallel()
	serviceName := "coffee-svc"
	serviceNamePart := "serviceName=" + serviceName
	stickyCookie := "srv_id expires=1h domain=.example.com path=/"
	stickyService := serviceNamePart + " " + stickyCookie

	serviceNameActual, stickyCookieActual, err := parseStickyService(stickyService)
	if serviceName != serviceNameActual || stickyCookie != stickyCookieActual || err != nil {
		t.Errorf("parseStickyService(%s) should return %q, %q, nil; got %q, %q, %v", stickyService, serviceName, stickyCookie, serviceNameActual, stickyCookieActual, err)
	}
}

func TestParseStickyServiceInvalidFormat(t *testing.T) {
	t.Parallel()
	stickyService := "serviceNamecoffee-svc srv_id expires=1h domain=.example.com path=/"

	_, _, err := parseStickyService(stickyService)
	if err == nil {
		t.Errorf("parseStickyService(%s) should return error, got nil", stickyService)
	}
}

func TestFilterMasterAnnotations(t *testing.T) {
	t.Parallel()
	masterAnnotations := map[string]string{
		"nginx.org/rewrites":                "serviceName=service1 rewrite=rewrite1",
		"nginx.org/ssl-services":            "service1",
		"nginx.org/hsts":                    "True",
		"nginx.org/hsts-max-age":            "2700000",
		"nginx.org/hsts-include-subdomains": "True",
	}
	removedAnnotations := filterMasterAnnotations(masterAnnotations)

	expectedfilteredMasterAnnotations := map[string]string{
		"nginx.org/hsts":                    "True",
		"nginx.org/hsts-max-age":            "2700000",
		"nginx.org/hsts-include-subdomains": "True",
	}
	expectedRemovedAnnotations := []string{
		"nginx.org/rewrites",
		"nginx.org/ssl-services",
	}

	sort.Strings(removedAnnotations)
	sort.Strings(expectedRemovedAnnotations)

	if !reflect.DeepEqual(expectedfilteredMasterAnnotations, masterAnnotations) {
		t.Errorf("filterMasterAnnotations returned %v, but expected %v", masterAnnotations, expectedfilteredMasterAnnotations)
	}
	if !reflect.DeepEqual(expectedRemovedAnnotations, removedAnnotations) {
		t.Errorf("filterMasterAnnotations returned %v, but expected %v", removedAnnotations, expectedRemovedAnnotations)
	}
}

func TestFilterMinionAnnotations(t *testing.T) {
	t.Parallel()
	minionAnnotations := map[string]string{
		"nginx.org/rewrites":                "serviceName=service1 rewrite=rewrite1",
		"nginx.org/ssl-services":            "service1",
		"nginx.org/hsts":                    "True",
		"nginx.org/hsts-max-age":            "2700000",
		"nginx.org/hsts-include-subdomains": "True",
	}
	removedAnnotations := filterMinionAnnotations(minionAnnotations)

	expectedfilteredMinionAnnotations := map[string]string{
		"nginx.org/rewrites":     "serviceName=service1 rewrite=rewrite1",
		"nginx.org/ssl-services": "service1",
	}
	expectedRemovedAnnotations := []string{
		"nginx.org/hsts",
		"nginx.org/hsts-max-age",
		"nginx.org/hsts-include-subdomains",
	}

	sort.Strings(removedAnnotations)
	sort.Strings(expectedRemovedAnnotations)

	if !reflect.DeepEqual(expectedfilteredMinionAnnotations, minionAnnotations) {
		t.Errorf("filterMinionAnnotations returned %v, but expected %v", minionAnnotations, expectedfilteredMinionAnnotations)
	}
	if !reflect.DeepEqual(expectedRemovedAnnotations, removedAnnotations) {
		t.Errorf("filterMinionAnnotations returned %v, but expected %v", removedAnnotations, expectedRemovedAnnotations)
	}
}

func TestMergeMasterAnnotationsIntoMinion(t *testing.T) {
	t.Parallel()
	masterAnnotations := map[string]string{
		"nginx.org/proxy-buffering":       "True",
		"nginx.org/proxy-buffers":         "2",
		"nginx.org/proxy-buffer-size":     "8k",
		"nginx.org/hsts":                  "True",
		"nginx.org/hsts-max-age":          "2700000",
		"nginx.org/proxy-connect-timeout": "50s",
		"nginx.com/jwt-token":             "$cookie_auth_token",
	}
	minionAnnotations := map[string]string{
		"nginx.org/client-max-body-size":  "2m",
		"nginx.org/proxy-connect-timeout": "20s",
	}
	mergeMasterAnnotationsIntoMinion(minionAnnotations, masterAnnotations)

	expectedMergedAnnotations := map[string]string{
		"nginx.org/proxy-buffering":       "True",
		"nginx.org/proxy-buffers":         "2",
		"nginx.org/proxy-buffer-size":     "8k",
		"nginx.org/client-max-body-size":  "2m",
		"nginx.org/proxy-connect-timeout": "20s",
	}
	if !reflect.DeepEqual(expectedMergedAnnotations, minionAnnotations) {
		t.Errorf("mergeMasterAnnotationsIntoMinion returned %v, but expected %v", minionAnnotations, expectedMergedAnnotations)
	}
}

func TestParseRateLimitAnnotations(t *testing.T) {
	ctx := &networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "context",
		},
	}

	if errors := parseRateLimitAnnotations(map[string]string{
		"nginx.org/limit-req-rate":        "200r/s",
		"nginx.org/limit-req-key":         "${request_uri}",
		"nginx.org/limit-req-burst":       "100",
		"nginx.org/limit-req-delay":       "80",
		"nginx.org/limit-req-no-delay":    "true",
		"nginx.org/limit-req-reject-code": "429",
		"nginx.org/limit-req-zone-size":   "11m",
		"nginx.org/limit-req-dry-run":     "true",
		"nginx.org/limit-req-log-level":   "info",
	}, NewDefaultConfigParams(context.Background(), false), ctx); len(errors) > 0 {
		t.Error("Errors when parsing valid limit-req annotations")
	}

	if errors := parseRateLimitAnnotations(map[string]string{
		"nginx.org/limit-req-rate": "200",
	}, NewDefaultConfigParams(context.Background(), false), ctx); len(errors) == 0 {
		t.Error("No Errors when parsing invalid request rate")
	}

	if errors := parseRateLimitAnnotations(map[string]string{
		"nginx.org/limit-req-rate": "200r/h",
	}, NewDefaultConfigParams(context.Background(), false), ctx); len(errors) == 0 {
		t.Error("No Errors when parsing invalid request rate")
	}

	if errors := parseRateLimitAnnotations(map[string]string{
		"nginx.org/limit-req-rate": "0r/s",
	}, NewDefaultConfigParams(context.Background(), false), ctx); len(errors) == 0 {
		t.Error("No Errors when parsing invalid request rate")
	}

	if errors := parseRateLimitAnnotations(map[string]string{
		"nginx.org/limit-req-zone-size": "10abc",
	}, NewDefaultConfigParams(context.Background(), false), ctx); len(errors) == 0 {
		t.Error("No Errors when parsing invalid zone size")
	}

	if errors := parseRateLimitAnnotations(map[string]string{
		"nginx.org/limit-req-log-level": "foobar",
	}, NewDefaultConfigParams(context.Background(), false), ctx); len(errors) == 0 {
		t.Error("No Errors when parsing invalid log level")
	}
}

func BenchmarkParseRewrites(b *testing.B) {
	serviceName := "coffee-svc"
	serviceNamePart := "serviceName=" + serviceName
	rewritePath := "/beans/"
	rewritePathPart := "rewrite=" + rewritePath
	rewriteService := serviceNamePart + " " + rewritePathPart

	b.ResetTimer()
	for range b.N {
		_, _, err := parseRewrites(rewriteService)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseRewritesWithLeadingAndTrailingWhitespace(b *testing.B) {
	serviceName := "coffee-svc"
	serviceNamePart := "serviceName=" + serviceName
	rewritePath := "/beans/"
	rewritePathPart := "rewrite=" + rewritePath
	rewriteService := "\t\n " + serviceNamePart + " " + rewritePathPart + " \t\n"

	b.ResetTimer()
	for range b.N {
		_, _, err := parseRewrites(rewriteService)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseStickyService(b *testing.B) {
	serviceName := "coffee-svc"
	serviceNamePart := "serviceName=" + serviceName
	stickyCookie := "srv_id expires=1h domain=.example.com path=/"
	stickyService := serviceNamePart + " " + stickyCookie

	b.ResetTimer()
	for range b.N {
		_, _, err := parseStickyService(stickyService)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFilterMasterAnnotations(b *testing.B) {
	masterAnnotations := map[string]string{
		"nginx.org/rewrites":                "serviceName=service1 rewrite=rewrite1",
		"nginx.org/ssl-services":            "service1",
		"nginx.org/hsts":                    "True",
		"nginx.org/hsts-max-age":            "2700000",
		"nginx.org/hsts-include-subdomains": "True",
	}
	b.ResetTimer()
	for range b.N {
		filterMasterAnnotations(masterAnnotations)
	}
}

func BenchmarkFilterMinionAnnotations(b *testing.B) {
	minionAnnotations := map[string]string{
		"nginx.org/rewrites":                "serviceName=service1 rewrite=rewrite1",
		"nginx.org/ssl-services":            "service1",
		"nginx.org/hsts":                    "True",
		"nginx.org/hsts-max-age":            "2700000",
		"nginx.org/hsts-include-subdomains": "True",
	}
	b.ResetTimer()
	for range b.N {
		filterMinionAnnotations(minionAnnotations)
	}
}

func BenchmarkMergeMasterAnnotationsIntoMinion(b *testing.B) {
	masterAnnotations := map[string]string{
		"nginx.org/proxy-buffering":       "True",
		"nginx.org/proxy-buffers":         "2",
		"nginx.org/proxy-buffer-size":     "8k",
		"nginx.org/hsts":                  "True",
		"nginx.org/hsts-max-age":          "2700000",
		"nginx.org/proxy-connect-timeout": "50s",
		"nginx.com/jwt-token":             "$cookie_auth_token",
	}
	minionAnnotations := map[string]string{
		"nginx.org/client-max-body-size":  "2m",
		"nginx.org/proxy-connect-timeout": "20s",
	}
	b.ResetTimer()
	for range b.N {
		mergeMasterAnnotationsIntoMinion(minionAnnotations, masterAnnotations)
	}
}

// TestSSLCipherAnnotationParsing tests the parsing of SSL cipher annotations
func TestSSLCipherAnnotationParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		annotations map[string]string
		expected    ConfigParams
	}{
		{
			name: "SSL ciphers annotation only",
			annotations: map[string]string{
				"nginx.org/ssl-ciphers": "HIGH:!aNULL:!MD5",
			},
			expected: ConfigParams{
				ServerSSLCiphers:             "HIGH:!aNULL:!MD5",
				ServerSSLPreferServerCiphers: false,
			},
		},
		{
			name: "SSL prefer server ciphers annotation only - true",
			annotations: map[string]string{
				"nginx.org/ssl-prefer-server-ciphers": "true",
			},
			expected: ConfigParams{
				ServerSSLCiphers:             "",
				ServerSSLPreferServerCiphers: true,
			},
		},
		{
			name: "SSL prefer server ciphers annotation only - True",
			annotations: map[string]string{
				"nginx.org/ssl-prefer-server-ciphers": "True",
			},
			expected: ConfigParams{
				ServerSSLCiphers:             "",
				ServerSSLPreferServerCiphers: true,
			},
		},
		{
			name: "SSL prefer server ciphers annotation only - false",
			annotations: map[string]string{
				"nginx.org/ssl-prefer-server-ciphers": "false",
			},
			expected: ConfigParams{
				ServerSSLCiphers:             "",
				ServerSSLPreferServerCiphers: false,
			},
		},
		{
			name: "Both SSL cipher annotations",
			annotations: map[string]string{
				"nginx.org/ssl-ciphers":               "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
				"nginx.org/ssl-prefer-server-ciphers": "true",
			},
			expected: ConfigParams{
				ServerSSLCiphers:             "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
				ServerSSLPreferServerCiphers: true,
			},
		},
		{
			name: "Empty SSL ciphers annotation",
			annotations: map[string]string{
				"nginx.org/ssl-ciphers": "",
			},
			expected: ConfigParams{
				ServerSSLCiphers:             "",
				ServerSSLPreferServerCiphers: false,
			},
		},
		{
			name: "No SSL cipher annotations",
			annotations: map[string]string{
				"nginx.org/proxy-connect-timeout": "30s",
			},
			expected: ConfigParams{
				ServerSSLCiphers:             "",
				ServerSSLPreferServerCiphers: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingress := &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-ingress",
					Namespace:   "default",
					Annotations: tt.annotations,
				},
			}

			ingEx := &IngressEx{
				Ingress: ingress,
			}

			baseCfgParams := NewDefaultConfigParams(context.Background(), false)
			result := parseAnnotations(ingEx, baseCfgParams, false, false, false, false, false)

			if result.ServerSSLCiphers != tt.expected.ServerSSLCiphers {
				t.Errorf("Expected ServerSSLCiphers %q, got %q", tt.expected.ServerSSLCiphers, result.ServerSSLCiphers)
			}

			if result.ServerSSLPreferServerCiphers != tt.expected.ServerSSLPreferServerCiphers {
				t.Errorf("Expected ServerSSLPreferServerCiphers %v, got %v", tt.expected.ServerSSLPreferServerCiphers, result.ServerSSLPreferServerCiphers)
			}
		})
	}
}

// TestSSLCipherAnnotationFiltering tests that SSL cipher annotations are filtered correctly for minions
func TestSSLCipherAnnotationFiltering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		annotations         map[string]string
		filterFunc          func(map[string]string) []string
		expectedRemoved     []string
		expectedAnnotations map[string]string
	}{
		{
			name: "SSL cipher annotations removed from minions",
			annotations: map[string]string{
				"nginx.org/ssl-ciphers":               "HIGH:!aNULL:!MD5",
				"nginx.org/ssl-prefer-server-ciphers": "true",
				"nginx.org/proxy-connect-timeout":     "30s",
				"nginx.org/server-snippets":           "add_header X-Frame-Options SAMEORIGIN;",
			},
			filterFunc: filterMinionAnnotations,
			expectedRemoved: []string{
				"nginx.org/ssl-ciphers",
				"nginx.org/ssl-prefer-server-ciphers",
				"nginx.org/server-snippets",
			},
			expectedAnnotations: map[string]string{
				"nginx.org/proxy-connect-timeout": "30s",
			},
		},
		{
			name: "SSL cipher annotations allowed in masters",
			annotations: map[string]string{
				"nginx.org/ssl-ciphers":               "HIGH:!aNULL:!MD5",
				"nginx.org/ssl-prefer-server-ciphers": "true",
				"nginx.org/rewrites":                  "serviceName=test rewrite=/",
				"nginx.org/proxy-connect-timeout":     "30s",
			},
			filterFunc: filterMasterAnnotations,
			expectedRemoved: []string{
				"nginx.org/rewrites",
			},
			expectedAnnotations: map[string]string{
				"nginx.org/ssl-ciphers":               "HIGH:!aNULL:!MD5",
				"nginx.org/ssl-prefer-server-ciphers": "true",
				"nginx.org/proxy-connect-timeout":     "30s",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy of annotations to avoid modifying the test data
			annotations := make(map[string]string)
			for k, v := range tt.annotations {
				annotations[k] = v
			}

			removedAnnotations := tt.filterFunc(annotations)

			// Sort slices for comparison
			sort.Strings(removedAnnotations)
			sort.Strings(tt.expectedRemoved)

			if !reflect.DeepEqual(removedAnnotations, tt.expectedRemoved) {
				t.Errorf("Expected removed annotations %v, got %v", tt.expectedRemoved, removedAnnotations)
			}

			if !reflect.DeepEqual(annotations, tt.expectedAnnotations) {
				t.Errorf("Expected remaining annotations %v, got %v", tt.expectedAnnotations, annotations)
			}
		})
	}
}

// TestSSLCipherAnnotationBooleanValues tests both valid and invalid boolean values for ssl-prefer-server-ciphers
func TestSSLCipherAnnotationBooleanValues(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		value    string
		expected bool
		isValid  bool
	}{
		// Valid boolean values
		{"true", true, true},
		{"TRUE", true, true},
		{"True", true, true},
		{"1", true, true},
		{"false", false, true},
		{"FALSE", false, true},
		{"False", false, true},
		{"0", false, true},
		// Invalid boolean values (should default to false)
		{"invalid", false, false},
		{"yes", false, false},
		{"no", false, false},
		{"2", false, false},
		{"", false, false},
		{"maybe", false, false},
		{"on", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.value, func(t *testing.T) {
			ingress := &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"nginx.org/ssl-prefer-server-ciphers": tc.value,
					},
				},
			}

			ingEx := &IngressEx{
				Ingress: ingress,
			}

			baseCfgParams := NewDefaultConfigParams(context.Background(), false)
			result := parseAnnotations(ingEx, baseCfgParams, false, false, false, false, false)

			if result.ServerSSLPreferServerCiphers != tc.expected {
				validityMsg := "valid"
				if !tc.isValid {
					validityMsg = "invalid"
				}
				t.Errorf("Expected ServerSSLPreferServerCiphers to be %v for %s value %q, got %v", tc.expected, validityMsg, tc.value, result.ServerSSLPreferServerCiphers)
			}
		})
	}
}

func TestGetRewriteTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		annotations         map[string]string
		expectedValue       string
		expectedWarningMsgs []string
		description         string
	}{
		{
			name: "rewrite-target only",
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/api/v1/$1",
			},
			expectedValue:       "/api/v1/$1",
			expectedWarningMsgs: nil,
			description:         "Should return rewrite-target value when only rewrite-target annotation is present",
		},
		{
			name: "rewrites only",
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=app-svc rewrite=/backend/",
			},
			expectedValue:       "",
			expectedWarningMsgs: nil,
			description:         "Should return empty string when only rewrites annotation is present",
		},
		{
			name: "both annotations present - mutual exclusivity",
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/api/v1/$1",
				"nginx.org/rewrites":       "serviceName=app-svc rewrite=/backend/",
			},
			expectedValue:       "",
			expectedWarningMsgs: []string{"nginx.org/rewrites and nginx.org/rewrite-target annotations are mutually exclusive; nginx.org/rewrites will take precedence"},
			description:         "Should return empty string and warning when both annotations are present (rewrites takes precedence)",
		},
		{
			name:                "no rewrite annotations",
			annotations:         map[string]string{},
			expectedValue:       "",
			expectedWarningMsgs: nil,
			description:         "Should return empty string when no rewrite annotations are present",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test Ingress
			ingress := &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-ingress",
					Namespace:   "default",
					Annotations: tt.annotations,
				},
			}

			ingEx := &IngressEx{
				Ingress: ingress,
			}

			// Call getRewriteTarget
			ctx := context.Background()
			value, warnings := getRewriteTarget(ctx, ingEx)

			// Verify return value
			if value != tt.expectedValue {
				t.Errorf("Test %q: expected value %q, got %q. %s", tt.name, tt.expectedValue, value, tt.description)
			}

			// Verify warnings
			if len(tt.expectedWarningMsgs) == 0 {
				if len(warnings) != 0 {
					t.Errorf("Test %q: expected no warnings, got %d warnings. %s", tt.name, len(warnings), tt.description)
				}
			} else {
				// Check that warnings contain our Ingress
				ingressWarnings, exists := warnings[ingress]
				if !exists {
					t.Errorf("Test %q: expected warnings for ingress, but found none. %s", tt.name, tt.description)
					return
				}

				// Check warning count
				if len(ingressWarnings) != len(tt.expectedWarningMsgs) {
					t.Errorf("Test %q: expected %d warnings, got %d. %s", tt.name, len(tt.expectedWarningMsgs), len(ingressWarnings), tt.description)
				}

				// Check warning messages
				for i, expectedMsg := range tt.expectedWarningMsgs {
					if i < len(ingressWarnings) {
						if ingressWarnings[i] != expectedMsg {
							t.Errorf("Test %q: expected warning message %q, got %q. %s", tt.name, expectedMsg, ingressWarnings[i], tt.description)
						}
					}
				}
			}
		})
	}
}

func TestGetRewriteTargetMutualExclusivity(t *testing.T) {
	t.Parallel()

	// Test that when both annotations exist, rewrites takes precedence
	ingress := &networking.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
			Annotations: map[string]string{
				"nginx.org/rewrite-target": "/should/not/be/used/$1",
				"nginx.org/rewrites":       "serviceName=coffee-svc rewrite=/coffee/beans/",
			},
		},
	}

	ingEx := &IngressEx{
		Ingress: ingress,
	}

	ctx := context.Background()
	value, warnings := getRewriteTarget(ctx, ingEx)

	// Should return empty string (rewrite-target disabled)
	if value != "" {
		t.Errorf("Expected empty string when both annotations present, got %q", value)
	}

	// Should have warning about mutual exclusivity
	ingressWarnings, exists := warnings[ingress]
	if !exists || len(ingressWarnings) == 0 {
		t.Error("Expected warning about mutual exclusivity")
	}

	expectedWarning := "nginx.org/rewrites and nginx.org/rewrite-target annotations are mutually exclusive; nginx.org/rewrites will take precedence"
	if len(ingressWarnings) > 0 && ingressWarnings[0] != expectedWarning {
		t.Errorf("Expected warning message %q, got %q", expectedWarning, ingressWarnings[0])
	}
}

func TestGetRewriteTargetWithComplexValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		rewriteTarget string
		expected      string
	}{
		{
			name:          "simple path replacement",
			rewriteTarget: "/api/$1",
			expected:      "/api/$1",
		},
		{
			name:          "multiple capture groups",
			rewriteTarget: "/api/$1/$2/data",
			expected:      "/api/$1/$2/data",
		},
		{
			name:          "static path",
			rewriteTarget: "/static/path",
			expected:      "/static/path",
		},
		{
			name:          "path with query parameters",
			rewriteTarget: "/api/$1?version=v2",
			expected:      "/api/$1?version=v2",
		},
		{
			name:          "complex pattern",
			rewriteTarget: "/v1/services/$1/endpoints/$2",
			expected:      "/v1/services/$1/endpoints/$2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingress := &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"nginx.org/rewrite-target": tt.rewriteTarget,
					},
				},
			}

			ingEx := &IngressEx{
				Ingress: ingress,
			}

			ctx := context.Background()
			value, _ := getRewriteTarget(ctx, ingEx)

			if value != tt.expected {
				t.Errorf("Test %q: expected %q, got %q", tt.name, tt.expected, value)
			}
		})
	}
}

func TestClientBodyBufferSizeAnnotationValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		clientBodyBufferSize string
		expected             string
	}{
		{
			name:                 "valid size with k",
			clientBodyBufferSize: "16k",
			expected:             "16k",
		},
		{
			name:                 "valid size with M",
			clientBodyBufferSize: "4M",
			expected:             "4M",
		},
		{
			name:                 "valid size without suffix",
			clientBodyBufferSize: "8192",
			expected:             "8192",
		},
		{
			name:                 "single digit",
			clientBodyBufferSize: "1k",
			expected:             "1k",
		},
		{
			name:                 "zero value",
			clientBodyBufferSize: "0",
			expected:             "0",
		},
		{
			name:                 "large buffer size",
			clientBodyBufferSize: "512K",
			expected:             "512K",
		},
		{
			name:                 "megabyte buffer size",
			clientBodyBufferSize: "64M",
			expected:             "64M",
		},
		{
			name:                 "empty annotation",
			clientBodyBufferSize: "",
			expected:             "",
		},
		{
			name:                 "very large number",
			clientBodyBufferSize: "999999999",
			expected:             "999999999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ingress := &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"nginx.org/client-body-buffer-size": tt.clientBodyBufferSize,
					},
				},
			}

			ingEx := &IngressEx{
				Ingress: ingress,
			}

			baseCfgParams := NewDefaultConfigParams(context.Background(), false)
			result := parseAnnotations(ingEx, baseCfgParams, false, false, false, false, false)

			if result.ClientBodyBufferSize != tt.expected {
				t.Errorf("Test %q: expected ClientBodyBufferSize %q, got %q", tt.name, tt.expected, result.ClientBodyBufferSize)
			}

			result2 := parseAnnotations(ingEx, baseCfgParams, false, false, false, false, false)
			if result2.ClientBodyBufferSize != tt.expected {
				t.Errorf("Test %q with other annotations: expected ClientBodyBufferSize %q, got %q", tt.name, tt.expected, result2.ClientBodyBufferSize)
			}
		})
	}
}

func TestClientBodyBufferSizeAnnotationInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		annotations map[string]string
	}{
		{
			name: "annotation name case sensitivity",
			annotations: map[string]string{
				"nginx.org/Client-Body-Buffer-Size": "16k", // capital letters
			},
		},
		{
			name: "invalid time unit h",
			annotations: map[string]string{
				"nginx.org/client-body-buffer-size": "4h",
			},
		},
		{
			name: "invalid random string",
			annotations: map[string]string{
				"nginx.org/client-body-buffer-size": "3cd2", // wrong format, too many chars
			},
		},
		{
			name: "invalid with g suffix",
			annotations: map[string]string{
				"nginx.org/client-body-buffer-size": "2g",
			},
		},

		{
			name: "invalid negative value",
			annotations: map[string]string{
				"nginx.org/client-body-buffer-size": "-16k",
			},
		},
		{
			name: "invalid with text prefix",
			annotations: map[string]string{
				"nginx.org/client-body-buffer-size": "abc16k",
			},
		},
		{
			name: "invalid with special characters",
			annotations: map[string]string{
				"nginx.org/client-body-buffer-size": "16@k",
			},
		},
		{
			name: "invalid with letters",
			annotations: map[string]string{
				"nginx.org/client-body-buffer-size": "abcdef",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ingress := &networking.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-ingress",
					Namespace:   "default",
					Annotations: tt.annotations,
				},
			}

			ingEx := &IngressEx{
				Ingress: ingress,
			}

			baseCfgParams := NewDefaultConfigParams(context.Background(), false)
			result := parseAnnotations(ingEx, baseCfgParams, false, false, false, false, false)

			if result.ClientBodyBufferSize != "" {
				t.Errorf(`Test %q: expected ClientBodyBufferSize %q, got ""`, tt.name, result.ClientBodyBufferSize)
			}
		})
	}
}

func TestSSLRedirectAnnotations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		annotations map[string]string
		expected    bool
	}{
		{
			name: "nginx.org/ssl-redirect enabled",
			annotations: map[string]string{
				"nginx.org/ssl-redirect": "true",
			},
			expected: true,
		},
		{
			name: "nginx.org/ssl-redirect disabled",
			annotations: map[string]string{
				"nginx.org/ssl-redirect": "false",
			},
			expected: false,
		},
		{
			name: "deprecated ingress.kubernetes.io/ssl-redirect enabled",
			annotations: map[string]string{
				"ingress.kubernetes.io/ssl-redirect": "true",
			},
			expected: true,
		},
		{
			name: "deprecated ingress.kubernetes.io/ssl-redirect disabled",
			annotations: map[string]string{
				"ingress.kubernetes.io/ssl-redirect": "false",
			},
			expected: false,
		},
		{
			name: "nginx.org/ssl-redirect takes precedence when both present",
			annotations: map[string]string{
				"nginx.org/ssl-redirect":             "false",
				"ingress.kubernetes.io/ssl-redirect": "true",
			},
			expected: false,
		},
		{
			name: "nginx.org/ssl-redirect enabled takes precedence",
			annotations: map[string]string{
				"nginx.org/ssl-redirect":             "true",
				"ingress.kubernetes.io/ssl-redirect": "false",
			},
			expected: true,
		},
		{
			name:        "no ssl-redirect annotations",
			annotations: map[string]string{},
			expected:    true, // Default is true
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ingEx := &IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "test-ingress",
						Namespace:   "default",
						Annotations: tt.annotations,
					},
				},
			}

			baseCfgParams := NewDefaultConfigParams(context.Background(), false)
			result := parseAnnotations(ingEx, baseCfgParams, false, false, false, false, false)

			if result.SSLRedirect != tt.expected {
				t.Errorf("Test %q: expected SSLRedirect %t, got %t", tt.name, tt.expected, result.SSLRedirect)
			}
		})
	}
}

func TestHTTPRedirectCodeAnnotationBehavior(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		annotations  map[string]string
		expectedCode int
	}{
		{
			name: "redirect code applied when SSL redirect enabled",
			annotations: map[string]string{
				"nginx.org/ssl-redirect":       "true",
				"nginx.org/http-redirect-code": "307",
			},
			expectedCode: 307,
		},
		{
			name: "redirect code applied when SSL redirect disabled",
			annotations: map[string]string{
				"nginx.org/ssl-redirect":       "false",
				"nginx.org/http-redirect-code": "307",
			},
			expectedCode: 307,
		},
		{
			name: "redirect code applied with redirect-to-https",
			annotations: map[string]string{
				"nginx.org/redirect-to-https":  "true",
				"nginx.org/http-redirect-code": "302",
			},
			expectedCode: 302,
		},
		{
			name: "redirect code applied without any redirect settings",
			annotations: map[string]string{
				"nginx.org/http-redirect-code": "308",
			},
			expectedCode: 308,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingEx := &IngressEx{
				Ingress: &networking.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "test-ingress",
						Namespace:   "default",
						Annotations: tt.annotations,
					},
				},
			}

			baseCfgParams := NewDefaultConfigParams(context.Background(), false)
			result := parseAnnotations(ingEx, baseCfgParams, false, false, false, false, false)

			if result.HTTPRedirectCode != tt.expectedCode {
				t.Errorf("Test %q: expected HTTPRedirectCode %d, got %d", tt.name, tt.expectedCode, result.HTTPRedirectCode)
			}
		})
	}
}

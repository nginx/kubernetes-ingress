package k8s

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateIngress_WithValidPathRegexValuesForNGINXPlus(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name    string
		ingress *networking.Ingress
		isPlus  bool
	}{
		{
			name: "case sensitive path regex",
			ingress: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/path-regex": "case_sensitive",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus: true,
		},
		{
			name: "case insensitive path regex",
			ingress: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/path-regex": "case_insensitive",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus: true,
		},
		{
			name: "exact path regex",
			ingress: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/path-regex": "exact",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus: true,
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allErrs := validateIngress(tc.ingress, tc.isPlus, false, false, false, false)
			if len(allErrs) != 0 {
				t.Errorf("want no errors, got %+v\n", allErrs)
			}
		})
	}
}

func TestValidateIngress_WithValidPathRegexValuesForNGINX(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name    string
		ingress *networking.Ingress
		isPlus  bool
	}{
		{
			name: "case sensitive path regex",
			ingress: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/path-regex": "case_sensitive",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "case insensitive path regex",
			ingress: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/path-regex": "case_insensitive",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "exact path regex",
			ingress: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/path-regex": "exact",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus: false,
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allErrs := validateIngress(tc.ingress, tc.isPlus, false, false, false, false)
			if len(allErrs) != 0 {
				t.Errorf("want no errors, got %+v\n", allErrs)
			}
		})
	}
}

func TestValidateIngress_WithInvalidPathRegexValuesForNGINXPlus(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name    string
		ingress *networking.Ingress
		isPlus  bool
	}{
		{
			name: "bogus not empty path regex string",
			ingress: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/path-regex": "bogus",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus: true,
		},
		{
			name: "bogus empty path regex string",
			ingress: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/path-regex": "",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus: true,
		},
	}
	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allErrs := validateIngress(tc.ingress, tc.isPlus, false, false, false, false)
			if len(allErrs) == 0 {
				t.Error("want errors on invalid path regex values")
			}
			t.Log(allErrs)
		})
	}
}

func TestValidateIngress_WithInvalidPathRegexValuesForNGINX(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name    string
		ingress *networking.Ingress
		isPlus  bool
	}{
		{
			name: "bogus not empty path regex string",
			ingress: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/path-regex": "bogus",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "bogus empty path regex string",
			ingress: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/path-regex": "",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus: false,
		},
	}
	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allErrs := validateIngress(tc.ingress, tc.isPlus, false, false, false, false)
			if len(allErrs) == 0 {
				t.Error("want errors on invalid path regex values")
			}
			t.Log(allErrs)
		})
	}
}

func TestValidateIngress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ing                   *networking.Ingress
		isPlus                bool
		appProtectEnabled     bool
		appProtectDosEnabled  bool
		internalRoutesEnabled bool
		expectedErrors        []string
		msg                   string
	}{
		{
			ing: &networking.Ingress{
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid input",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/mergeable-ingress-type": "invalid",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "",
						},
					},
				},
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/mergeable-ingress-type: Invalid value: "invalid": must be one of: 'master' or 'minion'`,
				"spec.rules[0].host: Required value",
			},
			msg: "invalid ingress",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/mergeable-ingress-type": "master",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networking.IngressRuleValue{
								HTTP: &networking.HTTPIngressRuleValue{
									Paths: []networking.HTTPIngressPath{
										{
											Path: "/",
										},
									},
								},
							},
						},
					},
				},
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"spec.rules[0].http.paths: Too many: 1: must have at most 0 items",
			},
			msg: "invalid master",
		},
		{
			ing: &networking.Ingress{
				ObjectMeta: meta_v1.ObjectMeta{
					Annotations: map[string]string{
						"nginx.org/mergeable-ingress-type": "minion",
					},
				},
				Spec: networking.IngressSpec{
					Rules: []networking.IngressRule{
						{
							Host:             "example.com",
							IngressRuleValue: networking.IngressRuleValue{},
						},
					},
				},
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"spec.rules[0].http.paths: Required value: must include at least one path",
			},
			msg: "invalid minion",
		},
	}

	for _, test := range tests {
		allErrs := validateIngress(test.ing, test.isPlus, test.appProtectEnabled, test.appProtectDosEnabled, test.internalRoutesEnabled, false)
		assertion := assertErrors("validateIngress()", test.msg, allErrs, test.expectedErrors)
		if assertion != "" {
			t.Error(assertion)
		}
	}
}

func TestValidateNginxIngressAnnotations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		annotations           map[string]string
		specServices          map[string]bool
		isPlus                bool
		appProtectEnabled     bool
		appProtectDosEnabled  bool
		internalRoutesEnabled bool
		snippetsEnabled       bool
		expectedErrors        []string
		msg                   string
	}{
		{
			annotations:           map[string]string{},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid no annotations",
		},

		{
			annotations: map[string]string{
				"nginx.org/lb-method":              "invalid_method",
				"nginx.org/mergeable-ingress-type": "invalid",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/lb-method: Invalid value: "invalid_method": invalid load balancing method: "invalid_method"`,
				`annotations.nginx.org/mergeable-ingress-type: Invalid value: "invalid": must be one of: 'master' or 'minion'`,
			},
			msg: "invalid multiple annotations messages in alphabetical order",
		},

		{
			annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "master",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid input with master annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "minion",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid input with minion annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.org/mergeable-ingress-type: Required value",
			},
			msg: "invalid mergeable type annotation 1",
		},
		{
			annotations: map[string]string{
				"nginx.org/mergeable-ingress-type": "abc",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/mergeable-ingress-type: Invalid value: "abc": must be one of: 'master' or 'minion'`,
			},
			msg: "invalid mergeable type annotation 2",
		},

		{
			annotations: map[string]string{
				"nginx.org/lb-method": "random",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/lb-method annotation, nginx normal",
		},
		{
			annotations: map[string]string{
				"nginx.org/lb-method": "least_time header",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/lb-method: Invalid value: "least_time header": invalid load balancing method: "least_time header"`,
			},
			msg: "invalid nginx.org/lb-method annotation, nginx plus only",
		},
		{
			annotations: map[string]string{
				"nginx.org/lb-method": "least_time header;",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/lb-method: Invalid value: "least_time header;": invalid load balancing method: "least_time header;"`,
			},
			msg: "invalid nginx.org/lb-method annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/lb-method": "{least_time header}",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/lb-method: Invalid value: "{least_time header}": invalid load balancing method: "{least_time header}"`,
			},
			msg: "invalid nginx.org/lb-method annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/lb-method": "$least_time header",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/lb-method: Invalid value: "$least_time header": invalid load balancing method: "$least_time header"`,
			},
			msg: "invalid nginx.org/lb-method annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/lb-method": "invalid_method",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/lb-method: Invalid value: "invalid_method": invalid load balancing method: "invalid_method"`,
			},
			msg: "invalid nginx.org/lb-method annotation",
		},

		{
			annotations: map[string]string{
				"nginx.com/health-checks": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/health-checks: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid nginx.com/health-checks annotation, nginx plus only",
		},
		{
			annotations: map[string]string{
				"nginx.com/health-checks": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.com/health-checks annotation",
		},
		{
			annotations: map[string]string{
				"nginx.com/health-checks": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/health-checks: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nginx.com/health-checks annotation",
		},

		{
			annotations: map[string]string{
				"nginx.com/health-checks-mandatory": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/health-checks-mandatory: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid nginx.com/health-checks-mandatory annotation, nginx plus only",
		},
		{
			annotations: map[string]string{
				"nginx.com/health-checks":           "true",
				"nginx.com/health-checks-mandatory": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.com/health-checks-mandatory annotation",
		},
		{
			annotations: map[string]string{
				"nginx.com/health-checks":           "true",
				"nginx.com/health-checks-mandatory": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/health-checks-mandatory: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nginx.com/health-checks-mandatory, must be a boolean",
		},
		{
			annotations: map[string]string{
				"nginx.com/health-checks-mandatory": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/health-checks-mandatory: Forbidden: related annotation nginx.com/health-checks: must be set",
			},
			msg: "invalid nginx.com/health-checks-mandatory, related annotation nginx.com/health-checks not set",
		},
		{
			annotations: map[string]string{
				"nginx.com/health-checks":           "false",
				"nginx.com/health-checks-mandatory": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/health-checks-mandatory: Forbidden: related annotation nginx.com/health-checks: must be true",
			},
			msg: "invalid nginx.com/health-checks-mandatory nginx.com/health-checks is not true",
		},

		{
			annotations: map[string]string{
				"nginx.com/health-checks-mandatory-queue": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/health-checks-mandatory-queue: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid nginx.com/health-checks-mandatory-queue annotation, nginx plus only",
		},
		{
			annotations: map[string]string{
				"nginx.com/health-checks":                 "true",
				"nginx.com/health-checks-mandatory":       "true",
				"nginx.com/health-checks-mandatory-queue": "5",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.com/health-checks-mandatory-queue annotation",
		},
		{
			annotations: map[string]string{
				"nginx.com/health-checks":                 "true",
				"nginx.com/health-checks-mandatory":       "true",
				"nginx.com/health-checks-mandatory-queue": "not_a_number",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/health-checks-mandatory-queue: Invalid value: "not_a_number": must be a non-negative integer`,
			},
			msg: "invalid nginx.com/health-checks-mandatory-queue, must be a number",
		},
		{
			annotations: map[string]string{
				"nginx.com/health-checks-mandatory-queue": "5",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/health-checks-mandatory-queue: Forbidden: related annotation nginx.com/health-checks-mandatory: must be set",
			},
			msg: "invalid nginx.com/health-checks-mandatory-queue, related annotation nginx.com/health-checks-mandatory not set",
		},
		{
			annotations: map[string]string{
				"nginx.com/health-checks":                 "true",
				"nginx.com/health-checks-mandatory":       "false",
				"nginx.com/health-checks-mandatory-queue": "5",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/health-checks-mandatory-queue: Forbidden: related annotation nginx.com/health-checks-mandatory: must be true",
			},
			msg: "invalid nginx.com/health-checks-mandatory-queue nginx.com/health-checks-mandatory is not true",
		},

		{
			annotations: map[string]string{
				"nginx.com/slow-start": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/slow-start: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid nginx.com/slow-start annotation, nginx plus only",
		},
		{
			annotations: map[string]string{
				"nginx.com/slow-start": "60s",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.com/slow-start annotation",
		},
		{
			annotations: map[string]string{
				"nginx.com/slow-start": "not_a_time",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/slow-start: Invalid value: "not_a_time": must be a time`,
			},
			msg: "invalid nginx.com/slow-start annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/server-tokens": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/server-tokens annotation, nginx",
		},
		{
			annotations: map[string]string{
				"nginx.org/server-tokens": "custom_setting",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/server-tokens annotation, nginx plus",
		},
		{
			annotations: map[string]string{
				"nginx.org/server-tokens": "custom_setting",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/server-tokens: Invalid value: "custom_setting": must be a boolean`,
			},
			msg: "invalid nginx.org/server-tokens annotation, must be a boolean",
		},
		{
			annotations: map[string]string{
				"nginx.org/server-tokens": "$custom_setting",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/server-tokens: Invalid value: "$custom_setting": ` + annotationValueFmtErrMsg,
			},
			msg: "invalid nginx.org/server-tokens annotation, " + annotationValueFmtErrMsg,
		},
		{
			annotations: map[string]string{
				"nginx.org/server-tokens": "custom_\"setting",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/server-tokens: Invalid value: "custom_\"setting": ` + annotationValueFmtErrMsg,
			},
			msg: "invalid nginx.org/server-tokens annotation, " + annotationValueFmtErrMsg,
		},
		{
			annotations: map[string]string{
				"nginx.org/server-tokens": `custom_setting\`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/server-tokens: Invalid value: "custom_setting\\": ` + annotationValueFmtErrMsg,
			},
			msg: "invalid nginx.org/server-tokens annotation, " + annotationValueFmtErrMsg,
		},

		{
			annotations: map[string]string{
				"nginx.org/server-snippets": "snippet-1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			snippetsEnabled:       true,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/server-snippets annotation, single-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/server-snippets": "snippet-1\nsnippet-2\nsnippet-3",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			snippetsEnabled:       true,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/server-snippets annotation, multi-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/server-snippets": "snippet-1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			internalRoutesEnabled: false,
			snippetsEnabled:       false,
			expectedErrors: []string{
				`annotations.nginx.org/server-snippets: Forbidden: snippet specified but snippets feature is not enabled`,
			},
			msg: "invalid nginx.org/server-snippets annotation when snippets are disabled",
		},

		{
			annotations: map[string]string{
				"nginx.org/location-snippets": "snippet-1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			snippetsEnabled:       true,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/location-snippets annotation, single-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/location-snippets": "snippet-1\nsnippet-2\nsnippet-3",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			snippetsEnabled:       true,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/location-snippets annotation, multi-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/location-snippets": "snippet-1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			internalRoutesEnabled: false,
			snippetsEnabled:       false,
			expectedErrors: []string{
				`annotations.nginx.org/location-snippets: Forbidden: snippet specified but snippets feature is not enabled`,
			},
			msg: "invalid nginx.org/location-snippets annotation when snippets are disabled",
		},

		{
			annotations: map[string]string{
				"nginx.org/proxy-connect-timeout": "10s",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-connect-timeout annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-connect-timeout": "not_a_time",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-connect-timeout: Invalid value: "not_a_time": must be a time`,
			},
			msg: "invalid nginx.org/proxy-connect-timeout annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/proxy-read-timeout": "10s",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-read-timeout annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-read-timeout": "not_a_time",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-read-timeout: Invalid value: "not_a_time": must be a time`,
			},
			msg: "invalid nginx.org/proxy-read-timeout annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/proxy-send-timeout": "10s",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-send-timeout annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-send-timeout": "not_a_time",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-send-timeout: Invalid value: "not_a_time": must be a time`,
			},
			msg: "invalid nginx.org/proxy-send-timeout annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/proxy-hide-headers": "header-1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-hide-headers annotation, single-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-hide-headers": "header-1,header-2,header-3",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-hide-headers annotation, multi-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-hide-headers": "header-1, header-2, header-3",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-hide-headers annotation, multi-value with spaces",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-hide-headers": "$header1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-hide-headers: Invalid value: "$header1": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-hide-headers annotation, single-value containing '$'",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-hide-headers": "{header1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-hide-headers: Invalid value: "{header1": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-hide-headers annotation, single-value containing '{'",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-hide-headers": "$header1,header2",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-hide-headers: Invalid value: "$header1": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-hide-headers annotation, multi-value containing '$'",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-hide-headers": "header1,$header2",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-hide-headers: Invalid value: "$header2": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-hide-headers annotation, multi-value containing '$' after valid header",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-pass-headers": "header-1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-pass-headers annotation, single-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-pass-headers": "header-1,header-2,header-3",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-pass-headers annotation, multi-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-pass-headers": "header-1, header-2, header-3",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-pass-headers annotation, multi-value with spaces",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-pass-headers": "$header1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-pass-headers: Invalid value: "$header1": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-pass-headers annotation, single-value containing '$'",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-pass-headers": "{header1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-pass-headers: Invalid value: "{header1": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-pass-headers annotation, single-value containing '{'",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-pass-headers": "$header1,header2",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-pass-headers: Invalid value: "$header1": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-pass-headers annotation, multi-value containing '$'",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-pass-headers": "header1,$header2",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-pass-headers: Invalid value: "$header2": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-pass-headers annotation, multi-value containing '$' after valid header",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-set-headers": "header-1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-set-headers annotation, single-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-set-headers": "header-1,header-2,header-3",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-set-headers annotation, multi-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-set-headers": "header-1, header-2, header-3",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-set-headers annotation, multi-value with spaces",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-set-headers": "$header1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-set-headers: Invalid value: "$header1": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-set-headers annotation, single-value containing '$'",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-set-headers": "{header1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-set-headers: Invalid value: "{header1": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-set-headers annotation, single-value containing '{'",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-set-headers": "$header1,header2",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-set-headers: Invalid value: "$header1": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-set-headers annotation, multi-value containing '$'",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-set-headers": "header1,$header2",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-set-headers: Invalid value: "$header2": a valid HTTP header must consist of alphanumeric characters or '-' (e.g. 'X-Header-Name', regex used for validation is '[-A-Za-z0-9]+')`,
			},
			msg: "invalid nginx.org/proxy-set-headers annotation, multi-value containing '$' after valid header",
		},
		{
			annotations: map[string]string{
				"nginx.org/client-max-body-size": "16M",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/client-max-body-size annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/client-max-body-size": "not_an_offset",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/client-max-body-size: Invalid value: "not_an_offset": must be an offset`,
			},
			msg: "invalid nginx.org/client-max-body-size annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/redirect-to-https": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/redirect-to-https annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/redirect-to-https": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/redirect-to-https: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nginx.org/redirect-to-https annotation",
		},

		{
			annotations: map[string]string{
				"ingress.kubernetes.io/ssl-redirect": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid ingress.kubernetes.io/ssl-redirect annotation",
		},
		{
			annotations: map[string]string{
				"ingress.kubernetes.io/ssl-redirect": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.ingress.kubernetes.io/ssl-redirect: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid ingress.kubernetes.io/ssl-redirect annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/proxy-buffering": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-buffering annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-buffering": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-buffering: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nginx.org/proxy-buffering annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/hsts": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/hsts annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/hsts": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/hsts: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nginx.org/hsts annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/hsts":         "true",
				"nginx.org/hsts-max-age": "120",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/hsts-max-age annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/hsts":         "false",
				"nginx.org/hsts-max-age": "120",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/hsts-max-age nginx.org/hsts can be false",
		},
		{
			annotations: map[string]string{
				"nginx.org/hsts":         "true",
				"nginx.org/hsts-max-age": "not_a_number",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/hsts-max-age: Invalid value: "not_a_number": must be an integer`,
			},
			msg: "invalid nginx.org/hsts-max-age, must be a number",
		},
		{
			annotations: map[string]string{
				"nginx.org/hsts-max-age": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.org/hsts-max-age: Forbidden: related annotation nginx.org/hsts: must be set",
			},
			msg: "invalid nginx.org/hsts-max-age, related annotation nginx.org/hsts not set",
		},

		{
			annotations: map[string]string{
				"nginx.org/hsts":                    "true",
				"nginx.org/hsts-include-subdomains": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/hsts-include-subdomains annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/hsts":                    "false",
				"nginx.org/hsts-include-subdomains": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/hsts-include-subdomains, nginx.org/hsts can be false",
		},
		{
			annotations: map[string]string{
				"nginx.org/hsts":                    "true",
				"nginx.org/hsts-include-subdomains": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/hsts-include-subdomains: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nginx.org/hsts-include-subdomains, must be a boolean",
		},
		{
			annotations: map[string]string{
				"nginx.org/hsts-include-subdomains": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.org/hsts-include-subdomains: Forbidden: related annotation nginx.org/hsts: must be set",
			},
			msg: "invalid nginx.org/hsts-include-subdomains, related annotation nginx.org/hsts not set",
		},

		{
			annotations: map[string]string{
				"nginx.org/hsts":              "true",
				"nginx.org/hsts-behind-proxy": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/hsts-behind-proxy annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/hsts":              "false",
				"nginx.org/hsts-behind-proxy": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/hsts-behind-proxy, nginx.org/hsts can be false",
		},
		{
			annotations: map[string]string{
				"nginx.org/hsts":              "true",
				"nginx.org/hsts-behind-proxy": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/hsts-behind-proxy: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nginx.org/hsts-behind-proxy, must be a boolean",
		},
		{
			annotations: map[string]string{
				"nginx.org/hsts-behind-proxy": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.org/hsts-behind-proxy: Forbidden: related annotation nginx.org/hsts: must be set",
			},
			msg: "invalid nginx.org/hsts-behind-proxy, related annotation nginx.org/hsts not set",
		},

		{
			annotations: map[string]string{
				"nginx.org/proxy-buffers": "8 8k",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-buffers annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-buffers": "not_a_proxy_buffers_spec",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-buffers: Invalid value: "not_a_proxy_buffers_spec": must be a proxy buffer spec`,
			},
			msg: "invalid nginx.org/proxy-buffers annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/proxy-buffer-size": "16k",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-buffer-size annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-buffer-size": "not_a_size",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-buffer-size: Invalid value: "not_a_size": must be a size`,
			},
			msg: "invalid nginx.org/proxy-buffer-size annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/proxy-max-temp-file-size": "128M",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/proxy-max-temp-file-size annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/proxy-max-temp-file-size": "not_a_size",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-max-temp-file-size: Invalid value: "not_a_size": must be a size`,
			},
			msg: "invalid nginx.org/proxy-max-temp-file-size annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/upstream-zone-size": "512k",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/upstream-zone-size annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/upstream-zone-size": "not a size",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/upstream-zone-size: Invalid value: "not a size": must be a size`,
			},
			msg: "invalid nginx.org/upstream-zone-size annotation",
		},

		{
			annotations: map[string]string{
				"nginx.com/jwt-realm": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-realm: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid nginx.com/jwt-realm annotation, nginx plus only",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-realm": "my-jwt-realm",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.com/jwt-realm annotation",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-realm": "",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-realm: Required value",
			},
			msg: "invalid nginx.com/jwt-realm annotation, empty",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-realm": "realm$1",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/jwt-realm: Invalid value: "realm$1": a valid annotation value must have all '"' escaped and must not contain any '$' or end with an unescaped '\' (e.g. 'My Realm',  or 'Cafe App', regex used for validation is '([^"$\\]|\\[^$])*')`,
			},
			msg: "invalid nginx.com/jwt-realm annotation with special character '$'",
		},

		{
			annotations: map[string]string{
				"nginx.com/jwt-key": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-key: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid nginx.com/jwt-key annotation, nginx plus only",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-key": "my-jwk",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.com/jwt-key annotation",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-key": "my_jwk",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-key: Invalid value: \"my_jwk\": a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')",
			},
			msg: "invalid nginx.com/jwt-key annotation, containing '_",
		},

		{
			annotations: map[string]string{
				"nginx.com/jwt-token": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-token: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid nginx.com/jwt-token annotation, nginx plus only",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-token": "$cookie_auth_token",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.com/jwt-token annotation",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-token": "cookie_auth_token",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-token: Invalid value: \"cookie_auth_token\": a valid annotation value must start with '$', have all '\"' escaped, and must not contain any '$' or end with an unescaped '\\' (e.g. '$http_token',  or '$cookie_auth_token', regex used for validation is '\\$([^\"$\\\\]|\\\\[^$])*')",
			}, msg: "invalid nginx.com/jwt-token annotation, '$' missing",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-token": `$cookie_auth_token"`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-token: Invalid value: \"$cookie_auth_token\\\"\": a valid annotation value must start with '$', have all '\"' escaped, and must not contain any '$' or end with an unescaped '\\' (e.g. '$http_token',  or '$cookie_auth_token', regex used for validation is '\\$([^\"$\\\\]|\\\\[^$])*')",
			},
			msg: "invalid nginx.com/jwt-token annotation, containing unescaped '\"'",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-token": `$cookie_auth_token\`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-token: Invalid value: \"$cookie_auth_token\\\\\": a valid annotation value must start with '$', have all '\"' escaped, and must not contain any '$' or end with an unescaped '\\' (e.g. '$http_token',  or '$cookie_auth_token', regex used for validation is '\\$([^\"$\\\\]|\\\\[^$])*')",
			},
			msg: "invalid nginx.com/jwt-token annotation, containing escape characters",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-token": "cookie_auth$token",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-token: Invalid value: \"cookie_auth$token\": a valid annotation value must start with '$', have all '\"' escaped, and must not contain any '$' or end with an unescaped '\\' (e.g. '$http_token',  or '$cookie_auth_token', regex used for validation is '\\$([^\"$\\\\]|\\\\[^$])*')",
			},
			msg: "invalid nginx.com/jwt-token annotation, containing incorrect variable",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-token": "$cookie_auth_token$http_token",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-token: Invalid value: \"$cookie_auth_token$http_token\": a valid annotation value must start with '$', have all '\"' escaped, and must not contain any '$' or end with an unescaped '\\' (e.g. '$http_token',  or '$cookie_auth_token', regex used for validation is '\\$([^\"$\\\\]|\\\\[^$])*')",
			},
			msg: "invalid nginx.com/jwt-token annotation, containing more than 1 variable",
		},

		{
			annotations: map[string]string{
				"nginx.com/jwt-login-url": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-login-url: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid nginx.com/jwt-login-url annotation, nginx plus only",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-login-url": "https://login.example.com",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.com/jwt-login-url annotation",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-login-url": `https://login.example.com\`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/jwt-login-url: Invalid value: "https://login.example.com\\": parse "https://login.example.com\\": invalid character "\\" in host name`,
			},
			msg: "invalid nginx.com/jwt-login-url annotation, containing escape character at the end",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-login-url": `https://{login.example.com`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/jwt-login-url: Invalid value: "https://{login.example.com": parse "https://{login.example.com": invalid character "{" in host name`,
			},
			msg: "invalid nginx.com/jwt-login-url annotation, containing invalid character",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-login-url": "login.example.com",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-login-url: Invalid value: \"login.example.com\": scheme required, please use the prefix http(s)://",
			},
			msg: "invalid nginx.com/jwt-login-url annotation, scheme missing",
		},
		{
			annotations: map[string]string{
				"nginx.com/jwt-login-url": "http:",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/jwt-login-url: Invalid value: \"http:\": hostname required",
			},
			msg: "invalid nginx.com/jwt-login-url annotation, hostname missing",
		},

		{
			annotations: map[string]string{
				"nginx.org/listen-ports": "80,8080,9090,44313",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/listen-ports annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/listen-ports": "not_a_port_list",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/listen-ports: Invalid value: "not_a_port_list": must be a comma-separated list of port numbers`,
			},
			msg: "invalid nginx.org/listen-ports annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/listen-ports-ssl": "443,8443,44315",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/listen-ports-ssl annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/listen-ports-ssl": "not_a_port_list",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/listen-ports-ssl: Invalid value: "not_a_port_list": must be a comma-separated list of port numbers`,
			},
			msg: "invalid nginx.org/listen-ports-ssl annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/keepalive": "1000",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/keepalive annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/keepalive": "not_a_number",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/keepalive: Invalid value: "not_a_number": must be an integer`,
			},
			msg: "invalid nginx.org/keepalive annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/max-fails": "5",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/max-fails annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/max-fails": "-100",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/max-fails: Invalid value: "-100": must be a non-negative integer`,
			},
			msg: "invalid nginx.org/max-fails annotation, negative number",
		},
		{
			annotations: map[string]string{
				"nginx.org/max-fails": "not_a_number",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/max-fails: Invalid value: "not_a_number": must be a non-negative integer`,
			},
			msg: "invalid nginx.org/max-fails annotation, not a number",
		},

		{
			annotations: map[string]string{
				"nginx.org/max-conns": "10",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/max-conns annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/max-conns": "-100",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/max-conns: Invalid value: "-100": must be a non-negative integer`,
			},
			msg: "invalid nginx.org/max-conns annotation, negative number",
		},
		{
			annotations: map[string]string{
				"nginx.org/max-conns": "not_a_number",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/max-conns: Invalid value: "not_a_number": must be a non-negative integer`,
			},
			msg: "invalid nginx.org/max-conns annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/fail-timeout": "10s",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/fail-timeout annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/fail-timeout": "not_a_time",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/fail-timeout: Invalid value: "not_a_time": must be a time`,
			},
			msg: "invalid nginx.org/fail-timeout annotation",
		},

		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-enable": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-enable: Forbidden: annotation requires AppProtect",
			},
			msg: "invalid appprotect.f5.com/app-protect-enable annotation, requires app protect",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-enable": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid appprotect.f5.com/app-protect-enable annotation",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-enable": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.appprotect.f5.com/app-protect-enable: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid appprotect.f5.com/app-protect-enable annotation",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-enable": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.appprotect.f5.com/app-protect-enable: Forbidden: annotation requires NGINX Plus`,
			},
			msg: "invalid appprotect.f5.com/app-protect-enable annotation, requires NGINX Plus",
		},

		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log-enable": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-security-log-enable: Forbidden: annotation requires AppProtect",
			},
			msg: "invalid appprotect.f5.com/app-protect-security-log-enable annotation, requires app protect",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log-enable": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid appprotect.f5.com/app-protect-security-log-enable annotation",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log-enable": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.appprotect.f5.com/app-protect-security-log-enable: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid appprotect.f5.com/app-protect-security-log-enable annotation",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log-enable": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.appprotect.f5.com/app-protect-security-log-enable: Forbidden: annotation requires NGINX Plus`,
			},
			msg: "invalid appprotect.f5.com/app-protect-security-log-enable annotation, requires NGINX Plus",
		},

		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-policy": "default/dataguard-alarm",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid appprotect.f5.com/app-protect-policy annotation",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-policy": `default/dataguard\alarm`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-policy: Invalid value: \"default/dataguard\\\\alarm\": must be a qualified name",
			}, msg: "invalid appprotect.f5.com/app-protect-policy annotation, not a qualified name",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-policy": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-policy: Forbidden: annotation requires AppProtect",
			},
			msg: "invalid appprotect.f5.com/app-protect-policy annotation, requires AppProtect",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-policy": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-policy: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid appprotect.f5.com/app-protect-policy annotation, requires NGINX Plus",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-policy": "",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-policy: Required value",
			},
			msg: "invalid appprotect.f5.com/app-protect-policy annotation, requires value",
		},

		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log": "default/logconf",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid appprotect.f5.com/app-protect-security-log annotation",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log": `default/logconf,default/logconf2`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid appprotect.f5.com/app-protect-security-log annotation, multiple values",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log": `default/logconf\`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-security-log: Invalid value: \"default/logconf\\\\\": security log configuration resource name must be qualified name, e.g. namespace/name",
			}, msg: "invalid appprotect.f5.com/app-protect-security-log annotation, not a qualified name",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-security-log: Forbidden: annotation requires AppProtect",
			},
			msg: "invalid appprotect.f5.com/app-protect-security-log annotation, requires AppProtect",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-security-log: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid appprotect.f5.com/app-protect-security-log annotation, requires NGINX Plus",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log": "",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-security-log: Required value",
			},
			msg: "invalid appprotect.f5.com/app-protect-security-log annotation, requires value",
		},

		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log-destination": "syslog:server=localhost:514",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid appprotect.f5.com/app-protect-security-log-destination annotation",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log-destination": `syslog:server=localhost:514,syslog:server=syslog-svc.default:514`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid appprotect.f5.com/app-protect-security-log-destination annotation, multiple values",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log-destination": `syslog:server=localhost\:514`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-security-log-destination: Invalid value: \"syslog:server=localhost\\\\:514\": Error Validating App Protect Log Destination Config: error parsing App Protect Log config: Destination must follow format: syslog:server=<ip-address | localhost>:<port> or fqdn or stderr or absolute path to file Log Destination did not follow format",
			},
			msg: "invalid appprotect.f5.com/app-protect-security-log-destination, invalid value",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log-destination": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-security-log-destination: Forbidden: annotation requires AppProtect",
			},
			msg: "invalid appprotect.f5.com/app-protect-security-log-destination annotation, requires AppProtect",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log-destination": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-security-log-destination: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid appprotect.f5.com/app-protect-security-log-destination annotation, requires NGINX Plus",
		},
		{
			annotations: map[string]string{
				"appprotect.f5.com/app-protect-security-log-destination": "",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     true,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotect.f5.com/app-protect-security-log-destination: Required value",
			},
			msg: "invalid appprotect.f5.com/app-protect-security-log-destination, requires value",
		},

		{
			annotations: map[string]string{
				"appprotectdos.f5.com/app-protect-dos-resource": "dos-resource-name",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotectdos.f5.com/app-protect-dos-resource: Forbidden: annotation requires AppProtectDos",
			},
			msg: "invalid appprotectdos.f5.com/app-protect-dos-resource annotation, requires app protect dos",
		},
		{
			annotations: map[string]string{
				"appprotectdos.f5.com/app-protect-dos-resource": "dos-resource-name",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  true,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid appprotectdos.f5.com/app-protect-dos-enable annotation with default namespace",
		},
		{
			annotations: map[string]string{
				"appprotectdos.f5.com/app-protect-dos-resource": "some-namespace/dos-resource-name",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  true,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid appprotectdos.f5.com/app-protect-dos-enable annotation with fully specified identifier",
		},
		{
			annotations: map[string]string{
				"appprotectdos.f5.com/app-protect-dos-resource": "special-chars-&%^",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  true,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotectdos.f5.com/app-protect-dos-resource: Invalid value: \"special-chars-&%^\": must be a qualified name",
			},
			msg: "invalid appprotectdos.f5.com/app-protect-dos-enable annotation with special characters",
		},
		{
			annotations: map[string]string{
				"appprotectdos.f5.com/app-protect-dos-resource": "too/many/qualifiers",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  true,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.appprotectdos.f5.com/app-protect-dos-resource: Invalid value: \"too/many/qualifiers\": must be a qualified name",
			},
			msg: "invalid appprotectdos.f5.com/app-protect-dos-enable annotation with incorrectly qualified identifier",
		},

		{
			annotations: map[string]string{
				"nsm.nginx.com/internal-route": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nsm.nginx.com/internal-route: Forbidden: annotation requires Internal Routes enabled",
			},
			msg: "invalid nsm.nginx.com/internal-route annotation, requires internal routes",
		},
		{
			annotations: map[string]string{
				"nsm.nginx.com/internal-route": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: true,
			expectedErrors:        nil,
			msg:                   "valid nsm.nginx.com/internal-route annotation",
		},
		{
			annotations: map[string]string{
				"nsm.nginx.com/internal-route": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: true,
			expectedErrors: []string{
				`annotations.nsm.nginx.com/internal-route: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nsm.nginx.com/internal-route annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/websocket-services": "service-1",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/websocket-services annotation, single-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/websocket-services": "service-1,service-2",
			},
			specServices: map[string]bool{
				"service-1": true,
				"service-2": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/websocket-services annotation, multi-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/websocket-services": "service-1,service-2",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/websocket-services: Invalid value: "service-1,service-2": must be a comma-separated list of services. The following services were not found: service-2`,
			},
			msg: "invalid nginx.org/websocket-services annotation, service does not exist",
		},

		{
			annotations: map[string]string{
				"nginx.org/ssl-services": "service-1",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/ssl-services annotation, single-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/ssl-services": "service-1,service-2",
			},
			specServices: map[string]bool{
				"service-1": true,
				"service-2": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/ssl-services annotation, multi-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/ssl-services": "service-1,service-2",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/ssl-services: Invalid value: "service-1,service-2": must be a comma-separated list of services. The following services were not found: service-2`,
			},
			msg: "invalid nginx.org/ssl-services annotation, service does not exist",
		},

		{
			annotations: map[string]string{
				"nginx.org/grpc-services": "service-1",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/grpc-services annotation, single-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/grpc-services": "service-1,service-2",
			},
			specServices: map[string]bool{
				"service-1": true,
				"service-2": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/grpc-services annotation, multi-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/grpc-services": "service-1,service-2",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/grpc-services: Invalid value: "service-1,service-2": must be a comma-separated list of services. The following services were not found: service-2`,
			},
			msg: "invalid nginx.org/grpc-services annotation, service does not exist",
		},

		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=/rewrite-1",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/rewrites annotation, single-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=/rewrite-1/",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/rewrites annotation, single-value, trailing '/'",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=/rewrite-1/rewrite",
			},
			specServices: map[string]bool{
				"service-1": true,
			}, isPlus: false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/rewrites annotation, single-value, uri levels",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=rewrite-1",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "serviceName=service-1 rewrite=rewrite-1": path must start with '/' and must not include any whitespace character, '{', '}' or '$': 'rewrite-1'`,
			},
			msg: "invalid nginx.org/rewrites annotation, single-value, no '/' in the beginning",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "service-1 rewrite=/rewrite-1",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "service-1 rewrite=/rewrite-1": 'service-1' is not a valid serviceName format, e.g. 'serviceName=tea-svc'`,
			},
			msg: "invalid nginx.org/rewrites annotation, single-value, invalid service name format, 'serviceName' missing",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName1=service-1 rewrite=/rewrite-1",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "serviceName1=service-1 rewrite=/rewrite-1": 'serviceName1=service-1' is not a valid serviceName format, e.g. 'serviceName=tea-svc'`,
			},
			msg: "invalid nginx.org/rewrites annotation, single-value, invalid service name format, 'serviceName' typo",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrit=/rewrite-1",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "serviceName=service-1 rewrit=/rewrite-1": 'rewrit=/rewrite-1' is not a valid rewrite path format, e.g. 'rewrite=/tea'`,
			},
			msg: "invalid nginx.org/rewrites annotation, single-value, invalid service name format, 'rewrite' typo ",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=/rewrite",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "serviceName=service-1 rewrite=/rewrite": The following services were not found: service-1`,
			},
			msg: "invaild nginx.org/rewrites annotation, single-value, service does not exist",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=/rewrite-{1}",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "serviceName=service-1 rewrite=/rewrite-{1}": path must start with '/' and must not include any whitespace character, '{', '}' or '$': '/rewrite-{1}'`,
			},
			msg: "invalid nginx.org/rewrites annotation, single-value, path containing special characters",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=/rewr ite",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "serviceName=service-1 rewrite=/rewr ite": path must start with '/' and must not include any whitespace character, '{', '}' or '$': '/rewr ite'`,
			},
			msg: "invalid nginx.org/rewrites annotation, single-value, path containing white spaces",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=/rewrite/$1",
			},
			specServices: map[string]bool{
				"service-1": true,
			}, isPlus: false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "serviceName=service-1 rewrite=/rewrite/$1": path must start with '/' and must not include any whitespace character, '{', '}' or '$': '/rewrite/$1'`,
			},
			msg: "invaild nginx.org/rewrites annotation, single-value, path containing regex characters",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=/rewrite-1;serviceName=service-2 rewrite=/rewrite-2",
			},
			specServices: map[string]bool{
				"service-1": true,
				"service-2": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/rewrites annotation, multi-value",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=/rewrite-1;serviceName=service-2 rewrite=/rewrite-2",
			},
			specServices: map[string]bool{
				"service-1": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "serviceName=service-1 rewrite=/rewrite-1;serviceName=service-2 rewrite=/rewrite-2": The following services were not found: service-2`,
			},
			msg: "valid nginx.org/rewrites annotation, multi-value, service does not exist",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "serviceName=service-1 rewrite=rewrite-1;serviceName=service-2 rewrite=/rewrite-2",
			},
			specServices: map[string]bool{
				"service-1": true,
				"service-2": true,
			},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "serviceName=service-1 rewrite=rewrite-1;serviceName=service-2 rewrite=/rewrite-2": path must start with '/' and must not include any whitespace character, '{', '}' or '$': 'rewrite-1'`,
			},
			msg: "invalid nginx.org/rewrites annotation, multi-value without '/' in the beginning",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrites": "not_a_rewrite",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: true,
			expectedErrors: []string{
				`annotations.nginx.org/rewrites: Invalid value: "not_a_rewrite": 'not_a_rewrite' is not a valid rewrite format, e.g. 'serviceName=tea-svc rewrite=/'`,
			},
			msg: "invalid nginx.org/rewrites annotation",
		},

		{
			annotations: map[string]string{
				"nginx.com/sticky-cookie-services": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.com/sticky-cookie-services: Forbidden: annotation requires NGINX Plus",
			},
			msg: "invalid nginx.com/sticky-cookie-services annotation, nginx plus only",
		},
		{
			annotations: map[string]string{
				"nginx.com/sticky-cookie-services": "serviceName=service-1 srv_id expires=1h path=/service-1",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.com/sticky-cookie-services annotation, single-value",
		},
		{
			annotations: map[string]string{
				"nginx.com/sticky-cookie-services": "serviceName=service-1 srv_id expires=1h path=/service-1;serviceName=service-2 srv_id expires=2h path=/service-2",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.com/sticky-cookie-services annotation, multi-value",
		},
		{
			annotations: map[string]string{
				"nginx.com/sticky-cookie-services": `serviceName=service-1 srv_id expires=1h path=/service-1\;serviceName=service-2 srv_id expires=2h path=/service-2`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/sticky-cookie-services: Invalid value: "serviceName=service-1 srv_id expires=1h path=/service-1\\;serviceName=service-2 srv_id expires=2h path=/service-2": invalid sticky-cookie parameters: srv_id expires=1h path=/service-1\`,
			},
			msg: `invalid sticky-cookie parameters: srv_id expires=1h path=/service-1\`,
		},
		{
			annotations: map[string]string{
				"nginx.com/sticky-cookie-services": `serviceName=service-1 srv_id expires=1h path=/service-1;serviceName=service-2 srv_id expires=2h path=/service-2\`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/sticky-cookie-services: Invalid value: "serviceName=service-1 srv_id expires=1h path=/service-1;serviceName=service-2 srv_id expires=2h path=/service-2\\": invalid sticky-cookie parameters: srv_id expires=2h path=/service-2\`,
			},
			msg: `invalid sticky-cookie parameters: srv_id expires=2h path=/service-2\`,
		},
		{
			annotations: map[string]string{
				"nginx.com/sticky-cookie-services": `serviceName=service-1 srv_id expires=1h path=/service-1\`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/sticky-cookie-services: Invalid value: "serviceName=service-1 srv_id expires=1h path=/service-1\\": invalid sticky-cookie parameters: srv_id expires=1h path=/service-1\`,
			},
			msg: `invalid sticky-cookie parameters: srv_id expires=1h path=/service-1\`,
		},
		{
			annotations: map[string]string{
				"nginx.com/sticky-cookie-services": `serviceName=service-1 srv_id expires=1h path=/service-1$`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/sticky-cookie-services: Invalid value: "serviceName=service-1 srv_id expires=1h path=/service-1$": invalid sticky-cookie parameters: srv_id expires=1h path=/service-1$`,
			},
			msg: `invalid sticky-cookie parameters: srv_id expires=1h path=/service-1$`,
		},
		{
			annotations: map[string]string{
				"nginx.com/sticky-cookie-services": `serviceName=service-1 srv_id expires=1h path=/service-1;serviceName=service-2 srv_id expires=2h path=/service-2$`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/sticky-cookie-services: Invalid value: "serviceName=service-1 srv_id expires=1h path=/service-1;serviceName=service-2 srv_id expires=2h path=/service-2$": invalid sticky-cookie parameters: srv_id expires=2h path=/service-2$`,
			},
			msg: `invalid sticky-cookie parameters: srv_id expires=2h path=/service-2$`,
		},
		{
			annotations: map[string]string{
				"nginx.com/sticky-cookie-services": "not_a_rewrite",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.com/sticky-cookie-services: Invalid value: "not_a_rewrite": invalid sticky-cookie service format: not_a_rewrite. Must be a semicolon-separated list of sticky services`,
			},
			msg: "invalid nginx.com/sticky-cookie-services annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/use-cluster-ip": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/use-cluster-ip: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nginx.org/use-cluster-ip annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/use-cluster-ip": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/use-cluster-ip annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/use-cluster-ip": "false",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/use-cluster-ip annotation",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			allErrs := validateIngressAnnotations(
				test.annotations,
				test.specServices,
				test.isPlus,
				test.appProtectEnabled,
				test.appProtectDosEnabled,
				test.internalRoutesEnabled,
				field.NewPath("annotations"),
				test.snippetsEnabled,
			)
			assertion := assertErrors("validateIngressAnnotations()", test.msg, allErrs, test.expectedErrors)
			if assertion != "" {
				t.Error(assertion)
			}
		})
	}
}

func TestValidateIngressSpec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		spec           *networking.IngressSpec
		expectedErrors []field.ErrorType
		msg            string
	}{
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: "/",
										Backend: networking.IngressBackend{
											Service: &networking.IngressServiceBackend{},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: nil,
			msg:            "valid input",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: `/tea\{custom_value}`,
										Backend: networking.IngressBackend{
											Service: &networking.IngressServiceBackend{},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: []field.ErrorType{
				field.ErrorTypeInvalid,
			},
			msg: "test invalid characters in path",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: `/tea\{custom_value}`,
										Backend: networking.IngressBackend{
											Service: &networking.IngressServiceBackend{},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: []field.ErrorType{
				field.ErrorTypeInvalid,
			},
			msg: "test invalid characters in path",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: `/tea\`,
										Backend: networking.IngressBackend{
											Service: &networking.IngressServiceBackend{},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: []field.ErrorType{
				field.ErrorTypeInvalid,
			},
			msg: "test invalid characters in path",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: `/tea\n`,
										Backend: networking.IngressBackend{
											Service: &networking.IngressServiceBackend{},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: []field.ErrorType{
				field.ErrorTypeInvalid,
			},
			msg: "test invalid characters in path",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: "",
										Backend: networking.IngressBackend{
											Service: &networking.IngressServiceBackend{},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: []field.ErrorType{
				field.ErrorTypeRequired,
			},
			msg: "test empty in path",
		},
		{
			spec: &networking.IngressSpec{
				DefaultBackend: &networking.IngressBackend{
					Service: &networking.IngressServiceBackend{},
				},
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
					},
				},
			},
			expectedErrors: nil,
			msg:            "valid input with default backend",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{},
			},
			expectedErrors: []field.ErrorType{
				field.ErrorTypeRequired,
			},
			msg: "zero rules",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "",
					},
				},
			},
			expectedErrors: []field.ErrorType{
				field.ErrorTypeRequired,
			},
			msg: "empty host",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
					},
					{
						Host: "foo.example.com",
					},
				},
			},
			expectedErrors: []field.ErrorType{
				field.ErrorTypeDuplicate,
			},
			msg: "duplicated host",
		},
		{
			spec: &networking.IngressSpec{
				DefaultBackend: &networking.IngressBackend{
					Resource: &v1.TypedLocalObjectReference{},
				},
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
					},
				},
			},
			expectedErrors: []field.ErrorType{
				field.ErrorTypeForbidden,
			},
			msg: "invalid default backend",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: "/",
										Backend: networking.IngressBackend{
											Resource: &v1.TypedLocalObjectReference{},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: []field.ErrorType{
				field.ErrorTypeForbidden,
			},
			msg: "invalid backend",
		},
	}

	for _, test := range tests {
		allErrs := validateIngressSpec(test.spec, field.NewPath("spec"))
		assertion := assertErrorTypes(test.msg, allErrs, test.expectedErrors)
		if assertion != "" {
			t.Error(assertion)
		}
	}
}

func TestValidateMasterSpec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		spec           *networking.IngressSpec
		expectedErrors []string
		msg            string
	}{
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{},
							},
						},
					},
				},
			},
			expectedErrors: nil,
			msg:            "valid input",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
					},
					{
						Host: "bar.example.com",
					},
				},
			},
			expectedErrors: []string{
				"spec.rules: Too many: 2: must have at most 1 items",
			},
			msg: "too many hosts",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: "/",
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: []string{
				"spec.rules[0].http.paths: Too many: 1: must have at most 0 items",
			},
			msg: "too many paths",
		},
	}

	for _, test := range tests {
		allErrs := validateMasterSpec(test.spec, field.NewPath("spec"))
		assertion := assertErrors("validateMasterSpec()", test.msg, allErrs, test.expectedErrors)
		if assertion != "" {
			t.Error(assertion)
		}
	}
}

func TestValidateMinionSpec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		spec           *networking.IngressSpec
		expectedErrors []string
		msg            string
	}{
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: "/",
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: nil,
			msg:            "valid input",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
					},
					{
						Host: "bar.example.com",
					},
				},
			},
			expectedErrors: []string{
				"spec.rules: Too many: 2: must have at most 1 items",
			},
			msg: "too many hosts",
		},
		{
			spec: &networking.IngressSpec{
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{},
							},
						},
					},
				},
			},
			expectedErrors: []string{
				"spec.rules[0].http.paths: Required value: must include at least one path",
			},
			msg: "too few paths",
		},
		{
			spec: &networking.IngressSpec{
				TLS: []networking.IngressTLS{
					{
						Hosts: []string{"foo.example.com"},
					},
				},
				Rules: []networking.IngressRule{
					{
						Host: "foo.example.com",
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: "/",
									},
								},
							},
						},
					},
				},
			},
			expectedErrors: []string{
				"spec.tls: Too many: 1: must have at most 0 items",
			},
			msg: "tls is forbidden",
		},
	}

	for _, test := range tests {
		allErrs := validateMinionSpec(test.spec, field.NewPath("spec"))
		assertion := assertErrors("validateMinionSpec()", test.msg, allErrs, test.expectedErrors)
		if assertion != "" {
			t.Error(assertion)
		}
	}
}

func assertErrorTypes(msg string, allErrs field.ErrorList, expectedErrors []field.ErrorType) string {
	returnedErrors := errorListToTypes(allErrs)
	if !reflect.DeepEqual(returnedErrors, expectedErrors) {
		return fmt.Sprintf("%s returned %s but expected %s", msg, returnedErrors, expectedErrors)
	}
	return ""
}

func assertErrors(funcName string, msg string, allErrs field.ErrorList, expectedErrors []string) string {
	errors := errorListToStrings(allErrs)
	if !reflect.DeepEqual(errors, expectedErrors) {
		result := strings.Join(errors, "\n")
		expected := strings.Join(expectedErrors, "\n")

		return fmt.Sprintf("%s returned \n%s \nbut expected \n%s \nfor the case of %s", funcName, result, expected, msg)
	}

	return ""
}

func errorListToStrings(list field.ErrorList) []string {
	var result []string

	for _, e := range list {
		result = append(result, e.Error())
	}

	return result
}

func errorListToTypes(list field.ErrorList) []field.ErrorType {
	var result []field.ErrorType

	for _, e := range list {
		result = append(result, e.Type)
	}

	return result
}

func TestGetSpecServices(t *testing.T) {
	t.Parallel()
	tests := []struct {
		spec     networking.IngressSpec
		expected map[string]bool
		msg      string
	}{
		{
			spec: networking.IngressSpec{
				DefaultBackend: &networking.IngressBackend{
					Service: &networking.IngressServiceBackend{
						Name: "svc1",
					},
				},
				Rules: []networking.IngressRule{
					{
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path: "/",
										Backend: networking.IngressBackend{
											Service: &networking.IngressServiceBackend{
												Name: "svc2",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: map[string]bool{
				"svc1": true,
				"svc2": true,
			},
			msg: "services are referenced",
		},
		{
			spec: networking.IngressSpec{
				DefaultBackend: &networking.IngressBackend{},
				Rules: []networking.IngressRule{
					{
						IngressRuleValue: networking.IngressRuleValue{
							HTTP: &networking.HTTPIngressRuleValue{
								Paths: []networking.HTTPIngressPath{
									{
										Path:    "/",
										Backend: networking.IngressBackend{},
									},
								},
							},
						},
					},
				},
			},
			expected: map[string]bool{},
			msg:      "services are not referenced",
		},
	}

	for _, test := range tests {
		result := getSpecServices(test.spec)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("getSpecServices() returned %v but expected %v for the case of %s", result, test.expected, test.msg)
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
			regexPath: "/foo.*\\.jpg",
			msg:       "case sensitive regexp",
		},
		{
			regexPath: "/Bar.*\\.jpg",
			msg:       "case insensitive regexp",
		},
		{
			regexPath: `/f\"oo.*\\.jpg`,
			msg:       "regexp with escaped double quotes",
		},
		{
			regexPath: "/[0-9a-z]{4}[0-9]+",
			msg:       "regexp with curly braces",
		},
		{
			regexPath: "~ ^/coffee/(?!.*\\/latte)(?!.*\\/americano)(.*)",
			msg:       "regexp with Perl5 regex",
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
			regexPath: "[{",
			msg:       "invalid regexp",
		},
		{
			regexPath: `/foo"`,
			msg:       "unescaped double quotes",
		},
		{
			regexPath: `"`,
			msg:       "empty regex",
		},
		{
			regexPath: `/foo\`,
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

func TestValidatePath(t *testing.T) {
	t.Parallel()

	validPaths := []string{
		"/",
		"/path",
		"/a-1/_A/",
		"/[A-Za-z]{6}/[a-z]{1,2}",
		"/[0-9a-z]{4}[0-9]",
		"/foo.*\\.jpg",
		"/Bar.*\\.jpg",
		`/f\"oo.*\\.jpg`,
		"/[0-9a-z]{4}[0-9]+",
		"/[a-z]{1,2}",
		"/[A-Z]{6}",
		"/[A-Z]{6}/[a-z]{1,2}",
		"/path",
		"/abc}{abc",
	}

	pathType := networking.PathTypeExact

	for _, path := range validPaths {
		allErrs := validatePath(path, &pathType, field.NewPath("path"))
		if len(allErrs) > 0 {
			t.Errorf("validatePath(%q) returned errors %v for valid input", path, allErrs)
		}
	}

	invalidPaths := []string{
		"",
		" /",
		"/ ",
		"/abc;",
		`/path\`,
		`/path\n`,
		`/var/run/secrets`,
		"/{autoindex on; root /var/run/secrets;}location /tea",
		"/{root}",
	}

	for _, path := range invalidPaths {
		allErrs := validatePath(path, &pathType, field.NewPath("path"))
		if len(allErrs) == 0 {
			t.Errorf("validatePath(%q) returned no errors for invalid input", path)
		}
	}

	pathType = networking.PathTypeImplementationSpecific

	allErrs := validatePath("", &pathType, field.NewPath("path"))
	if len(allErrs) > 0 {
		t.Errorf("validatePath with empty path and type ImplementationSpecific returned errors %v for valid input", allErrs)
	}
}

func TestValidateCurlyBraces(t *testing.T) {
	t.Parallel()

	validPaths := []string{
		"/[a-z]{1,2}",
		"/[A-Z]{6}",
		"/[A-Z]{6}/[a-z]{1,2}",
		"/path",
		"/abc}{abc",
	}

	for _, path := range validPaths {
		allErrs := validateCurlyBraces(path, field.NewPath("path"))
		if len(allErrs) > 0 {
			t.Errorf("validatePath(%q) returned errors %v for valid input", path, allErrs)
		}
	}

	invalidPaths := []string{
		"/[A-Z]{a}",
		"/{abc}abc",
		"/abc{a1}",
	}

	for _, path := range invalidPaths {
		allErrs := validateCurlyBraces(path, field.NewPath("path"))
		if len(allErrs) == 0 {
			t.Errorf("validateCurlyBraces(%q) returned no errors for invalid input", path)
		}
	}
}

func TestValidateIllegalKeywords(t *testing.T) {
	t.Parallel()

	invalidPaths := []string{
		"/root",
		"/etc/nginx/secrets",
		"/etc/passwd",
		"/var/run/secrets",
		`\n`,
		`\r`,
	}

	for _, path := range invalidPaths {
		allErrs := validateIllegalKeywords(path, field.NewPath("path"))
		if len(allErrs) == 0 {
			t.Errorf("validateCurlyBraces(%q) returned no errors for invalid input", path)
		}
	}
}

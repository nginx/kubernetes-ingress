package k8s

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/configs"
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
			allErrs := validateIngress(tc.ingress, tc.isPlus, false, false, false, false, false)
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
			allErrs := validateIngress(tc.ingress, tc.isPlus, false, false, false, false, false)
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
			allErrs := validateIngress(tc.ingress, tc.isPlus, false, false, false, false, false)
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
			allErrs := validateIngress(tc.ingress, tc.isPlus, false, false, false, false, false)
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
		allErrs := validateIngress(test.ing, test.isPlus, test.appProtectEnabled, test.appProtectDosEnabled, test.internalRoutesEnabled, false, false)
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
		directiveAutoAdjust   bool
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.nginx.org/redirect-to-https: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nginx.org/redirect-to-https annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/ssl-redirect": "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/ssl-redirect annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/ssl-redirect": "not_a_boolean",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.nginx.org/ssl-redirect: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid nginx.org/ssl-redirect annotation",
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.ingress.kubernetes.io/ssl-redirect: Invalid value: "not_a_boolean": must be a boolean`,
			},
			msg: "invalid ingress.kubernetes.io/ssl-redirect annotation",
		},

		{
			annotations: map[string]string{
				"nginx.org/http-redirect-code": "301",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/http-redirect-code annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/http-redirect-code": "302",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/http-redirect-code annotation with 302",
		},
		{
			annotations: map[string]string{
				"nginx.org/http-redirect-code": "307",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/http-redirect-code annotation with 307",
		},
		{
			annotations: map[string]string{
				"nginx.org/http-redirect-code": "308",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/http-redirect-code annotation with 308",
		},
		{
			annotations: map[string]string{
				"nginx.org/http-redirect-code": "",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.nginx.org/http-redirect-code: Required value`,
			},
			msg: "invalid nginx.org/http-redirect-code annotation, empty string",
		},
		{
			annotations: map[string]string{
				"nginx.org/http-redirect-code": "200",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.nginx.org/http-redirect-code: Invalid value: "200": status code out of accepted range. accepted values are '301', '302', '307', '308'`,
			},
			msg: "invalid nginx.org/http-redirect-code annotation, invalid code",
		},
		{
			annotations: map[string]string{
				"nginx.org/http-redirect-code": "invalid",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.nginx.org/http-redirect-code: Invalid value: "invalid": invalid redirect code: strconv.Atoi: parsing "invalid": invalid syntax`,
			},
			msg: "invalid nginx.org/http-redirect-code annotation, not a number",
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-buffer-size: Invalid value: "not_a_size": must consist of numeric characters followed by a valid size suffix. 'k|K|m|M (e.g. '16',  or '32k',  or '64M', regex used for validation is '\d+[kKmM]?')`,
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.nginx.org/proxy-max-temp-file-size: Invalid value: "not_a_size": must consist of numeric characters followed by a valid size suffix. 'k|K|m|M (e.g. '16',  or '32k',  or '64M', regex used for validation is '\d+[kKmM]?')`,
			},
			msg: "invalid nginx.org/proxy-max-temp-file-size annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamAnnotation: "error timeout http_502 http_503",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamAnnotation: "error      timeout http_502 http_503",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamAnnotation: "denied",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamAnnotation + `: Invalid value: "denied": must be a space-separated list with any of the following values: error, http_403, http_404, http_429, http_500, http_502, http_503, http_504, invalid_header, non_idempotent, off, timeout`,
			},
			msg: "Plus Only " + configs.ProxyNextUpstreamAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamAnnotation: "invalid_value",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamAnnotation + `: Invalid value: "invalid_value": must be a space-separated list with any of the following values: error, http_403, http_404, http_429, http_500, http_502, http_503, http_504, invalid_header, non_idempotent, off, timeout`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamAnnotation: "",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamAnnotation + `: Required value`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTimeoutAnnotation: "0",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamTimeoutAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTimeoutAnnotation: "123",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamTimeoutAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTimeoutAnnotation: "-123",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTimeoutAnnotation + `: Invalid value: "-123": must be a time`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTimeoutAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTimeoutAnnotation: "abc",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTimeoutAnnotation + `: Invalid value: "abc": must be a time`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTimeoutAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTimeoutAnnotation: "",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTimeoutAnnotation + `: Required value`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTimeoutAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTriesAnnotation: "0",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamTriesAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTriesAnnotation: "123",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamTriesAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTriesAnnotation: "-123",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTriesAnnotation + `: Invalid value: "-123": must be a non-negative integer`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTriesAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTriesAnnotation: "abc",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTriesAnnotation + `: Invalid value: "abc": must be a non-negative integer`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTriesAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTriesAnnotation: "",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTriesAnnotation + `: Required value`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTriesAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamAnnotation: "error timeout http_502 http_503",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamAnnotation: "invalid_value",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamAnnotation + `: Invalid value: "invalid_value": must be a space-separated list with any of the following values: denied, error, http_403, http_404, http_429, http_500, http_502, http_503, http_504, invalid_header, non_idempotent, off, timeout`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamAnnotation: "",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamAnnotation + `: Required value`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamAnnotation: "denied",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "Plus Only " + configs.ProxyNextUpstreamAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTimeoutAnnotation: "0",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamTimeoutAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTimeoutAnnotation: "123",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamTimeoutAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTimeoutAnnotation: "-123",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTimeoutAnnotation + `: Invalid value: "-123": must be a time`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTimeoutAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTimeoutAnnotation: "abc",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTimeoutAnnotation + `: Invalid value: "abc": must be a time`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTimeoutAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTimeoutAnnotation: "",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTimeoutAnnotation + `: Required value`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTimeoutAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTriesAnnotation: "0",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamTriesAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTriesAnnotation: "123",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			msg:                   "valid " + configs.ProxyNextUpstreamTriesAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTriesAnnotation: "-123",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTriesAnnotation + `: Invalid value: "-123": must be a non-negative integer`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTriesAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTriesAnnotation: "abc",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTriesAnnotation + `: Invalid value: "abc": must be a non-negative integer`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTriesAnnotation + " annotation",
		},
		{
			annotations: map[string]string{
				configs.ProxyNextUpstreamTriesAnnotation: "",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.` + configs.ProxyNextUpstreamTriesAnnotation + `: Required value`,
			},
			msg: "invalid " + configs.ProxyNextUpstreamTriesAnnotation + " annotation",
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
			directiveAutoAdjust:   false,
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
			directiveAutoAdjust:   false,
			expectedErrors: []string{
				`annotations.nginx.org/upstream-zone-size: Invalid value: "not a size": must consist of numeric characters followed by a valid size suffix. 'k|K|m|M (e.g. '16',  or '32k',  or '64M', regex used for validation is '\d+[kKmM]?')`,
			},
			msg: "invalid nginx.org/upstream-zone-size annotation",
		},

		{
			annotations: map[string]string{
				configs.JWTRealmAnnotation: "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf("annotations.%s: Forbidden: annotation requires NGINX Plus", configs.JWTRealmAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, nginx plus only", configs.JWTRealmAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTRealmAnnotation: "my-jwt-realm",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   fmt.Sprintf("valid %s annotation", configs.JWTRealmAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTRealmAnnotation: "",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf("annotations.%s: Required value", configs.JWTRealmAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, empty", configs.JWTRealmAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTRealmAnnotation: "realm$1",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf(`annotations.%s: Invalid value: "realm$1": a valid annotation value must have all '"' escaped and must not contain any '$' or end with an unescaped '\' (e.g. 'My Realm',  or 'Cafe App', regex used for validation is '([^"$\\]|\\[^$])*')`, configs.JWTRealmAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation with special character '$'", configs.JWTRealmAnnotation),
		},

		{
			annotations: map[string]string{
				configs.JWTKeyAnnotation: "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf("annotations.%s: Forbidden: annotation requires NGINX Plus", configs.JWTKeyAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, nginx plus only", configs.JWTKeyAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTKeyAnnotation: "my-jwk",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   fmt.Sprintf("valid %s annotation", configs.JWTKeyAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTKeyAnnotation: "my_jwk",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf(`annotations.%s: Invalid value: "my_jwk": a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')`, configs.JWTKeyAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, containing '_'", configs.JWTKeyAnnotation),
		},

		{
			annotations: map[string]string{
				configs.JWTTokenAnnotation: "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf("annotations.%s: Forbidden: annotation requires NGINX Plus", configs.JWTTokenAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, nginx plus only", configs.JWTTokenAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTTokenAnnotation: "$cookie_auth_token",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   fmt.Sprintf("valid %s annotation", configs.JWTTokenAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTTokenAnnotation: "cookie_auth_token",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf(`annotations.%s: Invalid value: "cookie_auth_token": a valid annotation value must start with '$', have all '"' escaped, and must not contain any '$' or end with an unescaped '\' (e.g. '$http_token',  or '$cookie_auth_token', regex used for validation is '\$([^"$\\]|\\[^$])*')`, configs.JWTTokenAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, '$' missing", configs.JWTTokenAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTTokenAnnotation: `$cookie_auth_token"`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf(`annotations.%s: Invalid value: "$cookie_auth_token\"": a valid annotation value must start with '$', have all '"' escaped, and must not contain any '$' or end with an unescaped '\' (e.g. '$http_token',  or '$cookie_auth_token', regex used for validation is '\$([^"$\\]|\\[^$])*')`, configs.JWTTokenAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, containing unescaped '\"'", configs.JWTTokenAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTTokenAnnotation: `$cookie_auth_token\`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf(`annotations.%s: Invalid value: "$cookie_auth_token\\": a valid annotation value must start with '$', have all '"' escaped, and must not contain any '$' or end with an unescaped '\' (e.g. '$http_token',  or '$cookie_auth_token', regex used for validation is '\$([^"$\\]|\\[^$])*')`, configs.JWTTokenAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, containing escape characters", configs.JWTTokenAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTTokenAnnotation: "cookie_auth$token",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf("annotations.%s: Invalid value: \"%s\": a valid annotation value must start with '$', have all '\"' escaped, and must not contain any '$' or end with an unescaped '\\' (e.g. '$http_token',  or '$cookie_auth_token', regex used for validation is '\\$([^\"$\\\\]|\\\\[^$])*')", configs.JWTTokenAnnotation, "cookie_auth$token"),
			},
			msg: fmt.Sprintf("invalid %s annotation, containing incorrect variable", configs.JWTTokenAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTTokenAnnotation: "$cookie_auth_token$http_token",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf("annotations.%s: Invalid value: \"%s\": a valid annotation value must start with '$', have all '\"' escaped, and must not contain any '$' or end with an unescaped '\\' (e.g. '$http_token',  or '$cookie_auth_token', regex used for validation is '\\$([^\"$\\\\]|\\\\[^$])*')", configs.JWTTokenAnnotation, "$cookie_auth_token$http_token"),
			},
			msg: fmt.Sprintf("invalid %s annotation, containing more than 1 variable", configs.JWTTokenAnnotation),
		},

		{
			annotations: map[string]string{
				configs.JWTLoginURLAnnotation: "true",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf("annotations.%s: Forbidden: annotation requires NGINX Plus", configs.JWTLoginURLAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, nginx plus only", configs.JWTLoginURLAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTLoginURLAnnotation: "https://login.example.com",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   fmt.Sprintf("valid %s annotation", configs.JWTLoginURLAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTLoginURLAnnotation: `https://login.example.com\`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf(`annotations.%s: Invalid value: "https://login.example.com\\": parse "https://login.example.com\\": invalid character "\\" in host name`, configs.JWTLoginURLAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, containing escape character at the end", configs.JWTLoginURLAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTLoginURLAnnotation: `https://{login.example.com`,
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf(`annotations.%s: Invalid value: "https://{login.example.com": parse "https://{login.example.com": invalid character "{" in host name`, configs.JWTLoginURLAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, containing invalid character", configs.JWTLoginURLAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTLoginURLAnnotation: "login.example.com",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf(`annotations.%s: Invalid value: "login.example.com": scheme required, please use the prefix http(s)://`, configs.JWTLoginURLAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, scheme missing", configs.JWTLoginURLAnnotation),
		},
		{
			annotations: map[string]string{
				configs.JWTLoginURLAnnotation: "http:",
			},
			specServices:          map[string]bool{},
			isPlus:                true,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				fmt.Sprintf(`annotations.%s: Invalid value: "http:": hostname required`, configs.JWTLoginURLAnnotation),
			},
			msg: fmt.Sprintf("invalid %s annotation, hostname missing", configs.JWTLoginURLAnnotation),
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
			},
			isPlus:                false,
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
			},
			isPlus:                false,
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

		// nginx.org/rewrite-target annotation tests
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/api/v1/$1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/rewrite-target annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/newpath",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/rewrite-target annotation, simple path",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/api/$1/$2/data",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/rewrite-target annotation, multiple capture groups",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrite-target: Required value`,
			},
			msg: "invalid nginx.org/rewrite-target annotation, empty value",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "http://example.com/path",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrite-target: Invalid value: "http://example.com/path": absolute URLs not allowed in rewrite target`,
			},
			msg: "invalid nginx.org/rewrite-target annotation, absolute HTTP URL",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "https://example.com/path",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrite-target: Invalid value: "https://example.com/path": absolute URLs not allowed in rewrite target`,
			},
			msg: "invalid nginx.org/rewrite-target annotation, absolute HTTPS URL",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "//example.com/path",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrite-target: Invalid value: "//example.com/path": protocol-relative URLs not allowed in rewrite target`,
			},
			msg: "invalid nginx.org/rewrite-target annotation, protocol-relative URL",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/api/../admin/users",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrite-target: Invalid value: "/api/../admin/users": path traversal patterns not allowed in rewrite target`,
			},
			msg: "invalid nginx.org/rewrite-target annotation, path traversal with ../",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/api/..\\admin/users",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrite-target: Invalid value: "/api/..\\admin/users": path traversal patterns not allowed in rewrite target`,
			},
			msg: "invalid nginx.org/rewrite-target annotation, path traversal with ..\\ (Windows style)",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/foo/$1; } path / { my/location/test/ }",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrite-target: Invalid value: "/foo/$1; } path / { my/location/test/ }": NGINX configuration syntax characters (;{}) and []|<>,^` + "`" + `~ not allowed in rewrite target`,
			},
			msg: "invalid nginx.org/rewrite-target annotation, NGINX configuration syntax characters (;{}) not allowed in rewrite target",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/api\npath",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrite-target: Invalid value: "/api\npath": control characters not allowed in rewrite target`,
			},
			msg: "invalid nginx.org/rewrite-target annotation, control characters not allowed in rewrite target",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "api/users",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/rewrite-target: Invalid value: "api/users": rewrite target must start with /`,
			},
			msg: "invalid nginx.org/rewrite-target annotation, does not start with slash",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/api/v1`; proxy_pass http://evil.com; #",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.org/rewrite-target: Invalid value: \"/api/v1`; proxy_pass http://evil.com; #\": NGINX configuration syntax characters (;{}) and []|<>,^`~ not allowed in rewrite target",
			},
			msg: "invalid nginx.org/rewrite-target annotation, backtick and semicolon injection",
		},
		{
			annotations: map[string]string{
				"nginx.org/rewrite-target": "/path/$1|/backup/$1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				"annotations.nginx.org/rewrite-target: Invalid value: \"/path/$1|/backup/$1\": NGINX configuration syntax characters (;{}) and []|<>,^`~ not allowed in rewrite target",
			},
			msg: "invalid nginx.org/rewrite-target annotation, pipe character for alternatives",
		},
		{
			annotations: map[string]string{
				"nginx.org/app-root": "/coffee",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/app-root annotation",
		},
		{
			annotations: map[string]string{
				"nginx.org/app-root": "/coffee/mocha",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors:        nil,
			msg:                   "valid nginx.org/app-root annotation with nested path",
		},
		{
			annotations: map[string]string{
				"nginx.org/app-root": "coffee",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/app-root: Invalid value: "coffee": must start with '/'`,
			},
			msg: "invalid nginx.org/app-root annotation, does not start with slash",
		},
		{
			annotations: map[string]string{
				"nginx.org/app-root": "/",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/app-root: Invalid value: "/": cannot be '/'`,
			},
			msg: "invalid nginx.org/app-root annotation, cannot be root path",
		},
		{
			annotations: map[string]string{
				"nginx.org/app-root": "/coffee/",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/app-root: Invalid value: "/coffee/": path should not end with '/'`,
			},
			msg: "invalid nginx.org/app-root annotation, cannot end with slash",
		},
		{
			annotations: map[string]string{
				"nginx.org/app-root": "/tea$1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/app-root: Invalid value: "/tea$1": path must not contain the following characters: whitespace, '{', '}', ';', '$', '|', '^', '<', '>', '\', '"', '#', '[', ']'`,
			},
			msg: "invalid nginx.org/app-root annotation, contains dollar sign",
		},
		{
			annotations: map[string]string{
				"nginx.org/app-root": "/tea~1",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/app-root: Invalid value: "/tea~1": path must not contain the '~' character`,
			},
			msg: "invalid nginx.org/app-root annotation, contains tilde",
		},
		{
			annotations: map[string]string{
				"nginx.org/app-root": "/coffee{test}",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/app-root: Invalid value: "/coffee{test}": path must not contain the following characters: whitespace, '{', '}', ';', '$', '|', '^', '<', '>', '\', '"', '#', '[', ']'`,
			},
			msg: "invalid app-root - contains curly braces",
		},
		{
			annotations: map[string]string{
				"nginx.org/app-root": "/tea;chai",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/app-root: Invalid value: "/tea;chai": path must not contain the following characters: whitespace, '{', '}', ';', '$', '|', '^', '<', '>', '\', '"', '#', '[', ']'`,
			},
			msg: "invalid app-root - contains semicolon",
		},
		{
			annotations: map[string]string{
				"nginx.org/app-root": "/tea chai",
			},
			specServices:          map[string]bool{},
			isPlus:                false,
			appProtectEnabled:     false,
			appProtectDosEnabled:  false,
			internalRoutesEnabled: false,
			expectedErrors: []string{
				`annotations.nginx.org/app-root: Invalid value: "/tea chai": path must not contain the following characters: whitespace, '{', '}', ';', '$', '|', '^', '<', '>', '\', '"', '#', '[', ']'`,
			},
			msg: "invalid app-root - contains whitespace",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			allErrs := validateIngressAnnotations(
				IngressOpts{
					isPlus:                test.isPlus,
					appProtectEnabled:     test.appProtectEnabled,
					appProtectDosEnabled:  test.appProtectDosEnabled,
					internalRoutesEnabled: test.internalRoutesEnabled,
					snippetsEnabled:       test.snippetsEnabled,
					directiveAutoAdjust:   test.directiveAutoAdjust,
				},
				test.annotations,
				test.specServices,
				field.NewPath("annotations"),
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
				"spec.rules: Too many: 2: must have at most 1 item",
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
				"spec.rules: Too many: 2: must have at most 1 item",
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

func TestValidatePolicyNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		value          string
		expectErrors   bool
		expectedErrMsg []string
	}{
		// Positive test cases - Simple policy names
		{
			name:         "valid single policy name",
			value:        "my-policy",
			expectErrors: false,
		},
		{
			name:         "valid policy with numbers",
			value:        "policy123",
			expectErrors: false,
		},
		{
			name:         "valid policy with hyphens",
			value:        "my-policy-name",
			expectErrors: false,
		},
		{
			name:         "valid policy with dots",
			value:        "policy.name.test",
			expectErrors: false,
		},
		{
			name:         "valid single character policy",
			value:        "a",
			expectErrors: false,
		},
		{
			name:         "valid policy starting with number",
			value:        "1policy",
			expectErrors: false,
		},

		// Positive test cases - Namespaced policies
		{
			name:         "valid namespaced policy",
			value:        "namespace/policy-name",
			expectErrors: false,
		},
		{
			name:         "valid namespaced policy with numbers",
			value:        "ns123/policy456",
			expectErrors: false,
		},
		{
			name:         "valid namespaced policy with dots",
			value:        "namespace.test/policy.example",
			expectErrors: false,
		},
		{
			name:         "valid single character namespace and policy",
			value:        "a/b",
			expectErrors: false,
		},
		{
			name:         "valid namespace and policy with numbers",
			value:        "1ns/2policy",
			expectErrors: false,
		},

		// Positive test cases - Multiple policies
		{
			name:         "valid multiple policies",
			value:        "policy1,policy2,policy3",
			expectErrors: false,
		},
		{
			name:         "valid multiple namespaced policies",
			value:        "ns1/policy1,ns2/policy2",
			expectErrors: false,
		},
		{
			name:         "valid mixed policies",
			value:        "policy1,ns1/policy2,policy3",
			expectErrors: false,
		},
		{
			name:         "valid policies with spaces around commas",
			value:        "policy1, policy2 , ns1/policy3",
			expectErrors: false,
		},
		{
			name:         "valid policies with tabs and newlines",
			value:        "policy1,\tpolicy2,\n ns1/policy3 ",
			expectErrors: false,
		},

		// Positive test cases - Edge cases within limits
		{
			name:         "maximum length policy name",
			value:        strings.Repeat("a", 63),
			expectErrors: false,
		},
		{
			name:         "maximum length namespace and policy",
			value:        strings.Repeat("a", 63) + "/" + strings.Repeat("b", 63),
			expectErrors: false,
		},
		{
			name:         "policy with maximum dot-separated labels",
			value:        "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z",
			expectErrors: false,
		},

		// Edge cases with multiple slashes (only first slash is significant)
		{
			name:           "policy name with additional slashes",
			value:          "namespace/policy/with/slashes",
			expectErrors:   true,                                                  // Only first slash is used for namespace/policy split
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"}, // The part after first slash is treated as policy name and fails validation
		},
		{
			name:           "multiple slashes in policy name",
			value:          "ns/policy//name",
			expectErrors:   true, // Everything after first slash is treated as policy name
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},

		// Negative test cases - Empty values
		{
			name:           "completely empty value",
			value:          "",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "empty policy in list",
			value:          "policy1,,policy2",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "only whitespace",
			value:          "   ",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "only tabs and newlines",
			value:          "\t\n\r  ",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "empty policy after comma",
			value:          "policy1,",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "empty policy before comma",
			value:          ",policy1",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "whitespace only policy in list",
			value:          "policy1,  ,policy2",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},

		// Negative test cases - Empty namespace or policy in namespaced format
		{
			name:           "empty namespace",
			value:          "/policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace cannot be empty"},
		},
		{
			name:           "empty policy name in namespaced policy",
			value:          "namespace/",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "both namespace and policy empty",
			value:          "/",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace cannot be empty", "policy name cannot be empty"},
		},
		{
			name:           "namespace with only whitespace",
			value:          "  /policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace cannot be empty"},
		},
		{
			name:           "policy with only whitespace after slash",
			value:          "namespace/  ",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},

		// Negative test cases - Invalid DNS subdomain names for policy
		{
			name:           "policy name with uppercase",
			value:          "PolicyName",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "policy name with underscore",
			value:          "policy_name",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "policy name starting with hyphen",
			value:          "-policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "policy name ending with hyphen",
			value:          "policy-",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "policy name starting with dot",
			value:          ".policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "policy name ending with dot",
			value:          "policy.",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "policy name with consecutive dots",
			value:          "policy..name",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:         "policy name too long",
			value:        strings.Repeat("a", 64),
			expectErrors: false,
		},
		{
			name:           "policy name with space",
			value:          "policy name",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "policy name with special characters",
			value:          "policy@name",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},

		// Negative test cases - Invalid namespace in namespaced policies
		{
			name:           "namespace with uppercase",
			value:          "NameSpace/policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain"},
		},
		{
			name:           "namespace with underscore",
			value:          "name_space/policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain"},
		},
		{
			name:           "namespace starting with hyphen",
			value:          "-namespace/policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain"},
		},
		{
			name:           "namespace ending with hyphen",
			value:          "namespace-/policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain"},
		},
		{
			name:           "namespace starting with dot",
			value:          ".namespace/policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain"},
		},
		{
			name:           "namespace ending with dot",
			value:          "namespace./policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain"},
		},
		{
			name:         "namespace too long",
			value:        strings.Repeat("a", 64) + "/policy",
			expectErrors: false,
		},
		{
			name:           "namespace with space",
			value:          "name space/policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain"},
		},
		{
			name:           "namespace with special characters",
			value:          "ns@test/policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain"},
		},

		// Negative test cases - Mixed valid and invalid
		{
			name:           "mix of valid and invalid policies",
			value:          "valid-policy,INVALID-POLICY,another-valid",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "valid namespace with invalid policy",
			value:          "valid-namespace/INVALID-POLICY",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "invalid namespace with valid policy",
			value:          "INVALID-NAMESPACE/valid-policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain"},
		},
		{
			name:           "both namespace and policy invalid",
			value:          "INVALID-NS/INVALID-POLICY",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain", "policy name must be a valid DNS subdomain"},
		},
		{
			name:           "multiple errors in list",
			value:          "valid-policy,,INVALID-CASE,/empty-ns,ns/",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty", "policy name must be a valid DNS subdomain", "policy namespace cannot be empty"},
		},

		// Negative test cases - Unicode and special characters
		{
			name:           "policy name with unicode characters",
			value:          "policyñame",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "policy name with emoji",
			value:          "policy🚀name",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "policy name with chinese characters",
			value:          "policy中文",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name must be a valid DNS subdomain"},
		},
		{
			name:           "namespace with unicode",
			value:          "nameспейс/policy",
			expectErrors:   true,
			expectedErrMsg: []string{"policy namespace must be a valid DNS subdomain"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := &annotationValidationContext{
				value:     tt.value,
				fieldPath: field.NewPath("test"),
			}

			errors := validatePolicyNames(context)

			if tt.expectErrors {
				if len(errors) == 0 {
					t.Errorf("Expected validation errors for %q, but got none", tt.value)
					return
				}

				// Check that each expected error message appears in at least one error
				for _, expectedMsg := range tt.expectedErrMsg {
					found := false
					for _, err := range errors {
						if strings.Contains(err.Detail, expectedMsg) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error message %q not found in errors: %v", expectedMsg, errors)
					}
				}
			} else {
				if len(errors) > 0 {
					t.Errorf("Expected no validation errors for %q, but got: %v", tt.value, errors)
				}
			}
		})
	}
}

// TestValidatePolicyNamesFuzzing tests the function with generated fuzzy inputs
func TestValidatePolicyNamesFuzzing(t *testing.T) {
	t.Parallel()

	// Generate fuzzy test inputs
	fuzzyInputs := []string{
		// Random special characters
		"policy!@#$%^&*()",
		"policy[]{};':\"<>?",
		"policy~`|\\+=",
		"policy/name!@#",
		"ns@#$/policy",

		// Mixed valid and invalid characters
		"valid-policy,invalid!policy",
		"ns1/policy1,ns@2/policy2",
		"good,bad_name,ugly-CASE",

		// Boundary length cases
		"a",                      // Minimum length
		strings.Repeat("a", 63),  // DNS label max length
		strings.Repeat("a", 64),  // Over DNS label max length (should fail)
		strings.Repeat("a", 100), // Way over limit
		strings.Repeat("a", 253), // Very long

		// Various whitespace combinations
		" policy ",
		"  policy1  ,  policy2  ",
		"\tpolicy\t",
		"\npolicy\n",
		"\rpolicy\r",
		"\f\vpolicy\b",

		// Empty and whitespace variations
		",",
		" , ",
		",,",
		" ,, ",
		"   ,   ",
		"\t,\n",

		// Slash variations
		"/",
		"//",
		"///",
		"a/",
		"/a",
		"a//b",
		"a/b/",
		"/a/b",
		"a/b/c/d/e",
		"//a//b//",
		"namespace///policy",

		// Dot variations
		".",
		"..",
		"...",
		"a.",
		".a",
		"a..b",
		"a.b.",
		".a.b",
		"ns./pol.icy",
		".ns/.pol",

		// Hyphen variations
		"-",
		"--",
		"a-",
		"-a",
		"a--b",
		"-ns/-pol",
		"ns-/pol-",

		// Number variations
		"123",
		"123abc",
		"abc123",
		"1a2b3c",
		"123/456",
		"0/0",

		// Case variations
		"POLICY",
		"Policy",
		"pOlIcY",
		"NAMESPACE/POLICY",
		"Namespace/Policy",
		"CamelCase/kebab-case",

		// Unicode and non-ASCII
		"policyé",
		"policy™",
		"policy中文",
		"policy🚀",
		"пространство/политика",
		"名前空間/ポリシー",
		"네임스페이스/정책",

		// Control characters
		"policy\x00name",
		"policy\x01name",
		"policy\x1fname",
		"policy\x7fname",
		"ns\x00/policy\x01",

		// Very long strings with various separators
		strings.Repeat("very-long-policy-name-", 10),
		strings.Repeat("a", 500) + "/" + strings.Repeat("b", 500),
		strings.Repeat("ns,", 100) + "policy",
		strings.Join(make([]string, 1000), "policy,") + "final",

		// Mixed chaos
		"valid,INVALID_case,good-one,/empty-ns,ns/,123_bad,valid.policy,ns.good/policy.name",
		"😀/🚀,valid-ns/good-policy,bad ns/policy,ns/bad policy",
		strings.Repeat("a.", 50) + "/" + strings.Repeat("b-", 50),

		// Edge cases around validation
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63), // Max length with dot
		"a" + strings.Repeat("-a", 31),                          // Alternating pattern
		strings.Repeat("1", 63) + "/" + strings.Repeat("2", 63), // All numbers

		// Pathological cases
		string(make([]byte, 1000)),          // Null bytes
		strings.Repeat("\x00\x01\x02", 100), // Control characters
		strings.Repeat("../", 100),          // Path traversal
		strings.Repeat("a/", 100),           // Many slashes
	}

	for i, input := range fuzzyInputs {
		t.Run(fmt.Sprintf("fuzzy_test_%d", i), func(t *testing.T) {
			context := &annotationValidationContext{
				value:     input,
				fieldPath: field.NewPath("fuzzy"),
			}

			// Just ensure the function doesn't panic and returns something
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Function panicked with input %q: %v", input, r)
					}
				}()

				errors := validatePolicyNames(context)

				// For fuzzy testing, we mainly care about:
				// 1. No panics
				// 2. Function returns (even if with errors)
				// 3. Errors are properly formed if they exist
				for _, err := range errors {
					if err.Field == "" {
						t.Errorf("Error missing field path for input %q: %v", input, err)
					}
					if err.Detail == "" {
						t.Errorf("Error missing detail for input %q: %v", input, err)
					}
				}
			}()
		})
	}
}

// TestValidatePolicyNamesEdgeCases tests specific edge cases and boundary conditions
func TestValidatePolicyNamesEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		value        string
		expectErrors bool
		description  string
	}{
		{
			name:         "single character policy",
			value:        "a",
			expectErrors: false,
			description:  "Single character should be valid",
		},
		{
			name:         "single character namespace and policy",
			value:        "a/b",
			expectErrors: false,
			description:  "Single character namespace and policy should be valid",
		},
		{
			name:         "maximum length valid policy",
			value:        strings.Repeat("a", 63),
			expectErrors: false,
			description:  "63 character policy name should be valid (DNS label max)",
		},
		{
			name:         "over maximum length policy",
			value:        strings.Repeat("a", 254),
			expectErrors: true,
			description:  "253+ character policy name should be invalid",
		},
		{
			name:         "policy with all valid DNS chars",
			value:        "policy-123.test",
			expectErrors: false,
			description:  "Policy with hyphens, numbers, and dots should be valid",
		},
		{
			name:         "namespaced policy with all valid DNS chars",
			value:        "namespace-123.test/policy-456.example",
			expectErrors: false,
			description:  "Namespaced policy with valid DNS chars should work",
		},
		{
			name:         "policy name that looks like IP but is valid DNS",
			value:        "policy.1.2.3",
			expectErrors: false,
			description:  "DNS subdomain that looks like IP should be valid",
		},
		{
			name:         "namespace and policy both at max length",
			value:        strings.Repeat("a", 253) + "/" + strings.Repeat("b", 253),
			expectErrors: false,
			description:  "Both namespace and policy at max length should be valid",
		},
		{
			name:         "deeply nested path treated as single policy name",
			value:        "ns/very/deep/nested/path/policy",
			expectErrors: true,
			description:  "Only first slash matters, rest is part of policy name",
		},
		{
			name:         "policy with all numbers",
			value:        "123456789",
			expectErrors: false,
			description:  "All numeric policy names should be valid",
		},
		{
			name:         "namespace and policy with all numbers",
			value:        "123/456",
			expectErrors: false,
			description:  "All numeric namespace and policy should be valid",
		},
		{
			name:         "policy starting with number and containing letters",
			value:        "1abc.2def-3ghi",
			expectErrors: false,
			description:  "Policy starting with number should be valid",
		},
		{
			name:         "many dot-separated segments",
			value:        strings.Repeat("a.", 20) + "policy",
			expectErrors: false,
			description:  "Many dot-separated segments should be valid if within length limits",
		},
		{
			name:         "policy name exactly at boundary with dots",
			value:        "a." + strings.Repeat("b", 251),
			expectErrors: false,
			description:  "Policy at exactly 253 chars with dot should be valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := &annotationValidationContext{
				value:     tt.value,
				fieldPath: field.NewPath("edge_case"),
			}

			errors := validatePolicyNames(context)

			if tt.expectErrors && len(errors) == 0 {
				t.Errorf("%s: Expected errors but got none for input %q", tt.description, tt.value)
			}
			if !tt.expectErrors && len(errors) > 0 {
				t.Errorf("%s: Expected no errors but got %v for input %q", tt.description, errors, tt.value)
			}
		})
	}
}

// TestValidatePolicyNamesCommaHandling tests specific comma and whitespace handling
func TestValidatePolicyNamesCommaHandling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		value          string
		expectErrors   bool
		expectedErrMsg []string
	}{
		{
			name:         "no commas single policy",
			value:        "simple-policy",
			expectErrors: false,
		},
		{
			name:         "two policies with comma",
			value:        "policy1,policy2",
			expectErrors: false,
		},
		{
			name:         "policies with spaces around comma",
			value:        "policy1 , policy2",
			expectErrors: false,
		},
		{
			name:         "policies with tabs and spaces",
			value:        "policy1\t,\t policy2 ",
			expectErrors: false,
		},
		{
			name:         "policies with various whitespace",
			value:        " policy1 \t, \n policy2 \r ",
			expectErrors: false,
		},
		{
			name:           "empty policy between commas",
			value:          "policy1,,policy2",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "trailing comma",
			value:          "policy1,policy2,",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "leading comma",
			value:          ",policy1,policy2",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "only commas",
			value:          ",,,",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "whitespace between commas",
			value:          "policy1,  ,policy2",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:           "tabs between commas",
			value:          "policy1,\t\t,policy2",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
		{
			name:         "many valid policies",
			value:        "p1,p2,p3,p4,p5,ns1/p6,ns2/p7,p8,p9,p10",
			expectErrors: false,
		},
		{
			name:         "many valid policies with whitespace",
			value:        " p1 , p2 , p3 , ns1/p4 , ns2/p5 ",
			expectErrors: false,
		},
		{
			name:           "mixed valid and empty policies",
			value:          "valid1,,valid2,,valid3",
			expectErrors:   true,
			expectedErrMsg: []string{"policy name cannot be empty"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := &annotationValidationContext{
				value:     tt.value,
				fieldPath: field.NewPath("comma_test"),
			}

			errors := validatePolicyNames(context)

			if tt.expectErrors {
				if len(errors) == 0 {
					t.Errorf("Expected validation errors for %q, but got none", tt.value)
					return
				}

				for _, expectedMsg := range tt.expectedErrMsg {
					found := false
					for _, err := range errors {
						if strings.Contains(err.Detail, expectedMsg) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error message %q not found in errors: %v", expectedMsg, errors)
					}
				}
			} else {
				if len(errors) > 0 {
					t.Errorf("Expected no validation errors for %q, but got: %v", tt.value, errors)
				}
			}
		})
	}
}

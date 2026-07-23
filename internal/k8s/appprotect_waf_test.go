package k8s

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/k8s/appprotect"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestAddWAFPolicyRefs(t *testing.T) {
	t.Parallel()
	apPol := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "default",
				"name":      "ap-pol",
			},
		},
	}

	logConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "default",
				"name":      "log-conf",
			},
		},
	}

	additionalLogConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "default",
				"name":      "additional-log-conf",
			},
		},
	}

	tests := []struct {
		policies            []*conf_v1.Policy
		expectedApPolRefs   map[string]*unstructured.Unstructured
		expectedLogConfRefs map[string]*unstructured.Unstructured
		wantErr             bool
		msg                 string
	}{
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "waf-pol",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApPolicy: "default/ap-pol",
							SecurityLog: &conf_v1.SecurityLog{
								Enable:    true,
								ApLogConf: "log-conf",
							},
						},
					},
				},
			},
			expectedApPolRefs: map[string]*unstructured.Unstructured{
				"default/ap-pol": apPol,
			},
			expectedLogConfRefs: map[string]*unstructured.Unstructured{
				"default/log-conf": logConf,
			},
			wantErr: false,
			msg:     "base test",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "waf-pol",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApPolicy: "non-existing-ap-pol",
						},
					},
				},
			},
			wantErr:             true,
			expectedApPolRefs:   make(map[string]*unstructured.Unstructured),
			expectedLogConfRefs: make(map[string]*unstructured.Unstructured),
			msg:                 "apPol doesn't exist",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "waf-pol",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApPolicy: "ap-pol",
							SecurityLog: &conf_v1.SecurityLog{
								Enable:    true,
								ApLogConf: "non-existing-log-conf",
							},
						},
					},
				},
			},
			wantErr: true,
			expectedApPolRefs: map[string]*unstructured.Unstructured{
				"default/ap-pol": apPol,
			},
			expectedLogConfRefs: make(map[string]*unstructured.Unstructured),
			msg:                 "logConf doesn't exist",
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "waf-pol",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApPolicy: "ap-pol",
							SecurityLogs: []*conf_v1.SecurityLog{
								{
									Enable:    true,
									ApLogConf: "log-conf",
								},
							},
						},
					},
				},
			},
			wantErr: false,
			expectedApPolRefs: map[string]*unstructured.Unstructured{
				"default/ap-pol": apPol,
			},
			expectedLogConfRefs: map[string]*unstructured.Unstructured{
				"default/log-conf": logConf,
			},
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "waf-pol",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApPolicy: "ap-pol",
							SecurityLogs: []*conf_v1.SecurityLog{
								{
									Enable:    true,
									ApLogConf: "log-conf",
								},
								{
									Enable:    true,
									ApLogConf: "additional-log-conf",
								},
							},
						},
					},
				},
			},
			wantErr: false,
			expectedApPolRefs: map[string]*unstructured.Unstructured{
				"default/ap-pol": apPol,
			},
			expectedLogConfRefs: map[string]*unstructured.Unstructured{
				"default/log-conf":            logConf,
				"default/additional-log-conf": additionalLogConf,
			},
		},
		{
			policies: []*conf_v1.Policy{
				{
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "waf-pol",
						Namespace: "default",
					},
					Spec: conf_v1.PolicySpec{
						WAF: &conf_v1.WAF{
							Enable:   true,
							ApPolicy: "ap-pol",
							SecurityLog: &conf_v1.SecurityLog{
								Enable:    true,
								ApLogConf: "additional-log-conf",
							},
							SecurityLogs: []*conf_v1.SecurityLog{
								{
									Enable:    true,
									ApLogConf: "log-conf",
								},
							},
						},
					},
				},
			},
			wantErr: false,
			expectedApPolRefs: map[string]*unstructured.Unstructured{
				"default/ap-pol": apPol,
			},
			expectedLogConfRefs: map[string]*unstructured.Unstructured{
				"default/log-conf": logConf,
			},
		},
	}

	lbc := LoadBalancerController{
		appProtectConfiguration: appprotect.NewFakeConfiguration(),
	}
	lbc.appProtectConfiguration.AddOrUpdatePolicy(apPol)
	lbc.appProtectConfiguration.AddOrUpdateLogConf(logConf)
	lbc.appProtectConfiguration.AddOrUpdateLogConf(additionalLogConf)

	for _, test := range tests {
		resApPolicy := make(map[string]*unstructured.Unstructured)
		resLogConf := make(map[string]*unstructured.Unstructured)

		if err := lbc.addWAFPolicyRefs(resApPolicy, resLogConf, test.policies); (err != nil) != test.wantErr {
			t.Errorf("LoadBalancerController.addWAFPolicyRefs() error = %v, wantErr %v", err, test.wantErr)
		}
		if diff := cmp.Diff(test.expectedApPolRefs, resApPolicy); diff != "" {
			t.Errorf("LoadBalancerController.addWAFPolicyRefs() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedLogConfRefs, resLogConf); diff != "" {
			t.Errorf("LoadBalancerController.addWAFPolicyRefs() '%v' mismatch (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetWAFPoliciesForAppProtectPolicy(t *testing.T) {
	t.Parallel()
	apPol := &conf_v1.Policy{
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable:   true,
				ApPolicy: "ns1/apPol",
			},
		},
	}

	apPolNs2 := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: "ns1",
		},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable:   true,
				ApPolicy: "ns2/apPol",
			},
		},
	}

	apPolNoNs := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable:   true,
				ApPolicy: "apPol",
			},
		},
	}

	policies := []*conf_v1.Policy{
		apPol, apPolNs2, apPolNoNs,
	}

	tests := []struct {
		pols []*conf_v1.Policy
		key  string
		want []*conf_v1.Policy
		msg  string
	}{
		{
			pols: policies,
			key:  "ns1/apPol",
			want: []*conf_v1.Policy{apPol},
			msg:  "WAF pols that ref apPol which has a namespace",
		},
		{
			pols: policies,
			key:  "default/apPol",
			want: []*conf_v1.Policy{apPolNoNs},
			msg:  "WAF pols that ref apPol which has no namespace",
		},
		{
			pols: policies,
			key:  "ns2/apPol",
			want: []*conf_v1.Policy{apPolNs2},
			msg:  "WAF pols that ref apPol which is in another ns",
		},
		{
			pols: policies,
			key:  "ns1/apPol-with-no-valid-refs",
			want: nil,
			msg:  "WAF pols where there is no valid ref",
		},
	}
	for _, test := range tests {
		got := getWAFPoliciesForAppProtectPolicy(test.pols, test.key)
		if diff := cmp.Diff(test.want, got); diff != "" {
			t.Errorf("getWAFPoliciesForAppProtectPolicy() returned unexpected result for the case of: %v (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetWAFPoliciesForAppProtectLogConf(t *testing.T) {
	t.Parallel()
	logConf := &conf_v1.Policy{
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				SecurityLog: &conf_v1.SecurityLog{
					Enable:    true,
					ApLogConf: "ns1/logConf",
				},
			},
		},
	}

	logConfs := &conf_v1.Policy{
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				SecurityLogs: []*conf_v1.SecurityLog{
					{
						Enable:    true,
						ApLogConf: "ns1/logConfs",
					},
				},
			},
		},
	}

	logConfNs2 := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: "ns1",
		},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				SecurityLog: &conf_v1.SecurityLog{
					Enable:    true,
					ApLogConf: "ns2/logConf",
				},
			},
		},
	}

	logConfNoNs := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: "default",
		},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				SecurityLog: &conf_v1.SecurityLog{
					Enable:    true,
					ApLogConf: "logConf",
				},
			},
		},
	}

	policies := []*conf_v1.Policy{
		logConf, logConfs, logConfNs2, logConfNoNs,
	}

	tests := []struct {
		pols []*conf_v1.Policy
		key  string
		want []*conf_v1.Policy
		msg  string
	}{
		{
			pols: policies,
			key:  "ns1/logConf",
			want: []*conf_v1.Policy{logConf},
			msg:  "WAF pols that ref logConf which has a namespace",
		},
		{
			pols: policies,
			key:  "default/logConf",
			want: []*conf_v1.Policy{logConfNoNs},
			msg:  "WAF pols that ref logConf which has no namespace",
		},
		{
			pols: policies,
			key:  "ns1/logConfs",
			want: []*conf_v1.Policy{logConfs},
			msg:  "WAF pols that ref logConf via logConfs field",
		},
		{
			pols: policies,
			key:  "ns2/logConf",
			want: []*conf_v1.Policy{logConfNs2},
			msg:  "WAF pols that ref logConf which is in another ns",
		},
		{
			pols: policies,
			key:  "ns1/logConf-with-no-valid-refs",
			want: nil,
			msg:  "WAF pols where there is no valid logConf ref",
		},
	}
	for _, test := range tests {
		got := getWAFPoliciesForAppProtectLogConf(test.pols, test.key)
		if diff := cmp.Diff(test.want, got); diff != "" {
			t.Errorf("getWAFPoliciesForAppProtectLogConf() returned unexpected result for the case of: %v (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetPLMPoliciesForAppProtectPolicy(t *testing.T) {
	t.Parallel()

	// PLM source with an explicit namespace on the ref.
	plmExplicitNs := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "apps"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				ApBundleSource: &conf_v1.BundleSource{
					Type:            conf_v1.BundleSourceTypePLM,
					PolicyName:      "ap-pol",
					PolicyNamespace: "plm-policies",
				},
			},
		},
	}

	// PLM source without a namespace on the ref; defaults to the Policy's own namespace.
	plmDefaultNs := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "apps"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				ApBundleSource: &conf_v1.BundleSource{
					Type:       conf_v1.BundleSourceTypePLM,
					PolicyName: "ap-pol",
				},
			},
		},
	}

	// HTTPS source must never match a PLM key.
	httpsSource := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "apps"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				ApBundleSource: &conf_v1.BundleSource{
					Type: conf_v1.BundleSourceTypeHTTPS,
					URL:  "https://example.com/ap-pol.tgz",
				},
			},
		},
	}

	// No WAF at all.
	noWAF := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "apps"},
		Spec:       conf_v1.PolicySpec{},
	}

	policies := []*conf_v1.Policy{plmExplicitNs, plmDefaultNs, httpsSource, noWAF}

	tests := []struct {
		key  string
		want []*conf_v1.Policy
		msg  string
	}{
		{
			key:  "plm-policies/ap-pol",
			want: []*conf_v1.Policy{plmExplicitNs},
			msg:  "matches PLM source with explicit ref namespace",
		},
		{
			key:  "apps/ap-pol",
			want: []*conf_v1.Policy{plmDefaultNs},
			msg:  "matches PLM source defaulting to owner namespace",
		},
		{
			key:  "plm-policies/other-pol",
			want: nil,
			msg:  "no PLM source references this key",
		},
	}
	for _, test := range tests {
		got := getPLMPoliciesForAppProtectPolicy(policies, test.key)
		if diff := cmp.Diff(test.want, got); diff != "" {
			t.Errorf("getPLMPoliciesForAppProtectPolicy() %v (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetPLMPoliciesForAppProtectLogConf(t *testing.T) {
	t.Parallel()

	// PLM log source with explicit namespace.
	plmLogExplicitNs := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "apps"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				SecurityLogs: []*conf_v1.SecurityLog{
					{
						Enable: true,
						ApLogBundleSource: &conf_v1.BundleSource{
							Type:            conf_v1.BundleSourceTypePLM,
							PolicyName:      "log-conf",
							PolicyNamespace: "plm-policies",
						},
					},
				},
			},
		},
	}

	// PLM log source without a namespace; defaults to the Policy's own namespace.
	plmLogDefaultNs := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "apps"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				SecurityLogs: []*conf_v1.SecurityLog{
					{
						Enable: true,
						ApLogBundleSource: &conf_v1.BundleSource{
							Type:       conf_v1.BundleSourceTypePLM,
							PolicyName: "log-conf",
						},
					},
				},
			},
		},
	}

	// Non-PLM log source must never match a PLM key.
	nimLog := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "apps"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				SecurityLogs: []*conf_v1.SecurityLog{
					{
						Enable: true,
						ApLogBundleSource: &conf_v1.BundleSource{
							Type:       conf_v1.BundleSourceTypeNIM,
							URL:        "https://nim.example.com",
							PolicyName: "log-conf",
						},
					},
				},
			},
		},
	}

	policies := []*conf_v1.Policy{plmLogExplicitNs, plmLogDefaultNs, nimLog}

	tests := []struct {
		key  string
		want []*conf_v1.Policy
		msg  string
	}{
		{
			key:  "plm-policies/log-conf",
			want: []*conf_v1.Policy{plmLogExplicitNs},
			msg:  "matches PLM log source with explicit ref namespace",
		},
		{
			key:  "apps/log-conf",
			want: []*conf_v1.Policy{plmLogDefaultNs},
			msg:  "matches PLM log source defaulting to owner namespace",
		},
		{
			key:  "plm-policies/missing",
			want: nil,
			msg:  "no PLM log source references this key",
		},
	}
	for _, test := range tests {
		got := getPLMPoliciesForAppProtectLogConf(policies, test.key)
		if diff := cmp.Diff(test.want, got); diff != "" {
			t.Errorf("getPLMPoliciesForAppProtectLogConf() %v (-want +got):\n%s", test.msg, diff)
		}
	}
}

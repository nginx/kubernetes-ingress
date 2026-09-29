package k8s

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/wafbundle"
	"github.com/nginx/kubernetes-ingress/internal/k8s/appprotect"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

// TestAppProtectSyncNamespaceNotWatched guards against a nil pointer dereference
// panic (see getNamespacedInformer) when an AppProtect-related task for a namespace
// that is no longer watched (e.g. its watch-namespace-label was removed) is processed.
func TestAppProtectSyncNamespaceNotWatched(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sync func(lbc *LoadBalancerController, key string)
	}{
		{
			name: "AppProtectPolicy",
			sync: func(lbc *LoadBalancerController, key string) {
				lbc.syncAppProtectPolicy(task{Kind: appProtectPolicy, Key: key})
			},
		},
		{
			name: "AppProtectLogConf",
			sync: func(lbc *LoadBalancerController, key string) {
				lbc.syncAppProtectLogConf(task{Kind: appProtectLogConf, Key: key})
			},
		},
		{
			name: "AppProtectUserSig",
			sync: func(lbc *LoadBalancerController, key string) {
				lbc.syncAppProtectUserSig(task{Kind: appProtectUserSig, Key: key})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(_ *testing.T) {
			lbc := &LoadBalancerController{
				namespacedInformers: map[string]*namespacedInformer{},
				Logger:              nl.LoggerFromContext(context.Background()),
			}
			tc.sync(lbc, "not-watched/some-resource")
		})
	}
}

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

// apPolicy/apLogConf references resolve to PLM bundles rather than in-pod AP resources,
// so addWAFPolicyRefs must accept them and collect nothing.
func TestAddWAFPolicyRefs_PLMAcceptsAPRefs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		waf  *conf_v1.WAF
	}{
		{
			name: "apPolicy",
			waf:  &conf_v1.WAF{ApPolicy: "raw-policy"},
		},
		{
			name: "deprecated security log apLogConf",
			waf:  &conf_v1.WAF{SecurityLog: &conf_v1.SecurityLog{ApLogConf: "raw-log"}},
		},
		{
			name: "security logs apLogConf",
			waf:  &conf_v1.WAF{SecurityLogs: []*conf_v1.SecurityLog{{ApLogConf: "raw-log"}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lbc := LoadBalancerController{plmEnabled: true}
			policies := []*conf_v1.Policy{{
				ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "waf-policy"},
				Spec:       conf_v1.PolicySpec{WAF: tc.waf},
			}}

			apPolRefs := map[string]*unstructured.Unstructured{}
			logConfRefs := map[string]*unstructured.Unstructured{}
			if err := lbc.addWAFPolicyRefs(apPolRefs, logConfRefs, policies); err != nil {
				t.Errorf("addWAFPolicyRefs() unexpected error = %v", err)
			}
			if len(apPolRefs) != 0 || len(logConfRefs) != 0 {
				t.Errorf("addWAFPolicyRefs() collected refs %v / %v, want none", apPolRefs, logConfRefs)
			}
		})
	}
}

func TestEffectivePLMPolicyRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		plmEnabled    bool
		waf           *conf_v1.WAF
		wantOK        bool
		wantName      string
		wantNamespace string
	}{
		{
			name:       "plm off leaves apPolicy unresolved",
			plmEnabled: false,
			waf:        &conf_v1.WAF{ApPolicy: "default/dataguard-alarm"},
			wantOK:     false,
		},
		{
			name:          "qualified apPolicy keeps its namespace",
			plmEnabled:    true,
			waf:           &conf_v1.WAF{ApPolicy: "plm-ns/dataguard-alarm"},
			wantOK:        true,
			wantName:      "dataguard-alarm",
			wantNamespace: "plm-ns",
		},
		{
			name:          "bare apPolicy defaults to the policy namespace",
			plmEnabled:    true,
			waf:           &conf_v1.WAF{ApPolicy: "dataguard-alarm"},
			wantOK:        true,
			wantName:      "dataguard-alarm",
			wantNamespace: "default",
		},
		{
			name:       "no apPolicy set",
			plmEnabled: true,
			waf:        &conf_v1.WAF{},
			wantOK:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lbc := &LoadBalancerController{plmEnabled: tc.plmEnabled}
			pol := &conf_v1.Policy{
				ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "waf-policy"},
				Spec:       conf_v1.PolicySpec{WAF: tc.waf},
			}

			ns, name, ok := lbc.effectivePLMPolicyRef(pol)
			if ok != tc.wantOK {
				t.Fatalf("effectivePLMPolicyRef() ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if name != tc.wantName {
				t.Errorf("Name = %q, want %q", name, tc.wantName)
			}
			if ns != tc.wantNamespace {
				t.Errorf("Namespace = %q, want %q", ns, tc.wantNamespace)
			}
		})
	}
}

func TestEffectivePLMLogRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		plmEnabled    bool
		securityLog   *conf_v1.SecurityLog
		wantOK        bool
		wantName      string
		wantNamespace string
	}{
		{
			name:        "nil security log",
			plmEnabled:  true,
			securityLog: nil,
			wantOK:      false,
		},
		{
			name:        "plm off leaves apLogConf unresolved",
			plmEnabled:  false,
			securityLog: &conf_v1.SecurityLog{ApLogConf: "default/logconf"},
			wantOK:      false,
		},
		{
			name:          "bare apLogConf defaults to the policy namespace",
			plmEnabled:    true,
			securityLog:   &conf_v1.SecurityLog{ApLogConf: "logconf"},
			wantOK:        true,
			wantName:      "logconf",
			wantNamespace: "default",
		},
		{
			name:          "qualified apLogConf keeps its namespace",
			plmEnabled:    true,
			securityLog:   &conf_v1.SecurityLog{ApLogConf: "plm-ns/logconf"},
			wantOK:        true,
			wantName:      "logconf",
			wantNamespace: "plm-ns",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lbc := &LoadBalancerController{plmEnabled: tc.plmEnabled}

			ns, name, ok := lbc.effectivePLMLogRef(tc.securityLog, "default")
			if ok != tc.wantOK {
				t.Fatalf("effectivePLMLogRef() ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if name != tc.wantName {
				t.Errorf("Name = %q, want %q", name, tc.wantName)
			}
			if ns != tc.wantNamespace {
				t.Errorf("Namespace = %q, want %q", ns, tc.wantNamespace)
			}
		})
	}
}

// An apPolicy reference must re-enqueue its Policy on APPolicy status changes, otherwise
// PLM bundle updates would never reach a policy still using that field.
func TestGetPLMPoliciesForAppProtectPolicy_APPolicyRef(t *testing.T) {
	t.Parallel()

	apPolicyPol := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "waf-policy"},
		Spec:       conf_v1.PolicySpec{WAF: &conf_v1.WAF{ApPolicy: "dataguard-alarm"}},
	}
	policies := []*conf_v1.Policy{apPolicyPol}

	lbcOn := &LoadBalancerController{plmEnabled: true}
	if got := lbcOn.getPLMPoliciesForAppProtectPolicy(policies, "default/dataguard-alarm"); len(got) != 1 {
		t.Errorf("with PLM enabled got %d policies, want 1", len(got))
	}

	lbcOff := &LoadBalancerController{plmEnabled: false}
	if got := lbcOff.getPLMPoliciesForAppProtectPolicy(policies, "default/dataguard-alarm"); got != nil {
		t.Errorf("with PLM disabled got %v, want nil", got)
	}
}

func TestResolvePLMBundleStatus_ReadsInformerStore(t *testing.T) {
	t.Parallel()

	apPolicy := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"namespace": "plm", "name": "compiled-policy"},
		"status": map[string]interface{}{
			"bundle": map[string]interface{}{
				"state":    wafbundle.BundleStateReady,
				"location": "s3://plm/bundles/compiled-policy.tgz",
				"sha256":   "0123456789abcdef",
			},
		},
	}}
	apPolicy.SetKind(appprotect.PolicyGVK.Kind)

	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := store.Add(apPolicy); err != nil {
		t.Fatalf("failed to add APPolicy to informer store: %v", err)
	}
	lbc := &LoadBalancerController{
		Logger: nl.LoggerFromContext(context.Background()),
		namespacedInformers: map[string]*namespacedInformer{
			"": {appProtectPolicyLister: store},
		},
	}
	pol := &conf_v1.Policy{ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "waf-policy"}}

	got := lbc.resolvePLMBundleStatus(pol, "plm", "compiled-policy", wafbundle.PolicyBundle)
	if got == nil {
		t.Fatal("resolvePLMBundleStatus() = nil, want ready bundle status")
	}
	if got.Location != "s3://plm/bundles/compiled-policy.tgz" || got.SHA256 != "0123456789abcdef" {
		t.Errorf("resolvePLMBundleStatus() = %#v, want informer status bundle", got)
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

	// PLM source with an explicit namespace on the apPolicy ref.
	plmExplicitNs := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "apps"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable:   true,
				ApPolicy: "plm-policies/ap-pol",
			},
		},
	}

	// PLM source without a namespace; defaults to the Policy's own namespace.
	plmDefaultNs := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "apps"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable:   true,
				ApPolicy: "ap-pol",
			},
		},
	}

	// HTTPS apBundleSource must never match a PLM key.
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
	lbc := &LoadBalancerController{plmEnabled: true}
	for _, test := range tests {
		got := lbc.getPLMPoliciesForAppProtectPolicy(policies, test.key)
		if diff := cmp.Diff(test.want, got); diff != "" {
			t.Errorf("getPLMPoliciesForAppProtectPolicy() %v (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetPLMPoliciesForAppProtectLogConf(t *testing.T) {
	t.Parallel()

	// PLM log source with explicit namespace on the apLogConf ref.
	plmLogExplicitNs := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "apps"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{
				Enable: true,
				SecurityLogs: []*conf_v1.SecurityLog{
					{
						Enable:    true,
						ApLogConf: "plm-policies/log-conf",
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
						Enable:    true,
						ApLogConf: "log-conf",
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
							Type: conf_v1.BundleSourceTypeNIM,
							URL:  "https://nim.example.com",
							Name: "log-conf",
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
	lbc := &LoadBalancerController{plmEnabled: true}
	for _, test := range tests {
		got := lbc.getPLMPoliciesForAppProtectLogConf(policies, test.key)
		if diff := cmp.Diff(test.want, got); diff != "" {
			t.Errorf("getPLMPoliciesForAppProtectLogConf() %v (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetPoliciesUsingPLMStorage(t *testing.T) {
	t.Parallel()

	plmPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "plm-policy"},
		Spec:       conf_v1.PolicySpec{WAF: &conf_v1.WAF{ApPolicy: "dataguard-alarm"}},
	}
	plmLog := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "plm-log"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{SecurityLogs: []*conf_v1.SecurityLog{{ApLogConf: "logconf"}}},
		},
	}
	nimPolicy := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "nim-policy"},
		Spec: conf_v1.PolicySpec{
			WAF: &conf_v1.WAF{ApBundleSource: &conf_v1.BundleSource{Type: conf_v1.BundleSourceTypeNIM}},
		},
	}
	noWAF := &conf_v1.Policy{ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "no-waf"}}

	lbc := &LoadBalancerController{plmEnabled: true}
	got := lbc.getPoliciesUsingPLMStorage([]*conf_v1.Policy{plmPolicy, plmLog, nimPolicy, noWAF})
	want := []*conf_v1.Policy{plmPolicy, plmLog}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("getPoliciesUsingPLMStorage() (-want +got):\n%s", diff)
	}
}

func TestPolicyNeedsPLMBundleFetch(t *testing.T) {
	t.Parallel()

	bundle := []byte("compiled-policy")
	checksum := wafbundle.ComputeChecksum(bundle)
	apPolicy := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"namespace": "plm", "name": "compiled-policy"},
		"status": map[string]interface{}{"bundle": map[string]interface{}{
			"state":    wafbundle.BundleStateReady,
			"location": "s3://plm/bundles/compiled-policy.tgz",
			"sha256":   checksum,
		}},
	}}
	apPolicy.SetKind(appprotect.PolicyGVK.Kind)
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := store.Add(apPolicy); err != nil {
		t.Fatalf("failed to add APPolicy to informer store: %v", err)
	}

	dir := t.TempDir()
	pol := &conf_v1.Policy{
		ObjectMeta: meta_v1.ObjectMeta{Namespace: "default", Name: "waf-policy"},
		Spec:       conf_v1.PolicySpec{WAF: &conf_v1.WAF{ApPolicy: "plm/compiled-policy"}},
	}
	lbc := &LoadBalancerController{
		Logger:        nl.LoggerFromContext(context.Background()),
		wafBundlePath: dir,
		plmEnabled:    true,
		namespacedInformers: map[string]*namespacedInformer{
			"": {appProtectPolicyLister: store},
		},
	}

	if !lbc.policyNeedsPLMBundleFetch(pol) {
		t.Error("policyNeedsPLMBundleFetch() = false for a missing bundle, want true")
	}

	path := filepath.Join(dir, wafbundle.FetchedBundleFilename(pol.Namespace, pol.Name, "policy"))
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("failed to write bundle: %v", err)
	}
	if lbc.policyNeedsPLMBundleFetch(pol) {
		t.Error("policyNeedsPLMBundleFetch() = true for a current bundle, want false")
	}
}

// apResourceWithStatusBundle builds an APPolicy/APLogConf-shaped unstructured object
// whose spec is fixed and whose .status.bundle is set to the given fields.
func apResourceWithStatusBundle(state, location, sha256 string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{"namespace": "plm", "name": "ap-pol"},
			"spec":     map[string]interface{}{"policy": map[string]interface{}{"name": "p"}},
			"status": map[string]interface{}{
				"bundle": map[string]interface{}{
					"state":    state,
					"location": location,
					"sha256":   sha256,
				},
			},
		},
	}
}

func TestBundleStatusChanged(t *testing.T) {
	t.Parallel()

	ready := apResourceWithStatusBundle("ready", "s3://b/ap.tgz", "abc123")
	// Same spec, only the bundle checksum/location changed (PLM recompile).
	recompiled := apResourceWithStatusBundle("ready", "s3://b/ap-v2.tgz", "def456")
	// Identical status to ready.
	readyDup := apResourceWithStatusBundle("ready", "s3://b/ap.tgz", "abc123")
	// No status at all (spec-only object).
	noStatus := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{"namespace": "plm", "name": "ap-pol"},
			"spec":     map[string]interface{}{"policy": map[string]interface{}{"name": "p"}},
		},
	}

	tests := []struct {
		name   string
		oldObj *unstructured.Unstructured
		newObj *unstructured.Unstructured
		want   bool
	}{
		{name: "checksum and location changed on recompile", oldObj: ready, newObj: recompiled, want: true},
		{name: "identical bundle status", oldObj: ready, newObj: readyDup, want: false},
		{name: "status.bundle first appears", oldObj: noStatus, newObj: ready, want: true},
		{name: "no status on either side", oldObj: noStatus, newObj: noStatus, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := bundleStatusChanged(tc.oldObj, tc.newObj); got != tc.want {
				t.Errorf("bundleStatusChanged() = %v, want %v", got, tc.want)
			}
		})
	}
}

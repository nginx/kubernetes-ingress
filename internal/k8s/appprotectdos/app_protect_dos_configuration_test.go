package appprotectdos

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	"github.com/nginx/kubernetes-ingress/pkg/apis/dos/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCreateAppProtectDosPolicyEx(t *testing.T) {
	t.Parallel()
	tests := []struct {
		policy           *unstructured.Unstructured
		expectedPolicyEx *DosPolicyEx
		wantErr          bool
		msg              string
	}{
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			expectedPolicyEx: &DosPolicyEx{
				IsValid:  false,
				ErrorMsg: "failed to store ApDosPolicy: error validating DosPolicy : required field map[] not found",
			},
			wantErr: true,
			msg:     "dos policy no spec",
		},
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			expectedPolicyEx: &DosPolicyEx{
				IsValid:  true,
				ErrorMsg: "",
			},
			wantErr: false,
			msg:     "dos policy is valid",
		},
	}

	for _, test := range tests {
		test.expectedPolicyEx.Obj = test.policy

		policyEx, err := createAppProtectDosPolicyEx(test.policy)
		if (err != nil) != test.wantErr {
			t.Errorf("createAppProtectDosPolicyEx() returned %v, for the case of %s", err, test.msg)
		}
		if diff := cmp.Diff(test.expectedPolicyEx, policyEx); diff != "" {
			t.Errorf("createAppProtectDosPolicyEx() %q returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestCreateAppProtectDosLogConfEx(t *testing.T) {
	t.Parallel()
	tests := []struct {
		logConf           *unstructured.Unstructured
		expectedLogConfEx *DosLogConfEx
		wantErr           bool
		msg               string
	}{
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"filter": map[string]interface{}{},
					},
				},
			},
			expectedLogConfEx: &DosLogConfEx{
				IsValid:  true,
				ErrorMsg: "",
			},
			wantErr: false,
			msg:     "Valid DosLogConf",
		},
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"content": map[string]interface{}{
							"format": "splunk",
						},
						"filter": map[string]interface{}{},
					},
				},
			},
			expectedLogConfEx: &DosLogConfEx{
				IsValid:  true,
				ErrorMsg: "the Content field is not supported, defaulting to splunk format.",
			},
			wantErr: false,
			msg:     "Valid DosLogConf with warning",
		},
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			expectedLogConfEx: &DosLogConfEx{
				IsValid:  false,
				ErrorMsg: "failed to store ApDosLogconf: error validating App Protect Dos Log Configuration : required field map[] not found",
			},
			wantErr: true,
			msg:     "Invalid DosLogConf",
		},
	}

	for _, test := range tests {
		test.expectedLogConfEx.Obj = test.logConf

		policyEx, err := createAppProtectDosLogConfEx(test.logConf)
		if (err != nil) != test.wantErr {
			t.Errorf("createAppProtectDosLogConfEx() returned %v, for the case of %s", err, test.msg)
		}
		if diff := cmp.Diff(test.expectedLogConfEx, policyEx); diff != "" {
			t.Errorf("createAppProtectDosLogConfEx() %q returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddOrUpdateDosProtected(t *testing.T) {
	t.Parallel()
	basicResource := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosOnly",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
		},
	}
	invalidResource := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "invalidResource",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable:           true,
			DosAccessLogDest: "127.0.0.1:5561",
		},
	}
	apc := NewConfiguration(true)
	tests := []struct {
		resource         *v1beta1.DosProtectedResource
		expectedChanges  []Change
		expectedProblems []Problem
		msg              string
	}{
		{
			resource: basicResource,
			expectedChanges: []Change{
				{
					Resource: &DosProtectedResourceEx{
						Obj:     basicResource,
						IsValid: true,
					},
					Op: AddOrUpdate,
				},
			},
			expectedProblems: nil,
			msg:              "Basic Case",
		},
		{
			resource: invalidResource,
			expectedChanges: []Change{
				{
					Resource: &DosProtectedResourceEx{
						Obj:      invalidResource,
						IsValid:  false,
						ErrorMsg: "failed to store DosProtectedResource: error validating DosProtectedResource: invalidResource missing value for field: name",
					},
					Op: Delete,
				},
			},
			expectedProblems: []Problem{
				{
					Object:  invalidResource,
					Reason:  nl.EventReasonRejected,
					Message: "error validating DosProtectedResource: invalidResource missing value for field: name",
				},
			},
			msg: "validation failed",
		},
	}
	for _, test := range tests {
		changes, problems := apc.AddOrUpdateDosProtectedResource(test.resource)
		if diff := cmp.Diff(test.expectedChanges, changes); diff != "" {
			t.Errorf("AddOrUpdateDosProtectedResource() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, problems); diff != "" {
			t.Errorf("AddOrUpdateDosProtectedResource() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddOrUpdateDosPolicy(t *testing.T) {
	t.Parallel()
	basicTestPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "testing",
				"name":      "name",
			},
			"spec": map[string]interface{}{
				"mitigation_mode":            "standard",
				"automation_tools_detection": "on",
				"tls_fingerprint":            "on",
				"signatures":                 "on",
				"bad_actors":                 "on",
			},
		},
	}

	basicPolicyResource := &DosPolicyEx{
		Obj:     basicTestPolicy,
		IsValid: true,
	}
	invalidTestPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "testing",
			},
		},
	}
	basicResource := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosOnly",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			ApDosPolicy:      "testing/name",
		},
	}
	apc := NewConfiguration(true)
	apc.dosProtectedResource[""] = &DosProtectedResourceEx{Obj: basicResource, IsValid: true}
	tests := []struct {
		policy           *unstructured.Unstructured
		expectedChanges  []Change
		expectedProblems []Problem
		msg              string
	}{
		{
			policy: basicTestPolicy,
			expectedChanges: []Change{
				{
					Resource: basicPolicyResource,
					Op:       AddOrUpdate,
				},
				{
					Resource: &DosProtectedResourceEx{
						Obj:     basicResource,
						IsValid: true,
					},
					Op: AddOrUpdate,
				},
			},
			expectedProblems: nil,
			msg:              "Basic Case",
		},
		{
			policy: invalidTestPolicy,
			expectedChanges: []Change{
				{
					Resource: &DosPolicyEx{
						Obj:      invalidTestPolicy,
						IsValid:  false,
						ErrorMsg: "failed to store ApDosPolicy: error validating DosPolicy : required field map[] not found",
					},
					Op: Delete,
				},
			},
			expectedProblems: []Problem{
				{
					Object:  invalidTestPolicy,
					Reason:  nl.EventReasonRejected,
					Message: "error validating DosPolicy : required field map[] not found",
				},
			},
			msg: "validation failed",
		},
	}
	for _, test := range tests {
		changes, problems := apc.AddOrUpdatePolicy(test.policy)
		if diff := cmp.Diff(test.expectedChanges, changes); diff != "" {
			t.Errorf("AddOrUpdatePolicy() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, problems); diff != "" {
			t.Errorf("AddOrUpdatePolicy() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddOrUpdateDosLogConf(t *testing.T) {
	t.Parallel()
	validLogConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "testing",
				"name":      "testlogconf",
			},
			"spec": map[string]interface{}{
				"filter": map[string]interface{}{},
			},
		},
	}
	validLogConfResource := &DosLogConfEx{
		Obj:     validLogConf,
		IsValid: true,
	}
	invalidLogConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "testing",
				"name":      "invalid-logconf",
			},
			"spec": map[string]interface{}{},
		},
	}
	basicResource := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosOnly",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			DosSecurityLog: &v1beta1.DosSecurityLog{
				Enable:       true,
				ApDosLogConf: "testing/testlogconf",
				DosLogDest:   "test.dns.com:123",
			},
		},
	}
	apc := NewConfiguration(true)
	apc.dosProtectedResource["single"] = &DosProtectedResourceEx{Obj: basicResource, IsValid: true}
	tests := []struct {
		logconf          *unstructured.Unstructured
		expectedChanges  []Change
		expectedProblems []Problem
		msg              string
	}{
		{
			logconf: validLogConf,
			expectedChanges: []Change{
				{
					Resource: validLogConfResource,
					Op:       AddOrUpdate,
				},
				{
					Resource: &DosProtectedResourceEx{
						Obj:     basicResource,
						IsValid: true,
					},
					Op: AddOrUpdate,
				},
			},
			expectedProblems: nil,
			msg:              "Basic Case",
		},
		{
			logconf: invalidLogConf,
			expectedChanges: []Change{
				{
					Resource: &DosLogConfEx{
						Obj:      invalidLogConf,
						IsValid:  false,
						ErrorMsg: "failed to store ApDosLogconf: error validating App Protect Dos Log Configuration invalid-logconf: required field map[] not found",
					},
					Op: Delete,
				},
			},
			expectedProblems: []Problem{
				{
					Object:  invalidLogConf,
					Reason:  nl.EventReasonRejected,
					Message: "error validating App Protect Dos Log Configuration invalid-logconf: required field map[] not found",
				},
			},
			msg: "validation failed",
		},
	}
	for _, test := range tests {
		changes, problems := apc.AddOrUpdateLogConf(test.logconf)
		if diff := cmp.Diff(test.expectedChanges, changes); diff != "" {
			t.Errorf("AddOrUpdateLogConf() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, problems); diff != "" {
			t.Errorf("AddOrUpdateLogConf() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestDeletePolicy(t *testing.T) {
	t.Parallel()
	appProtectConfiguration := NewConfiguration(true)
	appProtectConfiguration.dosPolicies["testing/test"] = &DosPolicyEx{}
	tests := []struct {
		key              string
		expectedChanges  []Change
		expectedProblems []Problem
		msg              string
	}{
		{
			key: "testing/test",
			expectedChanges: []Change{
				{
					Op:       Delete,
					Resource: &DosPolicyEx{},
				},
			},
			expectedProblems: nil,
			msg:              "Positive",
		},
		{
			key:              "testing/notpresent",
			expectedChanges:  nil,
			expectedProblems: nil,
			msg:              "Negative",
		},
	}
	for _, test := range tests {
		apChan, apProbs := appProtectConfiguration.DeletePolicy(test.key)
		if diff := cmp.Diff(test.expectedChanges, apChan); diff != "" {
			t.Errorf("DeletePolicy() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, apProbs); diff != "" {
			t.Errorf("DeletePolicy() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestDeleteDosLogConf(t *testing.T) {
	t.Parallel()
	appProtectConfiguration := NewConfiguration(true)
	appProtectConfiguration.dosLogConfs["testing/test"] = &DosLogConfEx{}
	tests := []struct {
		key              string
		expectedChanges  []Change
		expectedProblems []Problem
		msg              string
	}{
		{
			key: "testing/test",
			expectedChanges: []Change{
				{
					Op:       Delete,
					Resource: &DosLogConfEx{},
				},
			},
			expectedProblems: nil,
			msg:              "Positive",
		},
		{
			key:              "testing/notpresent",
			expectedChanges:  nil,
			expectedProblems: nil,
			msg:              "Negative",
		},
	}
	for _, test := range tests {
		apChan, apProbs := appProtectConfiguration.DeleteLogConf(test.key)
		if diff := cmp.Diff(test.expectedChanges, apChan); diff != "" {
			t.Errorf("DeleteLogConf() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, apProbs); diff != "" {
			t.Errorf("DeleteLogConf() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestDeleteDosProtected(t *testing.T) {
	t.Parallel()
	appProtectConfiguration := NewConfiguration(true)
	appProtectConfiguration.dosProtectedResource["testing/test"] = &DosProtectedResourceEx{}
	tests := []struct {
		key              string
		expectedChanges  []Change
		expectedProblems []Problem
		msg              string
	}{
		{
			key: "testing/test",
			expectedChanges: []Change{
				{
					Op:       Delete,
					Resource: &DosProtectedResourceEx{},
				},
			},
			expectedProblems: nil,
			msg:              "Positive",
		},
		{
			key:              "testing/notpresent",
			expectedChanges:  nil,
			expectedProblems: nil,
			msg:              "Negative",
		},
	}
	for _, test := range tests {
		changes, problems := appProtectConfiguration.DeleteProtectedResource(test.key)
		if diff := cmp.Diff(test.expectedChanges, changes); diff != "" {
			t.Errorf("DeleteProtectedResource() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, problems); diff != "" {
			t.Errorf("DeleteProtectedResource() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetDosProtected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind    string
		key     string
		wantErr bool
		errMsg  string
		msg     string
	}{
		{
			kind:    "DosProtectedResource",
			key:     "testing/test1",
			wantErr: false,
			msg:     "DosProtectedResource, positive",
		},
		{
			kind:    "DosProtectedResource",
			key:     "testing/test2",
			wantErr: true,
			errMsg:  "Validation Failed",
			msg:     "DosProtectedResource, Negative, invalid object",
		},
		{
			kind:    "DosProtectedResource",
			key:     "testing/test3",
			wantErr: true,
			errMsg:  "DosProtectedResource testing/test3 not found",
			msg:     "DosProtectedResource, Negative, Object Does not exist",
		},
	}
	appProtectConfiguration := NewConfiguration(true)
	appProtectConfiguration.dosProtectedResource["testing/test1"] = &DosProtectedResourceEx{IsValid: true, Obj: &v1beta1.DosProtectedResource{}}
	appProtectConfiguration.dosProtectedResource["testing/test2"] = &DosProtectedResourceEx{IsValid: false, Obj: &v1beta1.DosProtectedResource{}, ErrorMsg: "Validation Failed"}

	for _, test := range tests {
		_, err := appProtectConfiguration.getDosProtected(test.key)
		if (err != nil) != test.wantErr {
			t.Errorf("getDosProtected() returned %v on case %s", err, test.msg)
		}
		if test.wantErr || err != nil {
			if test.errMsg != err.Error() {
				t.Errorf("getDosProtected() returned error message '%s' on case '%s' (expected '%s')", err.Error(), test.msg, test.errMsg)
			}
		}
	}
}

func TestGetPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind    string
		key     string
		wantErr bool
		errMsg  string
		msg     string
	}{
		{
			kind:    "APDosPolicy",
			key:     "testing/test1",
			wantErr: false,
			msg:     "Policy, positive",
		},
		{
			kind:    "APDosPolicy",
			key:     "testing/test2",
			wantErr: true,
			errMsg:  "Validation Failed",
			msg:     "Policy, Negative, invalid object",
		},
		{
			kind:    "APDosPolicy",
			key:     "testing/test3",
			wantErr: true,
			errMsg:  "DosPolicy testing/test3 not found",
			msg:     "Policy, Negative, Object Does not exist",
		},
	}
	appProtectConfiguration := NewConfiguration(true)
	appProtectConfiguration.dosPolicies["testing/test1"] = &DosPolicyEx{IsValid: true, Obj: &unstructured.Unstructured{}}
	appProtectConfiguration.dosPolicies["testing/test2"] = &DosPolicyEx{IsValid: false, Obj: &unstructured.Unstructured{}, ErrorMsg: "Validation Failed"}

	for _, test := range tests {
		_, err := appProtectConfiguration.getPolicy(test.key)
		if (err != nil) != test.wantErr {
			t.Errorf("getPolicy() returned %v on case %s", err, test.msg)
		}
		if test.wantErr || err != nil {
			if test.errMsg != err.Error() {
				t.Errorf("getPolicy() returned error message '%s' on case '%s' (expected '%s')", err.Error(), test.msg, test.errMsg)
			}
		}
	}
}

func TestGetLogConf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind    string
		key     string
		wantErr bool
		errMsg  string
		msg     string
	}{
		{
			kind:    "APDosLogConf",
			key:     "testing/test1",
			wantErr: false,
			msg:     "LogConf, positive",
		},
		{
			kind:    "APDosLogConf",
			key:     "testing/test2",
			wantErr: true,
			errMsg:  "Validation Failed",
			msg:     "LogConf, Negative, invalid object",
		},
		{
			kind:    "APDosLogConf",
			key:     "testing/test3",
			wantErr: true,
			errMsg:  "DosLogConf testing/test3 not found",
			msg:     "LogConf, Negative, Object Does not exist",
		},
	}
	appProtectConfiguration := NewConfiguration(true)
	appProtectConfiguration.dosLogConfs["testing/test1"] = &DosLogConfEx{IsValid: true, Obj: &unstructured.Unstructured{}}
	appProtectConfiguration.dosLogConfs["testing/test2"] = &DosLogConfEx{IsValid: false, Obj: &unstructured.Unstructured{}, ErrorMsg: "Validation Failed"}

	for _, test := range tests {
		_, err := appProtectConfiguration.getLogConf(test.key)
		if (err != nil) != test.wantErr {
			t.Errorf("getLogConf() returned %v on case %s", err, test.msg)
		}
		if test.wantErr || err != nil {
			if test.errMsg != err.Error() {
				t.Errorf("getLogConf() returned error message '%s' on case '%s' (expected '%s')", err.Error(), test.msg, test.errMsg)
			}
		}
	}
}

func TestGetDosEx(t *testing.T) {
	t.Parallel()
	dosConf := NewConfiguration(true)
	dosLogConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "default",
				"name":      "dosLogConf",
			},
			"spec": map[string]interface{}{
				"content": map[string]interface{}{},
				"filter":  map[string]interface{}{},
			},
		},
	}
	dosPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "default",
				"name":      "dosPolicy",
			},
			"spec": map[string]interface{}{},
		},
	}
	dosProtectedOnly := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosOnly",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
		},
	}
	dosProtectedWithLogConf := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithLogConf",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			DosSecurityLog: &v1beta1.DosSecurityLog{
				Enable:       true,
				ApDosLogConf: "dosLogConf",
				DosLogDest:   "syslog-svc.default.svc.cluster.local:514",
			},
		},
	}
	dosProtectedWithPolicy := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithPolicy",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			ApDosPolicy:      "dosPolicy",
		},
	}
	dosProtectedWithInvalidLogConf := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithInvalidLogConf",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			DosSecurityLog: &v1beta1.DosSecurityLog{
				Enable:       true,
				ApDosLogConf: "invalid-dosLogConf",
				DosLogDest:   "syslog-svc.default.svc.cluster.local:514",
			},
		},
	}
	dosProtectedWithInvalidPolicy := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithInvalidPolicy",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			ApDosPolicy:      "invalid-dosPolicy",
		},
	}
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedOnly)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithLogConf)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithPolicy)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithInvalidLogConf)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithInvalidPolicy)
	dosConf.AddOrUpdateLogConf(dosLogConf)
	dosConf.AddOrUpdatePolicy(dosPolicy)

	tests := []struct {
		namespace string
		ref       string
		expected  *configs.DosEx
		msg       string
		error     string
	}{
		{
			namespace: "default",
			ref:       "dosOnly",
			expected: &configs.DosEx{
				DosProtected: dosProtectedOnly,
			},
			msg: "return the referenced resource, use parent namespace",
		},
		{
			namespace: "",
			ref:       "default/dosOnly",
			expected: &configs.DosEx{
				DosProtected: dosProtectedOnly,
			},
			msg: "return the referenced resource, use own namespace",
		},
		{
			namespace: "default",
			ref:       "dosNotExist",
			error:     "DosProtectedResource default/dosNotExist not found",
			msg:       "fails to find the referenced resource",
		},
		{
			namespace: "default",
			ref:       "default/dosWithLogConf",
			expected: &configs.DosEx{
				DosProtected: dosProtectedWithLogConf,
				DosLogConf:   dosLogConf,
			},
			msg: "return the referenced resource, including reference to logconf",
		},
		{
			namespace: "default",
			ref:       "default/dosWithPolicy",
			expected: &configs.DosEx{
				DosProtected: dosProtectedWithPolicy,
				DosPolicy:    dosPolicy,
			},
			msg: "return the referenced resource, including reference to policy",
		},
		{
			namespace: "default",
			ref:       "default/dosWithInvalidLogConf",
			error:     "DosProtectedResource references a missing DosLogConf: DosLogConf default/invalid-dosLogConf not found",
			msg:       "fails to find the referenced logconf resource",
		},
		{
			namespace: "default",
			ref:       "default/dosWithInvalidPolicy",
			error:     "DosProtectedResource references a missing DosPolicy: DosPolicy default/invalid-dosPolicy not found",
			msg:       "fails to find the referenced policy resource",
		},
	}
	for _, test := range tests {
		dosEx, err := dosConf.GetValidDosEx(test.namespace, test.ref)
		if err != nil {
			if test.error != "" {
				// we expect an error, check if it matches
				if test.error != err.Error() {
					t.Errorf("GetValidDosEx() returned different error than expected for the case of: %v \nexpected error '%v' \nactual error '%v' \n", test.msg, test.error, err.Error())
				}
				// all good
			} else {
				t.Errorf("GetValidDosEx() returned unexpected error for the case of: %v \n%v", test.msg, err)
			}
		}
		if diff := cmp.Diff(test.expected, dosEx); diff != "" {
			t.Errorf("GetValidDosEx() returned unexpected result for the case of: %v (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetDosExDosDisabled(t *testing.T) {
	t.Parallel()
	dosConf := NewConfiguration(false)
	dosLogConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "default",
				"name":      "dosLogConf",
			},
			"spec": map[string]interface{}{
				"content": map[string]interface{}{},
				"filter":  map[string]interface{}{},
			},
		},
	}
	dosPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "default",
				"name":      "dosPolicy",
			},
			"spec": map[string]interface{}{},
		},
	}
	dosProtectedOnly := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosOnly",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
		},
	}
	dosProtectedWithLogConf := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithLogConf",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			DosSecurityLog: &v1beta1.DosSecurityLog{
				Enable:       true,
				ApDosLogConf: "dosLogConf",
				DosLogDest:   "syslog-svc.default.svc.cluster.local:514",
			},
		},
	}
	dosProtectedWithPolicy := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithPolicy",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			ApDosPolicy:      "dosPolicy",
		},
	}
	dosProtectedWithInvalidLogConf := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithInvalidLogConf",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			DosSecurityLog: &v1beta1.DosSecurityLog{
				Enable:       true,
				ApDosLogConf: "invalid-dosLogConf",
				DosLogDest:   "syslog-svc.default.svc.cluster.local:514",
			},
		},
	}
	dosProtectedWithInvalidPolicy := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithInvalidPolicy",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			ApDosPolicy:      "invalid-dosPolicy",
		},
	}
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedOnly)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithLogConf)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithPolicy)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithInvalidLogConf)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithInvalidPolicy)
	dosConf.AddOrUpdateLogConf(dosLogConf)
	dosConf.AddOrUpdatePolicy(dosPolicy)

	tests := []struct {
		namespace string
		ref       string
		expected  *configs.DosEx
		msg       string
		error     string
	}{
		{
			namespace: "default",
			ref:       "dosOnly",
			error:     "DosProtectedResource is referenced but Dos feature is not enabled. resource: default/dosOnly",
			msg:       "fails to return a resource, using parent namespace",
		},
		{
			namespace: "",
			ref:       "default/dosOnly",
			error:     "DosProtectedResource is referenced but Dos feature is not enabled. resource: default/dosOnly",
			msg:       "fails to return the referenced resource, using own namespace",
		},
		{
			namespace: "default",
			ref:       "dosNotExist",
			error:     "DosProtectedResource is referenced but Dos feature is not enabled. resource: default/dosNotExist",
			msg:       "fails to find the referenced resource",
		},
		{
			namespace: "default",
			ref:       "default/dosWithLogConf",
			error:     "DosProtectedResource is referenced but Dos feature is not enabled. resource: default/dosWithLogConf",
			msg:       "fails to return the referenced resource, including reference to logconf",
		},
		{
			namespace: "default",
			ref:       "default/dosWithPolicy",
			error:     "DosProtectedResource is referenced but Dos feature is not enabled. resource: default/dosWithPolicy",
			msg:       "fails to return the referenced resource, including reference to policy",
		},
		{
			namespace: "default",
			ref:       "default/dosWithInvalidLogConf",
			error:     "DosProtectedResource is referenced but Dos feature is not enabled. resource: default/dosWithInvalidLogConf",
			msg:       "fails to find the referenced logconf resource",
		},
		{
			namespace: "default",
			ref:       "default/dosWithInvalidPolicy",
			error:     "DosProtectedResource is referenced but Dos feature is not enabled. resource: default/dosWithInvalidPolicy",
			msg:       "fails to find the referenced policy resource",
		},
	}
	for _, test := range tests {
		dosEx, err := dosConf.GetValidDosEx(test.namespace, test.ref)
		if err != nil {
			if test.error != "" {
				// we expect an error, check if it matches
				if test.error != err.Error() {
					t.Errorf("GetValidDosEx() returned different error than expected for the case of: %v \nexpected error '%v' \nactual error '%v' \n", test.msg, test.error, err.Error())
				}
				// all good
			} else {
				t.Errorf("GetValidDosEx() returned unexpected error for the case of: %v \n%v", test.msg, err)
			}
		}
		if diff := cmp.Diff(test.expected, dosEx); diff != "" {
			t.Errorf("GetValidDosEx() returned unexpected result for the case of: %v (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetDosProtectedThatReferencedDosPolicy(t *testing.T) {
	t.Parallel()
	dosConf := NewConfiguration(true)
	dosPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "nginx",
				"name":      "dosPolicyOne",
			},
			"spec": map[string]interface{}{},
		},
	}
	dosPolicyTwo := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "dev",
				"name":      "dosPolicyTwo",
			},
			"spec": map[string]interface{}{},
		},
	}
	dosPolicyThree := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "dev",
				"name":      "dosPolicyThree",
			},
			"spec": map[string]interface{}{},
		},
	}
	dosProtectedNoRefs := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosProtectedNoRefs",
			Namespace: "nginx",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
		},
	}
	dosProtectedWithPolicyOne := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithPolicyOne",
			Namespace: "nginx",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			ApDosPolicy:      "dosPolicyOne",
		},
	}
	dosProtectedWithPolicyTwo := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithPolicyTwo",
			Namespace: "nginx",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			ApDosPolicy:      "dev/dosPolicyTwo",
		},
	}
	anotherDosProtectedWithPolicyTwo := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "anotherDosWithPolicyTwo",
			Namespace: "dev",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			ApDosPolicy:      "dosPolicyTwo",
		},
	}

	dosConf.AddOrUpdateDosProtectedResource(dosProtectedNoRefs)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithPolicyOne)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithPolicyTwo)
	dosConf.AddOrUpdateDosProtectedResource(anotherDosProtectedWithPolicyTwo)
	dosConf.AddOrUpdatePolicy(dosPolicy)
	dosConf.AddOrUpdatePolicy(dosPolicyTwo)
	dosConf.AddOrUpdatePolicy(dosPolicyThree)

	tests := []struct {
		policyNamespace string
		policyName      string
		expected        []*v1beta1.DosProtectedResource
		msg             string
	}{
		{
			policyNamespace: "nginx",
			policyName:      "dosPolicyThree",
			expected:        nil,
			msg:             "returns nothing",
		},
		{
			policyNamespace: "nginx",
			policyName:      "dosPolicyOne",
			expected: []*v1beta1.DosProtectedResource{
				dosProtectedWithPolicyOne,
			},
			msg: "return a single referenced obj, from policy reference",
		},
		{
			policyNamespace: "different",
			policyName:      "dosPolicyOne",
			expected:        nil,
			msg:             "return nothing as namespace doesn't match",
		},
		{
			policyNamespace: "dev",
			policyName:      "dosPolicyTwo",
			expected: []*v1beta1.DosProtectedResource{
				anotherDosProtectedWithPolicyTwo,
				dosProtectedWithPolicyTwo,
			},
			msg: "return two referenced objects, from policy reference with mixed namespaces",
		},
	}
	for _, test := range tests {
		resources := dosConf.GetDosProtectedThatReferencedDosPolicy(test.policyNamespace + "/" + test.policyName)
		sort.SliceStable(resources, func(i, j int) bool {
			return resources[i].Name < resources[j].Name
		})
		if diff := cmp.Diff(test.expected, resources); diff != "" {
			t.Errorf("GetDosProtectedThatReferencedDosPolicy() returned unexpected result for the case of: %v (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetDosProtectedThatReferencedDosLogConf(t *testing.T) {
	t.Parallel()
	dosConf := NewConfiguration(true)
	dosLogConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "nginx",
				"name":      "dosLogConfOne",
			},
			"spec": map[string]interface{}{},
		},
	}
	dosLogConfTwo := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "dev",
				"name":      "dosLogConfTwo",
			},
			"spec": map[string]interface{}{},
		},
	}
	dosLogConfThree := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "dev",
				"name":      "dosLogConfThree",
			},
			"spec": map[string]interface{}{},
		},
	}
	dosProtectedNoRefs := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosProtectedNoRefs",
			Namespace: "nginx",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
		},
	}
	dosProtectedWithLogConfOne := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithLogConfOne",
			Namespace: "nginx",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			DosSecurityLog: &v1beta1.DosSecurityLog{
				Enable:       true,
				ApDosLogConf: "dosLogConfOne",
				DosLogDest:   "syslog.dev:514",
			},
		},
	}
	dosProtectedWithLogConfTwo := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithLogConfTwo",
			Namespace: "nginx",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			DosSecurityLog: &v1beta1.DosSecurityLog{
				Enable:       true,
				ApDosLogConf: "dev/dosLogConfTwo",
				DosLogDest:   "syslog.dev:514",
			},
		},
	}
	anotherDosProtectedWithLogConfTwo := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "anotherDosWithLogConfTwo",
			Namespace: "dev",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			DosSecurityLog: &v1beta1.DosSecurityLog{
				Enable:       true,
				ApDosLogConf: "dosLogConfTwo",
				DosLogDest:   "syslog.dev:514",
			},
		},
	}

	dosConf.AddOrUpdateDosProtectedResource(dosProtectedNoRefs)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithLogConfOne)
	dosConf.AddOrUpdateDosProtectedResource(dosProtectedWithLogConfTwo)
	dosConf.AddOrUpdateDosProtectedResource(anotherDosProtectedWithLogConfTwo)
	dosConf.AddOrUpdateLogConf(dosLogConf)
	dosConf.AddOrUpdateLogConf(dosLogConfTwo)
	dosConf.AddOrUpdateLogConf(dosLogConfThree)

	tests := []struct {
		policyNamespace string
		policyName      string
		expected        []*v1beta1.DosProtectedResource
		msg             string
	}{
		{
			policyNamespace: "nginx",
			policyName:      "dosLogConfThree",
			expected:        nil,
			msg:             "returns nothing",
		},
		{
			policyNamespace: "nginx",
			policyName:      "dosLogConfOne",
			expected: []*v1beta1.DosProtectedResource{
				dosProtectedWithLogConfOne,
			},
			msg: "return a single referenced obj, from log conf reference",
		},
		{
			policyNamespace: "different",
			policyName:      "dosLogConfOne",
			expected:        nil,
			msg:             "return nothing as namespace doesn't match",
		},
		{
			policyNamespace: "dev",
			policyName:      "dosLogConfTwo",
			expected: []*v1beta1.DosProtectedResource{
				anotherDosProtectedWithLogConfTwo,
				dosProtectedWithLogConfTwo,
			},
			msg: "return two referenced objects, from log conf reference with mixed namespaces",
		},
	}
	for _, test := range tests {
		resources := dosConf.GetDosProtectedThatReferencedDosLogConf(test.policyNamespace + "/" + test.policyName)
		sort.SliceStable(resources, func(i, j int) bool {
			return resources[i].Name < resources[j].Name
		})
		if diff := cmp.Diff(test.expected, resources); diff != "" {
			t.Errorf("GetDosProtectedThatReferencedDosLogConf() returned unexpected result for the case of: %v (-want +got):\n%s", test.msg, diff)
		}
	}
}

package configs

import (
	"reflect"
	"testing"

	"github.com/nginx/kubernetes-ingress/pkg/apis/dos/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestUpdateApDosResource(t *testing.T) {
	t.Parallel()
	appProtectDosPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "test-ns",
				"name":      "test-name",
			},
		},
	}
	appProtectDosLogConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "test-ns",
				"name":      "test-name",
			},
			"spec": map[string]interface{}{
				"enable":           true,
				"name":             "dos-protected",
				"apDosMonitor":     "example.com",
				"dosAccessLogDest": "127.0.0.1:5561",
			},
		},
	}
	appProtectDosProtected := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosOnly",
			Namespace: "test-ns",
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
	appProtectDosProtectedWithLog := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithLogConf",
			Namespace: "test-ns",
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
	appProtectDosProtectedWithAllowList := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithAllowList",
			Namespace: "test-ns",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable: true,
			Name:   "dos-protected",
			ApDosMonitor: &v1beta1.ApDosMonitor{
				URI: "example.com",
			},
			DosAccessLogDest: "127.0.0.1:5561",
			AllowList: []v1beta1.AllowListEntry{
				{IPWithMask: "192.168.1.0/24"},
				{IPWithMask: "10.0.0.0/8"},
			},
		},
	}

	tests := []struct {
		dosProtectedEx *DosEx
		expected       *appProtectDosResource
		msg            string
	}{
		{
			dosProtectedEx: nil,
			expected:       nil,
			msg:            "nil app protect dos resources",
		},
		{
			dosProtectedEx: &DosEx{},
			expected:       nil,
			msg:            "empty app protect dos resources",
		},
		{
			dosProtectedEx: &DosEx{
				DosProtected: appProtectDosProtected,
			},
			expected: &appProtectDosResource{
				AppProtectDosEnable:       "on",
				AppProtectDosName:         "test-ns/dosOnly/dos-protected",
				AppProtectDosMonitorURI:   "example.com",
				AppProtectDosAccessLogDst: "syslog:server=127.0.0.1:5561",
			},
			msg: "app protect basic protected config",
		},
		{
			dosProtectedEx: &DosEx{
				DosProtected: appProtectDosProtected,
				DosPolicy:    appProtectDosPolicy,
			},
			expected: &appProtectDosResource{
				AppProtectDosEnable:       "on",
				AppProtectDosName:         "test-ns/dosOnly/dos-protected",
				AppProtectDosMonitorURI:   "example.com",
				AppProtectDosAccessLogDst: "syslog:server=127.0.0.1:5561",
				AppProtectDosPolicyFile:   "/etc/nginx/dos/policies/test-ns_test-name.json",
			},
			msg: "app protect dos policy",
		},
		{
			dosProtectedEx: &DosEx{
				DosProtected: appProtectDosProtectedWithLog,
				DosPolicy:    appProtectDosPolicy,
				DosLogConf:   appProtectDosLogConf,
			},
			expected: &appProtectDosResource{
				AppProtectDosEnable:       "on",
				AppProtectDosName:         "test-ns/dosWithLogConf/dos-protected",
				AppProtectDosMonitorURI:   "example.com",
				AppProtectDosAccessLogDst: "syslog:server=127.0.0.1:5561",
				AppProtectDosPolicyFile:   "/etc/nginx/dos/policies/test-ns_test-name.json",
				AppProtectDosLogEnable:    true,
				AppProtectDosLogConfFile:  "/etc/nginx/dos/logconfs/test-ns_test-name.json syslog:server=syslog-svc.default.svc.cluster.local:514",
			},
			msg: "app protect dos policy and log conf",
		},
		{
			dosProtectedEx: &DosEx{
				DosProtected: appProtectDosProtectedWithAllowList,
				DosPolicy:    appProtectDosPolicy,
			},
			expected: &appProtectDosResource{
				AppProtectDosEnable:        "on",
				AppProtectDosName:          "test-ns/dosWithAllowList/dos-protected",
				AppProtectDosMonitorURI:    "example.com",
				AppProtectDosAccessLogDst:  "syslog:server=127.0.0.1:5561",
				AppProtectDosPolicyFile:    "/etc/nginx/dos/policies/test-ns_test-name.json",
				AppProtectDosAllowListPath: "/etc/nginx/dos/allowlist/test-ns_dosWithAllowList.json",
			},
			msg: "app protect dos with allow list",
		},
	}

	for _, test := range tests {
		result := getAppProtectDosResource(test.dosProtectedEx)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("getAppProtectDosResource() returned:\n%v\nbut expected:\n%v\n for the case of '%s'", result, test.expected, test.msg)
		}
	}
}

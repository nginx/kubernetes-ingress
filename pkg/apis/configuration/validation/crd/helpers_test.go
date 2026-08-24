//go:build envtest

package crd

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// admissionCase is one CRD admission scenario. `spec` is the Policy
// spec as a Go map so tests can send arbitrary shapes without being
// constrained by pointer/omitempty quirks of the typed structs.
type admissionCase struct {
	name      string
	spec      map[string]any
	wantErr   bool
	errSubstr string // optional; must appear in err.Error() when wantErr is true
}

func policyGVK() schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: "k8s.nginx.org", Version: "v1", Kind: "Policy"}
}

// newPolicy builds an Unstructured Policy carrying the given spec.
// generateName is used so the API server assigns unique names and
// parallel subtests never collide.
func newPolicy(spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(policyGVK())
	u.SetNamespace(testNS)
	u.SetGenerateName("crdtest-")
	u.Object["spec"] = spec
	return u
}

func runAdmissionCases(t *testing.T, cases []admissionCase) {
	t.Helper()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			obj := newPolicy(tc.spec)
			err := k8sClient.Create(testCtx, obj)
			switch {
			case tc.wantErr && err == nil:
				_ = k8sClient.Delete(testCtx, obj)
				t.Fatalf("expected admission error, got nil")
			case !tc.wantErr && err != nil:
				t.Fatalf("expected admission to succeed, got: %v", err)
			case tc.wantErr && tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr):
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
			}
			if err == nil {
				_ = k8sClient.Delete(testCtx, obj, &client.DeleteOptions{})
			}
		})
	}
}

package wafbundle

import (
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// Bundle-state values PLM writes to .status.bundle.state on an APPolicy or
// APLogConf CR. Fetch is only dispatched when state == BundleStateReady.
const (
	BundleStateReady      = "ready"
	BundleStatePending    = "pending"
	BundleStateProcessing = "processing"
	BundleStateInvalid    = "invalid"
)

// APPolicyStatus is a typed view over the .status sub-resource of a
// PLM-compiled APPolicy CR, read from unstructured.Unstructured via the
// dynamic client.
type APPolicyStatus struct {
	Bundle *BundleStatus `json:"bundle,omitempty"`
}

// APLogConfStatus is the APLogConf counterpart of APPolicyStatus.
type APLogConfStatus struct {
	Bundle *BundleStatus `json:"bundle,omitempty"`
}

// BundleStatus describes the compiled bundle for a PLM-managed resource.
// Location and SHA256 are populated when State is BundleStateReady.
type BundleStatus struct {
	State              string `json:"state"`
	Location           string `json:"location,omitempty"`
	SHA256             string `json:"sha256,omitempty"`
	CompilerVersion    string `json:"compilerVersion,omitempty"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
}

// ParseAPPolicyStatus extracts a typed APPolicyStatus from an unstructured
// APPolicy CR. Errors on missing / malformed status.
func ParseAPPolicyStatus(obj *unstructured.Unstructured) (*APPolicyStatus, error) {
	var status APPolicyStatus
	if err := parseAPStatus(obj, "APPolicy", &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// ParseAPLogConfStatus is the APLogConf counterpart of ParseAPPolicyStatus.
func ParseAPLogConfStatus(obj *unstructured.Unstructured) (*APLogConfStatus, error) {
	var status APLogConfStatus
	if err := parseAPStatus(obj, "APLogConf", &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func parseAPStatus(obj *unstructured.Unstructured, kind string, out any) error {
	if obj == nil {
		return errors.New("nil object")
	}
	if got := obj.GetKind(); got != kind {
		return fmt.Errorf("expected kind %q, got %q", kind, got)
	}
	statusRaw, ok := obj.Object["status"]
	if !ok {
		return fmt.Errorf("%s %s/%s has no status", kind, obj.GetNamespace(), obj.GetName())
	}
	statusMap, ok := statusRaw.(map[string]any)
	if !ok {
		return fmt.Errorf("%s %s/%s status is not a map", kind, obj.GetNamespace(), obj.GetName())
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(statusMap, out); err != nil {
		return fmt.Errorf("convert %s status: %w", kind, err)
	}
	return nil
}

// IsReady reports whether the bundle can be fetched: state is "ready" and
// both location and sha256 are populated.
func (b *BundleStatus) IsReady() bool {
	return b != nil && b.State == BundleStateReady && b.Location != "" && b.SHA256 != ""
}

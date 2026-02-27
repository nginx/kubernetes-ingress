package appprotect

import "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

// BundleState represents the compilation state of a PLM bundle.
type BundleState string

// PLM bundle state constants.
const (
	// BundleStatePending indicates the bundle is pending compilation.
	BundleStatePending BundleState = "pending"
	// BundleStateProcessing indicates the bundle is being processed/compiled.
	BundleStateProcessing BundleState = "processing"
	// BundleStateReady indicates the bundle is compiled and ready for use.
	BundleStateReady BundleState = "ready"
	// BundleStateInvalid indicates the bundle failed validation or compilation.
	BundleStateInvalid BundleState = "invalid"
)

// PLMBundleStatus holds the bundle info extracted from status.bundle of APPolicy/APLogConf v1.
type PLMBundleStatus struct {
	// State is the current bundle state.
	State BundleState
	// Location is the S3 path where the compiled bundle is stored (format: "bucket/key").
	// Only set when State == BundleStateReady.
	Location string
	// Sha256 is the SHA256 hash of the bundle file.
	Sha256 string
}

// ExtractPLMBundleStatus reads status.bundle from an unstructured APPolicy or APLogConf v1 resource.
func ExtractPLMBundleStatus(obj *unstructured.Unstructured) PLMBundleStatus {
	status, found, err := unstructured.NestedMap(obj.Object, "status")
	if err != nil || !found {
		return PLMBundleStatus{}
	}

	bundleMap, found, err := unstructured.NestedMap(status, "bundle")
	if err != nil || !found {
		return PLMBundleStatus{}
	}

	result := PLMBundleStatus{}

	if state, ok, _ := unstructured.NestedString(bundleMap, "state"); ok {
		result.State = BundleState(state)
	}

	if loc, ok, _ := unstructured.NestedString(bundleMap, "location"); ok {
		result.Location = loc
	}

	if sha, ok, _ := unstructured.NestedString(bundleMap, "sha256"); ok {
		result.Sha256 = sha
	}

	return result
}

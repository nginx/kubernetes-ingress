package appprotectcommon

import (
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// GetNsName gets the key of a resource in the format: "resNamespace/resName"
func GetNsName(obj *unstructured.Unstructured) string {
	return obj.GetNamespace() + "/" + obj.GetName()
}

// ParseResourceReferenceAnnotation returns a namespace/name string
func ParseResourceReferenceAnnotation(ns, antn string) string {
	if !validation.HasNamespace(antn) {
		return ns + "/" + antn
	}
	return antn
}

// ParseResourceReferenceAnnotationList returns a slice of ns/names strings
func ParseResourceReferenceAnnotationList(ns, annotations string) []string {
	var out []string
	for _, antn := range strings.Split(annotations, ",") {
		out = append(out, ParseResourceReferenceAnnotation(ns, antn))
	}
	return out
}

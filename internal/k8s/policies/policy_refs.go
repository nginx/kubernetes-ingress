package policies

import (
	"strings"

	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

// GetPolicyRefsFromAnnotation parses the policies annotation and returns a slice of PolicyReference.
func GetPolicyRefsFromAnnotation(annotation, namespace string) []conf_v1.PolicyReference {
	var policyRefs []conf_v1.PolicyReference
	if annotation == "" {
		return policyRefs
	}
	policyNames := strings.Split(annotation, ",")
	for _, policyName := range policyNames {
		policyName = strings.TrimSpace(policyName)
		parts := strings.Split(policyName, "/")
		if len(parts) == 2 {
			namespace = parts[0]
			policyName = parts[1]
		}
		if policyName == "" {
			continue
		}
		policyRef := conf_v1.PolicyReference{
			Name:      policyName,
			Namespace: namespace,
		}
		policyRefs = append(policyRefs, policyRef)
	}
	return policyRefs
}

// GetPolicyRefsFromPolicies parses the policies annotation and returns a slice of PolicyReference.
func GetPolicyRefsFromPolicies(policies map[string]*conf_v1.Policy) []conf_v1.PolicyReference {
	var policyRefs []conf_v1.PolicyReference
	if len(policies) == 0 {
		return policyRefs
	}
	for _, policy := range policies {
		policyRef := conf_v1.PolicyReference{
			Name:      policy.Name,
			Namespace: policy.Namespace,
		}
		policyRefs = append(policyRefs, policyRef)
	}
	return policyRefs
}

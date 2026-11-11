package configs

import "strings"

// ACMEChallengePathPrefix is the path prefix under which ACME HTTP-01 challenge tokens are served (RFC 8555, section 8.3).
const ACMEChallengePathPrefix = "/.well-known/acme-challenge/"

// ACMESolverServicePrefix is the name prefix of the Services cert-manager creates for its HTTP-01 solver pods.
// See cert-manager pkg/issuer/acme/http/service.go, which sets GenerateName to this prefix.
const ACMESolverServicePrefix = "cm-acme-http-solver-"

// IsACMEChallengeLocation reports whether a location with the given path and backend service name
// serves a cert-manager ACME HTTP-01 challenge. One leading "= " (exact match modifier) is stripped from path.
// Regex locations are not matched.
func IsACMEChallengeLocation(path, serviceName string) bool {
	path = strings.TrimPrefix(path, "= ")
	return strings.HasPrefix(path, ACMEChallengePathPrefix) &&
		strings.HasPrefix(serviceName, ACMESolverServicePrefix) &&
		len(serviceName) > len(ACMESolverServicePrefix)
}

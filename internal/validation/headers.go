package validation

import (
	"strings"

	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
)

// This file holds the shared HTTP header name validator that NIC's
// tenant-controlled surfaces route through, so the accepted grammar cannot
// drift between them. It is not yet the single source of truth for every
// surface; the remaining ones are listed below and are aligned separately.
//
// NIC accepts header names from several surfaces that all end up in the same
// NGINX directives. The tenant-controlled annotations
// nginx.org/proxy-hide-headers and nginx.org/proxy-pass-headers validate
// through ValidateHeaderName here, via the annotation header-list validation
// in internal/k8s.
//
// nginx.org/proxy-set-headers is validated separately by validateProxySetHeader
// in internal/configs/version1, which applies its own regexp. That regexp
// accepts exactly the grammar IsHTTPHeaderName accepts, so the two surfaces
// agree today; routing it through here as well is left for the same follow-up
// that aligns the sources listed below.
//
// The ConfigMap keys — proxy-hide-headers, proxy-pass-headers, real-ip-header
// and otel-exporter-header-name — are deliberately not routed here yet.
// Changing a ConfigMap needs cluster-level Kubernetes permission, a
// different threat model from the tenant surfaces, so centralizing their
// header-name validation belongs with the ConfigMap hardening work rather than
// with this tenant-facing change.
//
// Messages are returned verbatim from IsHTTPHeaderName, so every surface that
// does route here reports an identical reason for an identical failure. The
// sources still calling k8svalidation.IsHTTPHeaderName (or the k8s helper)
// directly, to be aligned later, are those ConfigMap keys and the CRD side in
// pkg/apis/configuration/validation:
//
//   - virtualserver.go validateActionProxyHeader, for the requestHeaders.set
//     and responseHeaders.add header names
//   - virtualserver.go validateActionProxyResponseHeaders, for the
//     responseHeaders.hide and responseHeaders.pass lists
//   - virtualserver.go validateCondition, for a match condition header
//   - policy.go validateAPIKey, for apiKey.suppliedIn.header
//   - common.go isValidSpecialHeaderLikeVariable, which maps '_' to '-' before
//     validating and so accepts a different grammar again
//
// Once those are aligned, the wording can become a constant owned by this
// package and every assertion can change in one place.
//
// Note that IsHTTPHeaderName is narrower than the RFC 9110 field-name grammar:
// it permits letters, digits and '-', but rejects other legal tchar characters
// such as '_' and '.'. Broadening it is a change in accepted configuration
// rather than a change in structure, so it is deliberately not done here.

// ValidateHeaderName validates a single HTTP header name. It returns the
// messages describing why the name is invalid, and an empty slice when the name
// is valid.
func ValidateHeaderName(name string) []string {
	return k8svalidation.IsHTTPHeaderName(name)
}

// SplitHeaderNameList splits a comma-separated list of HTTP header names and
// trims each entry. It performs no validation, so that callers which need to
// attribute a message to an individual entry can pair it with
// ValidateHeaderName themselves.
//
// Callers must configure NGINX with the returned names rather than splitting the
// raw value again, so that the value which passed validation is the value that
// reaches the generated configuration.
func SplitHeaderNameList(value string) []string {
	values := strings.Split(value, ",")
	names := make([]string, 0, len(values))
	for _, name := range values {
		names = append(names, strings.TrimSpace(name))
	}
	return names
}

// ValidateHeaderNameList splits a comma-separated list of HTTP header names and
// returns the trimmed names alongside the messages describing every invalid
// entry. Callers that need to report which entry a message belongs to should
// use SplitHeaderNameList with ValidateHeaderName instead.
func ValidateHeaderNameList(value string) (names []string, msgs []string) {
	names = SplitHeaderNameList(value)
	for _, name := range names {
		msgs = append(msgs, ValidateHeaderName(name)...)
	}
	return names, msgs
}

// ValidateRealIPHeader validates a value for the real_ip_header directive,
// which accepts a header name or the literal proxy_protocol.
func ValidateRealIPHeader(value string) []string {
	if value == "proxy_protocol" {
		return nil
	}
	return ValidateHeaderName(value)
}

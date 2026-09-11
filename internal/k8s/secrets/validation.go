package secrets

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"slices"

	api_v1 "k8s.io/api/core/v1"
)

// JWTKeyKey is the key of the data field of a Secret where the JWK must be stored.
const JWTKeyKey = "jwk"

// CAKey is the key of the data field of a Secret where the certificate authority must be stored.
const CAKey = "ca.crt"

// CACrlKey is the key of the data field of a Secret where the certificate revocation list must be stored.
const CACrlKey = "ca.crl"

// ClientSecretKey is the key of the data field of a Secret where the OIDC client secret must be stored.
const ClientSecretKey = "client-secret"

// HtpasswdFileKey is the key of the data field of a Secret where the HTTP basic authorization list must be stored
const HtpasswdFileKey = "htpasswd"

// LicenseKey is the key of the data field of a Secret where the NGINX Plus license must be stored.
const LicenseKey = "license.jwt"

// BundleTokenKey is the key of the data field of a Secret where the WAF bundle API token (NGINX One Console)
// or bearer token (NGINX Instance Manager) must be stored.
const BundleTokenKey    = "token"

// BundleUsernameKey is the key of the data field of a Secret where the WAF bundle basic auth username must be stored.
const BundleUsernameKey = "username"

// BundlePasswordKey is the key of the data field of a Secret where the WAF bundle basic auth password must be stored.
const BundlePasswordKey = "password"

// PLMS3SecretKey is the data key for the PLM S3 storage secret access key.
const PLMS3SecretKey = "seaweedfs_admin_secret"

// apiKeyClientIDDisallowedChars are the characters an API key client ID may not contain.
const apiKeyClientIDDisallowedChars = ";{}$`\"'\\\n\r"

// SecretTypeCA contains a certificate authority for TLS certificate verification. #nosec G101
const SecretTypeCA api_v1.SecretType = "nginx.org/ca" //nolint:gosec // G101: Potential hardcoded credentials - false positive

// SecretTypeJWK contains a JWK (JSON Web Key) for validating JWTs (JSON Web Tokens). #nosec G101
const SecretTypeJWK api_v1.SecretType = "nginx.org/jwk" //nolint:gosec // G101: Potential hardcoded credentials - false positive

// SecretTypeOIDC contains an OIDC client secret for use in oauth flows. #nosec G101
const SecretTypeOIDC api_v1.SecretType = "nginx.org/oidc" //nolint:gosec // G101: Potential hardcoded credentials - false positive

// SecretTypeHtpasswd contains an htpasswd file for use in HTTP Basic authorization.. #nosec G101
const SecretTypeHtpasswd api_v1.SecretType = "nginx.org/htpasswd" // #nosec G101

// SecretTypeAPIKey contains a list of client ID and key for API key authorization.. #nosec G101
const SecretTypeAPIKey api_v1.SecretType = "nginx.org/apikey" // #nosec G101

// SecretTypeLicense contains the license.jwt required for NGINX Plus. #nosec G101
const SecretTypeLicense api_v1.SecretType = "nginx.com/license" // #nosec G101

// SecretTypeWAFBundle contains credentials for fetching WAF bundles from management planes (N1C, NIM). #nosec G101
const SecretTypeWAFBundle api_v1.SecretType = "nginx.com/waf-bundle" // #nosec G101

// SecretRole is what a Secret is used for at a particular reference site.
// It is independent of api_v1.SecretType.
type SecretRole string

const (
    RoleTLS       SecretRole = "tls"
    RoleCA        SecretRole = "ca"
    RoleJWK       SecretRole = "jwk"
    RoleHtpasswd  SecretRole = "htpasswd"
    RoleOIDC      SecretRole = "oidc"
	RoleLicense   SecretRole = "license"
    RoleAPIKey    SecretRole = "apikey"
    RoleWAFBundle SecretRole = "wafbundle"
)

var allRoles = []SecretRole{
	RoleTLS, RoleCA, RoleJWK, RoleHtpasswd,
	RoleOIDC, RoleAPIKey, RoleLicense, RoleWAFBundle,
}

// RequiredKeys returns the data keys a Secret must carry to satisfy role.
// RoleAPIKey returns nil — its keys are user-defined client IDs.
// RoleWAFBundle returns nil — its keys are user-defined token or username+password.
func RequiredKeys(role SecretRole) []string {
	switch role {
	case RoleTLS:
		return []string{api_v1.TLSCertKey, api_v1.TLSPrivateKeyKey}
	case RoleCA:
		return []string{CAKey}
	case RoleJWK:
		return []string{JWTKeyKey}
	case RoleHtpasswd:
		return []string{HtpasswdFileKey}
	case RoleOIDC:
		return []string{ClientSecretKey}
	case RoleLicense:
		return []string{LicenseKey}
	case RoleAPIKey, RoleWAFBundle:
		return nil
	}
	return nil

}

// KnownKeys returns every key a role assigns meaning to, required or not. It
// is a superset of RequiredKeys: RoleCA also reads the optional ca.crl, and
// RoleWAFBundle accepts a token OR username+password plus an optional ca.crt, so
// all four are known while none is individually required.
func KnownKeys(role SecretRole) []string {
	switch role {
	case RoleCA:
		return []string{CAKey, CACrlKey}
	case RoleWAFBundle:
		return []string{BundleTokenKey, BundleUsernameKey, BundlePasswordKey, CAKey}
	case RoleAPIKey:
		return nil
	default:
		return RequiredKeys(role)
	}
}

// requireRoleKeys checks that each key is present in the Secret's data. Presence only,
// deliberately not non-emptiness: five of the eight validators accept an empty
// value today, and narrowing that would reject working-if-degraded deployments
// on upgrade.
func requiredRoleKeys(secret *api_v1.Secret, role SecretRole) error {
	for _, key := range RequiredKeys(role) {
		if _, exists := secret.Data[key]; !exists {
			return fmt.Errorf("secret is missing required key %q", key)
		}
	}
	return nil
}

// reservedKeys returns every data key that belongs to some other NGINX Ingress
// Controller feature: the union of KnownKeys over every role except RoleAPIKey,
// plus the well-known Kubernetes Secret keys.
func reservedKeys() map[string]struct{} {
	reserved := map[string]struct{}{
		PLMS3SecretKey:                 {},
		"namespace":                    {},
		api_v1.DockerConfigKey:         {},
		api_v1.DockerConfigJsonKey:     {},
	}
	for _, role := range allRoles {
		if role == RoleAPIKey {
			continue
		}
		for _, key := range KnownKeys(role) {
			reserved[key] = struct{}{}
		}
	}
	return reserved
}

// ValidateTLSSecret validates the secret. If it is valid, the function returns nil.
func ValidateTLSSecret(secret *api_v1.Secret) error {
	if err := requiredRoleKeys(secret, RoleTLS); err != nil {
		return err
	}

	// Kubernetes ensures that 'tls.crt' and 'tls.key' are present for secrets of api_v1.SecretTypeTLS type

	_, err := tls.X509KeyPair(secret.Data[api_v1.TLSCertKey], secret.Data[api_v1.TLSPrivateKeyKey])
	if err != nil {
		return fmt.Errorf("failed to validate TLS cert and key: %w", err)
	}

	return nil
}

// ValidateJWKSecret validates the secret. If it is valid, the function returns nil.
func ValidateJWKSecret(secret *api_v1.Secret) error {
	// we don't validate the contents of secret.Data[JWTKeyKey], because invalid contents will not make NGINX Plus
	// fail to reload: NGINX Plus will return 500 responses for the affected URLs.
	return requiredRoleKeys(secret, RoleJWK)
}

// ValidateCASecret validates the secret. If it is valid, the function returns nil.
func ValidateCASecret(secret *api_v1.Secret) error {
	if err := requiredRoleKeys(secret, RoleCA); err != nil {
		return err
	}


	block, _ := pem.Decode(secret.Data[CAKey])
	if block == nil {
		return fmt.Errorf("the data field %s must hold a valid CERTIFICATE PEM block", CAKey)
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("the data field %s must hold a valid CERTIFICATE PEM block, but got '%s'", CAKey, block.Type)
	}

	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to validate certificate: %w", err)
	}

	return nil
}

// ValidateOIDCSecret validates the secret. If it is valid, the function returns nil.
func ValidateOIDCSecret(secret *api_v1.Secret) error {
	err := requiredRoleKeys(secret, RoleOIDC)
	if err != nil {
		return err
	}

	clientSecret := secret.Data[ClientSecretKey]
	if msg, ok := isValidClientSecretValue(string(clientSecret)); !ok {
		return fmt.Errorf("OIDC client secret is invalid: %s", msg)
	}
	return nil
}

// ValidateAPIKeySecret validates the secret. If it is valid, the function returns nil.
func ValidateAPIKeySecret(secret *api_v1.Secret) error {
	if err := requiredRoleKeys(secret, RoleAPIKey); err != nil {
		return err
	}
	if err := rejectReservedAPIKeyClientIDs(secret); err != nil {
		return err
	}
	uniqueKeys := make(map[string]bool)
	for clientID, apiKey := range secret.Data {
		if strings.ContainsAny(clientID, apiKeyClientIDDisallowedChars) {
			return fmt.Errorf("secret has an API key client ID %q containing characters "+
				"that are not permitted in NGINX configuration",
				clientID)
		}
		if uniqueKeys[string(apiKey)] {
			return fmt.Errorf("API Keys cannot be repeated")
		}
		uniqueKeys[string(apiKey)] = true
	}

	return nil
}

// rejectReservedAPIKeyClientIDs rejects a Secret whose keys are all reserved by
// another feature, when it carries two or more of them.
func rejectReservedAPIKeyClientIDs(secret *api_v1.Secret) error {
	if len(secret.Data) < 2 {
		return nil
	}
	clientIDs := make([]string, 0, len(secret.Data))

	reserved := reservedKeys()
	for key := range secret.Data {
		if _, isReserved := reserved[key]; !isReserved {
			return nil
		}
		clientIDs = append(clientIDs, key)
	}
	slices.Sort(clientIDs)

	return fmt.Errorf("secret cannot be used for API key authentication: "+
		"every data key (%s) is reserved by another NGINX Ingress Controller feature",
		strings.Join(clientIDs, ", "))
}

// ValidateHtpasswdSecret validates the secret. If it is valid, the function returns nil.
func ValidateHtpasswdSecret(secret *api_v1.Secret) error {
	// we don't validate the contents of secret.Data[HtpasswdFileKey], because invalid contents will not make NGINX
	// fail to reload: NGINX will return 403 responses for the affected URLs.
	return requiredRoleKeys(secret, RoleHtpasswd)
}

// ValidateLicenseSecret validates the secret. If it is valid, the function returns nil.
func ValidateLicenseSecret(secret *api_v1.Secret) error {
	return requiredRoleKeys(secret, RoleLicense)
}

// ValidateWAFBundleSecret validates a WAF bundle credentials secret.
// The secret must contain a 'token' field (API token for N1C, bearer
// token for NIM) or 'username'+'password' (basic auth for NIM).
func ValidateWAFBundleSecret(secret *api_v1.Secret) error {
	if err := requiredRoleKeys(secret, RoleWAFBundle); err != nil {
		return err
	}
	_, hasToken := secret.Data[BundleTokenKey]
	_, hasUsername := secret.Data[BundleUsernameKey]
	_, hasPassword := secret.Data[BundlePasswordKey]

	if !hasToken && !hasUsername {
		return fmt.Errorf("WAF bundle secret must contain 'token' or 'username'+'password'")
	}
	if hasUsername && !hasPassword {
		return fmt.Errorf("WAF bundle secret with 'username' must also contain 'password'")
	}

	return nil
}

// ValidateSecretForRole replaces the type-dispatching ValidateSecret.
func ValidateSecretForRole(secret *api_v1.Secret, role SecretRole) error {
	switch role {
	case RoleTLS:
		return ValidateTLSSecret(secret)
	case RoleCA:
		return ValidateCASecret(secret)
	case RoleJWK:
		return ValidateJWKSecret(secret)
	case RoleHtpasswd:
		return ValidateHtpasswdSecret(secret)
	case RoleOIDC:
		return ValidateOIDCSecret(secret)
	case RoleLicense:
		return ValidateLicenseSecret(secret)
	case RoleAPIKey:
		return ValidateAPIKeySecret(secret)
	case RoleWAFBundle:
		return ValidateWAFBundleSecret(secret)
	}
	return fmt.Errorf("unknown secret role %q", role)
}

var clientSecretValueFmtRegexp = regexp.MustCompile(`^([^"$\\\s]|\\[^$])*$`)

func isValidClientSecretValue(s string) (string, bool) {
	if ok := clientSecretValueFmtRegexp.MatchString(s); !ok {
		return `It must contain valid ASCII characters, must have all '"' escaped and must not contain any '$' or whitespaces ('\n', '\t' etc.) or end with an unescaped '\'`, false
	}
	return "", true
}

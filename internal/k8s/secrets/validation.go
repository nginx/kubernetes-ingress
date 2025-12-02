package secrets

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"

	api_v1 "k8s.io/api/core/v1"
)

// JWTKeyKey is the key of the data field of a Secret where the JWK must be stored.
const JWTKeyKey = "jwk"

// CAKey is the key of the data field of a Secret where the certificate authority must be stored.
const CAKey = "ca.crt"

// ClientSecretKey is the key of the data field of a Secret where the OIDC client secret must be stored.
const ClientSecretKey = "client-secret"

// HtpasswdFileKey is the key of the data field of a Secret where the HTTP basic authorization list must be stored
const HtpasswdFileKey = "htpasswd"

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

// ValidateTLSSecret validates the secret. If it is valid, the function returns nil.
func ValidateTLSSecret(secret *api_v1.Secret) error {
	if secret.Type != api_v1.SecretTypeTLS {
		return fmt.Errorf("TLS Secret must be of the type %v", api_v1.SecretTypeTLS)
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
	if secret.Type != SecretTypeJWK {
		return fmt.Errorf("JWK secret must be of the type %v", SecretTypeJWK)
	}

	if _, exists := secret.Data[JWTKeyKey]; !exists {
		return fmt.Errorf("JWK secret must have the data field %v", JWTKeyKey)
	}

	// we don't validate the contents of secret.Data[JWTKeyKey], because invalid contents will not make NGINX Plus
	// fail to reload: NGINX Plus will return 500 responses for the affected URLs.

	return nil
}

// ValidateCASecret validates the secret. If it is valid, the function returns nil.
func ValidateCASecret(secret *api_v1.Secret) error {
	if secret.Type != SecretTypeCA {
		return fmt.Errorf("CA secret must be of the type %v", SecretTypeCA)
	}

	if _, exists := secret.Data[CAKey]; !exists {
		return fmt.Errorf("CA secret must have the data field %v", CAKey)
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
	if secret.Type != SecretTypeOIDC {
		return fmt.Errorf("OIDC secret must be of the type %v", SecretTypeOIDC)
	}

	clientSecret, exists := secret.Data[ClientSecretKey]
	if !exists {
		return fmt.Errorf("OIDC secret must have the data field %v", ClientSecretKey)
	}

	if msg, ok := isValidClientSecretValue(string(clientSecret)); !ok {
		return fmt.Errorf("OIDC client secret is invalid: %s", msg)
	}
	return nil
}

// ValidateAPIKeySecret validates the secret. If it is valid, the function returns nil.
func ValidateAPIKeySecret(secret *api_v1.Secret) error {
	if secret.Type != SecretTypeAPIKey {
		return fmt.Errorf("APIKey secret must be of the type %v", SecretTypeAPIKey)
	}

	uniqueKeys := make(map[string]bool)
	for _, key := range secret.Data {
		if uniqueKeys[string(key)] {
			return fmt.Errorf("API Keys cannot be repeated")
		}
		uniqueKeys[string(key)] = true
	}

	return nil
}

// ValidateHtpasswdSecret validates the secret. If it is valid, the function returns nil.
func ValidateHtpasswdSecret(secret *api_v1.Secret) error {
	if secret.Type != SecretTypeHtpasswd {
		return fmt.Errorf("htpasswd secret must be of the type %v", SecretTypeHtpasswd)
	}

	if _, exists := secret.Data[HtpasswdFileKey]; !exists {
		return fmt.Errorf("htpasswd secret must have the data field %v", HtpasswdFileKey)
	}

	// we don't validate the contents of secret.Data[HtpasswdFileKey], because invalid contents will not make NGINX
	// fail to reload: NGINX will return 403 responses for the affected URLs.

	return nil
}

// ValidateLicenseSecret validates the secret. If it is valid, the function returns nil.
func ValidateLicenseSecret(secret *api_v1.Secret) error {
	if secret.Type != SecretTypeLicense {
		return fmt.Errorf("license secret must be of the type %v", SecretTypeLicense)
	}

	if _, exists := secret.Data["license.jwt"]; !exists {
		return fmt.Errorf("license secret must have the data field %v", "license.jwt")
	}

	return nil
}

// IsSupportedSecretType checks if the secret type is supported.
func IsSupportedSecretType(secretType api_v1.SecretType) bool {
	return secretType == api_v1.SecretTypeTLS ||
		secretType == SecretTypeCA ||
		secretType == SecretTypeJWK ||
		secretType == SecretTypeOIDC ||
		secretType == SecretTypeHtpasswd ||
		secretType == SecretTypeAPIKey ||
		secretType == SecretTypeLicense
}

// ValidateSecret validates the secret. If it is valid, the function returns nil.
func ValidateSecret(secret *api_v1.Secret) error {
	switch secret.Type {
	case api_v1.SecretTypeTLS:
		return ValidateTLSSecret(secret)
	case SecretTypeJWK:
		return ValidateJWKSecret(secret)
	case SecretTypeCA:
		return ValidateCASecret(secret)
	case SecretTypeOIDC:
		return ValidateOIDCSecret(secret)
	case SecretTypeHtpasswd:
		return ValidateHtpasswdSecret(secret)
	case SecretTypeAPIKey:
		return ValidateAPIKeySecret(secret)
	case SecretTypeLicense:
		return ValidateLicenseSecret(secret)
	}

	return fmt.Errorf("secret is of the unsupported type %v", secret.Type)
}

var clientSecretValueFmtRegexp = regexp.MustCompile(`^([^"$\\\s]|\\[^$])*$`)

func isValidClientSecretValue(s string) (string, bool) {
	if ok := clientSecretValueFmtRegexp.MatchString(s); !ok {
		return `It must contain valid ASCII characters, must have all '"' escaped and must not contain any '$' or whitespaces ('\n', '\t' etc.) or end with an unescaped '\'`, false
	}
	return "", true
}

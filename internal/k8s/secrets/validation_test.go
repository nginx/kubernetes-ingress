package secrets

import (
	_ "embed"
	"encoding/base64"
	"testing"

	v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateJWKSecret(t *testing.T) {
	t.Parallel()
	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "jwk-secret",
			Namespace: "default",
		},
		Type: SecretTypeJWK,
		Data: map[string][]byte{
			"jwk": nil,
		},
	}

	err := ValidateJWKSecret(secret)
	if err != nil {
		t.Errorf("ValidateJWKSecret() returned error %v", err)
	}
}

func TestValidateJWKSecretFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret *v1.Secret
		msg    string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "jwk-secret",
					Namespace: "default",
				},
				Type: "some-type",
				Data: map[string][]byte{
					"jwk": nil,
				},
			},
			msg: "Incorrect type for JWK secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "jwk-secret",
					Namespace: "default",
				},
				Type: SecretTypeJWK,
			},
			msg: "Missing jwk for JWK secret",
		},
	}

	for _, test := range tests {
		err := ValidateJWKSecret(test.secret)
		if err == nil {
			t.Errorf("ValidateJWKSecret() returned no error for the case of %s", test.msg)
		}
	}
}

func TestValidateValidateAPIKeySecret(t *testing.T) {
	t.Parallel()
	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "api-key-secret",
			Namespace: "default",
		},
		Type: SecretTypeAPIKey,
		Data: map[string][]byte{
			"client1": []byte("cGFzc3dvcmQ="),
			"client2": []byte("N2ViNDMwOGItY2Q1Yi00NDEzLWI0NTUtYjMyZmQ4OTg2MmZk"),
		},
	}

	err := ValidateAPIKeySecret(secret)
	if err != nil {
		t.Errorf("ValidateAPIKeySecret() returned error %v", err)
	}
}

func TestValidateValidateAPIKeyFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret *v1.Secret
		msg    string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Type: "some-type",
				Data: map[string][]byte{
					"client": nil,
				},
			},
			msg: "Incorrect type for API Key secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Type: SecretTypeAPIKey,
				Data: map[string][]byte{
					"client1": []byte("cGFzc3dvcmQ="),
					"client2": []byte("N2ViNDMwOGItY2Q1Yi00NDEzLWI0NTUtYjMyZmQ4OTg2MmZk"),
					"client3": []byte("N2ViNDMwOGItY2Q1Yi00NDEzLWI0NTUtYjMyZmQ4OTg2MmZk"),
				},
			},
			msg: "repeated API Keys for API Key secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Type: SecretTypeAPIKey,
				Data: map[string][]byte{
					"client1": []byte(""),
					"client2": []byte(""),
				},
			},
			msg: "repeated empty API Keys for API Key secret",
		},
	}

	for _, test := range tests {
		err := ValidateAPIKeySecret(test.secret)
		t.Logf("ValidateAPIKeySecret() returned error %v", err)
		if err == nil {
			t.Errorf("ValidateAPIKeySecret() returned no error for the case of %s", test.msg)
		}
	}
}

func TestValidateHtpasswdSecret(t *testing.T) {
	t.Parallel()
	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "htpasswd-secret",
			Namespace: "default",
		},
		Type: SecretTypeHtpasswd,
		Data: map[string][]byte{
			"htpasswd": nil,
		},
	}

	err := ValidateHtpasswdSecret(secret)
	if err != nil {
		t.Errorf("ValidateHtpasswdSecret() returned error %v", err)
	}
}

func TestValidateHtpasswdSecretFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret *v1.Secret
		msg    string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "htpasswd-secret",
					Namespace: "default",
				},
				Type: "some-type",
				Data: map[string][]byte{
					"htpasswd": nil,
				},
			},
			msg: "Incorrect type for Htpasswd secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "htpasswd-secret",
					Namespace: "default",
				},
				Type: SecretTypeHtpasswd,
			},
			msg: "Missing htpasswd for Htpasswd secret",
		},
	}

	for _, test := range tests {
		err := ValidateHtpasswdSecret(test.secret)
		if err == nil {
			t.Errorf("ValidateHtpasswdSecret() returned no error for the case of %s", test.msg)
		}
	}
}

func TestValidateCASecret(t *testing.T) {
	t.Parallel()
	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "ingress-mtls-secret",
			Namespace: "default",
		},
		Type: SecretTypeCA,
		Data: map[string][]byte{
			"ca.crt": validCert,
		},
	}

	err := ValidateCASecret(secret)
	if err != nil {
		t.Errorf("ValidateCASecret() returned error %v", err)
	}
}

func TestValidateCASecretFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret *v1.Secret
		msg    string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "ingress-mtls-secret",
					Namespace: "default",
				},
				Type: "some-type",
				Data: map[string][]byte{
					"ca.crt": validCert,
				},
			},
			msg: "Incorrect type for CA secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "ingress-mtls-secret",
					Namespace: "default",
				},
				Type: SecretTypeCA,
			},
			msg: "Missing ca.crt for CA secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "ingress-mtls-secret",
					Namespace: "default",
				},
				Type: SecretTypeCA,
				Data: map[string][]byte{
					"ca.crt": invalidCACertWithNoPEMBlock,
				},
			},
			msg: "Invalid cert with no PEM block",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "ingress-mtls-secret",
					Namespace: "default",
				},
				Type: SecretTypeCA,
				Data: map[string][]byte{
					"ca.crt": invalidCACertWithWrongPEMBlock,
				},
			},
			msg: "Invalid cert with wrong PEM block",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "ingress-mtls-secret",
					Namespace: "default",
				},
				Type: SecretTypeCA,
				Data: map[string][]byte{
					"ca.crt": invalidCACert,
				},
			},
			msg: "Invalid cert",
		},
	}

	for _, test := range tests {
		err := ValidateCASecret(test.secret)
		if err == nil {
			t.Errorf("ValidateCASecret() returned no error for the case of %s", test.msg)
		}
	}
}

func TestValidateTLSSecret(t *testing.T) {
	t.Parallel()
	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "tls-secret",
			Namespace: "default",
		},
		Type: v1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": validCert,
			"tls.key": validKey,
		},
	}

	err := ValidateTLSSecret(secret)
	if err != nil {
		t.Errorf("ValidateTLSSecret() returned error %v", err)
	}
}

func TestValidateTLSSecretFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret *v1.Secret
		msg    string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "default",
				},
				Type: "some type",
			},
			msg: "Wrong type",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "default",
				},
				Type: v1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": invalidCert,
					"tls.key": validKey,
				},
			},
			msg: "Invalid cert",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "default",
				},
				Type: v1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": validCert,
					"tls.key": invalidKey,
				},
			},
			msg: "Invalid key",
		},
	}

	for _, test := range tests {
		err := ValidateTLSSecret(test.secret)
		if err == nil {
			t.Errorf("ValidateTLSSecret() returned no error for the case of %s", test.msg)
		}
	}
}

func TestValidateOIDCSecret(t *testing.T) {
	t.Parallel()
	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "oidc-secret",
			Namespace: "default",
		},
		Type: SecretTypeOIDC,
		Data: map[string][]byte{
			"client-secret": nil,
		},
	}

	err := ValidateOIDCSecret(secret)
	if err != nil {
		t.Errorf("ValidateOIDCSecret() returned error %v", err)
	}
}

func TestValidateOIDCSecretFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret *v1.Secret
		msg    string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "oidc-secret",
					Namespace: "default",
				},
				Type: "some-type",
				Data: map[string][]byte{
					"client-secret": nil,
				},
			},
			msg: "Incorrect type for OIDC secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "oidc-secret",
					Namespace: "default",
				},
				Type: SecretTypeOIDC,
			},
			msg: "Missing client-secret for OIDC secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "oidc-secret",
					Namespace: "default",
				},
				Type: SecretTypeOIDC,
				Data: map[string][]byte{
					"client-secret": []byte("hello$$$"),
				},
			},
			msg: "Invalid characters in OIDC client secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "oidc-secret",
					Namespace: "default",
				},
				Type: SecretTypeOIDC,
				Data: map[string][]byte{
					"client-secret": []byte("hello\t\n"),
				},
			},
			msg: "Invalid newline in OIDC client secret",
		},
	}

	for _, test := range tests {
		err := ValidateOIDCSecret(test.secret)
		if err == nil {
			t.Errorf("ValidateOIDCSecret() returned no error for the case of %s", test.msg)
		}
	}
}

func TestValidateLicenseSecret(t *testing.T) {
	t.Parallel()
	secret := &v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "license-token",
			Namespace: "default",
		},
		Type: SecretTypeLicense,
		Data: map[string][]byte{
			"license.jwt": []byte(base64.StdEncoding.EncodeToString([]byte("license-token"))),
		},
	}

	err := ValidateLicenseSecret(secret)
	if err != nil {
		t.Errorf("ValidateLicenseSecret() returned error %v", err)
	}
}

func TestValidateLicenseSecretFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret *v1.Secret
		msg    string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "license-token",
					Namespace: "default",
				},
				Type: "some-type",
				Data: map[string][]byte{
					"license.jwt": []byte(base64.StdEncoding.EncodeToString([]byte("license-token"))),
				},
			},
			msg: "Incorrect type for license secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "license-token",
					Namespace: "default",
				},
				Type: SecretTypeLicense,
			},
			msg: "Missing license.jwt for license secret",
		},
	}

	for _, test := range tests {
		err := ValidateLicenseSecret(test.secret)
		if err == nil {
			t.Errorf("ValidateLicenseSecret() returned no error for the case of %s", test.msg)
		}
	}
}

func TestValidateSecret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret *v1.Secret
		msg    string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "default",
				},
				Type: v1.SecretTypeTLS,
				Data: map[string][]byte{
					"tls.crt": validCert,
					"tls.key": validKey,
				},
			},
			msg: "Valid TLS secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "ingress-mtls-secret",
					Namespace: "default",
				},
				Type: SecretTypeCA,
				Data: map[string][]byte{
					"ca.crt": validCACert,
				},
			},
			msg: "Valid CA secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "jwk-secret",
					Namespace: "default",
				},
				Type: SecretTypeJWK,
				Data: map[string][]byte{
					"jwk": nil,
				},
			},
			msg: "Valid JWK secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "htpasswd-secret",
					Namespace: "default",
				},
				Type: SecretTypeHtpasswd,
				Data: map[string][]byte{
					"htpasswd": nil,
				},
			},
			msg: "Valid Htpasswd secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "oidc-secret",
					Namespace: "default",
				},
				Type: SecretTypeOIDC,
				Data: map[string][]byte{
					"client-secret": nil,
				},
			},
			msg: "Valid OIDC secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key",
					Namespace: "default",
				},
				Type: SecretTypeAPIKey,
				Data: map[string][]byte{
					"client1": []byte("cGFzc3dvcmQ="),
				},
			},
			msg: "Valid API Key secret",
		},
	}

	for _, test := range tests {
		err := ValidateSecret(test.secret)
		if err != nil {
			t.Errorf("ValidateSecret() returned error %v for the case of %s", err, test.msg)
		}
	}
}

func TestValidateSecretFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret *v1.Secret
		msg    string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"tls.crt": validCert,
					"tls.key": validKey,
				},
			},
			msg: "Missing type for TLS secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "ingress-mtls-secret",
					Namespace: "default",
				},
				Type: SecretTypeCA,
			},
			msg: "Missing ca.crt for CA secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "jwk-secret",
					Namespace: "default",
				},
				Type: SecretTypeJWK,
			},
			msg: "Missing jwk for JWK secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "htpasswd-secret",
					Namespace: "default",
				},
				Type: SecretTypeHtpasswd,
			},
			msg: "Missing htpasswd for Htpasswd secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key",
					Namespace: "default",
				},
				Type: SecretTypeAPIKey,
				Data: map[string][]byte{
					"client1": []byte("cGFzc3dvcmQ="),
					"client2": []byte("cGFzc3dvcmQ="),
				},
			},
			msg: "duplicated API Keys in API Key secret",
		},
	}

	for _, test := range tests {
		err := ValidateSecret(test.secret)
		if err == nil {
			t.Errorf("ValidateSecret() returned no error for the case of %s", test.msg)
		}
	}
}

func TestHasCorrectSecretType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secretType v1.SecretType
		expected   bool
	}{
		{
			secretType: v1.SecretTypeTLS,
			expected:   true,
		},
		{
			secretType: SecretTypeCA,
			expected:   true,
		},
		{
			secretType: SecretTypeJWK,
			expected:   true,
		},
		{
			secretType: SecretTypeOIDC,
			expected:   true,
		},
		{
			secretType: SecretTypeHtpasswd,
			expected:   true,
		},
		{
			secretType: SecretTypeAPIKey,
			expected:   true,
		},
		{
			secretType: "some-type",
			expected:   false,
		},
	}

	for _, test := range tests {
		result := IsSupportedSecretType(test.secretType)
		if result != test.expected {
			t.Errorf("IsSupportedSecretType(%v) returned %v but expected %v", test.secretType, result, test.expected)
		}
	}
}

var (
	// Important: you need to run `make secrets` to generate the files
	// that are being embedded here!
	//
	// These files are also regular files rather than symlinks because
	// `go:embed` cannot follow symlinks, and it can't embed files from
	// outside the module root.

	//go:embed embeds-ca.crt
	validCert []byte

	//go:embed embeds-ca.key
	validKey []byte

	//go:embed embeds-empty-ca.crt
	invalidCert []byte

	//go:embed embeds-empty-ca.key
	invalidKey []byte

	validCACert = validCert

	invalidCACertWithNoPEMBlock []byte

	// This needs to be the empty key. The wrong PEM block is that it's
	// expecting a CERTIFICATE block but getting a PRIVATE KEY block.
	//go:embed embeds-empty-ca.key
	invalidCACertWithWrongPEMBlock []byte

	invalidCACert = invalidCert
)

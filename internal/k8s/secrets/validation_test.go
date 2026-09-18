package secrets

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateJWKSecret(t *testing.T) {
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
				Data: map[string][]byte{
					"jwk": nil,
				},
			},
			msg: "Valid JWK secret",
		},
	}
	for _, test := range tests {
		err := ValidateJWKSecret(test.secret)
		if err != nil {
			t.Errorf("ValidateJWKSecret() returned error %v", err)
		}
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
				Data: map[string][]byte{
					"client1": []byte("cGFzc3dvcmQ="),
					"client2": []byte("N2ViNDMwOGItY2Q1Yi00NDEzLWI0NTUtYjMyZmQ4OTg2MmZk"),
				},
			},
			msg: "Valid API Key secret",
		},
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
			msg: "API key secret with an unrecognized type",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{},
			},
			msg: "Empty API key secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"token": []byte("N2ViNDMwOGItY2Q1Yi00NDEzLWI0NTUtYjMyZmQ4OTg2MmZk"),
				},
			},
			msg: "API key secret with a single reserved key",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"token":   []byte("N2ViNDMwOGItY2Q1Yi00NDEzLWI0NTUtYjMyZmQ4OTg2MmZk"),
					"client1": []byte("cGFzc3dvcmQ="),
				},
			},
			msg: "API key secret with a reserved key and custom client",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"tls.crt":     []byte("one"),
					"tls.key":     []byte("two"),
					"real-client": []byte("three"),
				},
			},
			msg: "reserved keys plus custom client",
		},
	}

	for _, test := range tests {
		err := ValidateAPIKeySecret(test.secret)
		if err != nil {
			t.Errorf("ValidateAPIKeySecret() returned error %v", err)
		}
	}
}

func TestValidateValidateAPIKeyFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret  *v1.Secret
		msg     string
		wantErr string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"client1": []byte("cGFzc3dvcmQ="),
					"client2": []byte("N2ViNDMwOGItY2Q1Yi00NDEzLWI0NTUtYjMyZmQ4OTg2MmZk"),
					"client3": []byte("N2ViNDMwOGItY2Q1Yi00NDEzLWI0NTUtYjMyZmQ4OTg2MmZk"),
				},
			},
			msg:     "repeated API Keys for API Key secret",
			wantErr: "API Keys cannot be repeated",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"client1": []byte(""),
					"client2": []byte(""),
				},
			},
			msg:     "repeated empty API Keys for API Key secret",
			wantErr: "API Keys cannot be repeated",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"tls.crt": []byte("one"),
					"tls.key": []byte("two"),
				},
			},
			msg: "API token with tls keys",
			wantErr: "secret cannot be used for API key authentication: every data key " +
				"(tls.crt, tls.key) is reserved by another NGINX Ingress Controller feature",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"username": []byte("one"),
					"password": []byte("two"),
				},
			},
			msg: "API Key with basic auth keys",
			wantErr: "secret cannot be used for API key authentication: every data key " +
				"(password, username) is reserved by another NGINX Ingress Controller feature",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"ca.crt":    []byte("one"),
					"namespace": []byte("default"),
					"token":     []byte("three"),
				},
			},
			msg: "API Key with service account keys",
			wantErr: "secret cannot be used for API key authentication: every data key " +
				"(ca.crt, namespace, token) is reserved by another NGINX Ingress Controller feature",
		},
	}

	for _, test := range tests {
		err := ValidateAPIKeySecret(test.secret)
		t.Logf("ValidateAPIKeySecret() returned error %v", err)
		if err == nil {
			t.Errorf("ValidateAPIKeySecret() returned no error for the case of %s", test.msg)
		}
		if err.Error() != test.wantErr {
			t.Errorf("error = %q, want %q", err, test.wantErr)
		}
	}
}

func TestValidateAPIKeySecretRejectsDangerousClientIDs(t *testing.T) {
	t.Parallel()

	tests := []string{
		";", "{", "}", "$", "`", `"`, "'", `\`, "\n", "\r",
	}

	for _, dangerous := range tests {
		dangerous := dangerous
		t.Run(fmt.Sprintf("%q", dangerous), func(t *testing.T) {
			t.Parallel()

			clientID := "client" + dangerous
			secret := &v1.Secret{
				Data: map[string][]byte{
					clientID: []byte("credential"),
				},
			}

			err := ValidateAPIKeySecret(secret)
			if err == nil {
				t.Fatalf("expected client ID %q to be rejected", clientID)
			}

			want := fmt.Sprintf(
				"secret has an API key client ID %q containing characters that are not permitted in NGINX configuration",
				clientID,
			)
			if err.Error() != want {
				t.Errorf("error = %q, want %q", err, want)
			}
		})
	}
}

func TestValidateHtpasswdSecret(t *testing.T) {
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
				Data: map[string][]byte{
					"htpasswd": nil,
				},
			},
			msg: "Valid Htpasswd secret",
		},
	}

	for _, test := range tests {
		err := ValidateHtpasswdSecret(test.secret)
		if err != nil {
			t.Errorf("ValidateHtpasswdSecret() returned error %v", err)
		}
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
				Data: map[string][]byte{
					"ca.crt": validCert,
				},
			},
			msg: "Valid CA secret",
		},
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
			msg: "CA secret with an unrecognized type",
		},
	}

	for _, test := range tests {
		err := ValidateCASecret(test.secret)
		if err != nil {
			t.Errorf("ValidateCASecret() returned error %v", err)
		}
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
			},
			msg: "Missing ca.crt for CA secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "ingress-mtls-secret",
					Namespace: "default",
				},
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
				Data: map[string][]byte{
					"ca.crt": invalidCACert,
				},
			},
			msg: "Invalid cert",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "ingress-mtls-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{CAKey: nil},
			},
			msg: "Empty CA key",
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
			},
			msg: "Missing tls.crt and tls.key",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "default",
				},
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
				Data: map[string][]byte{
					"tls.crt": validCert,
					"tls.key": invalidKey,
				},
			},
			msg: "Invalid key",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "tls-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					v1.TLSCertKey:       nil,
					v1.TLSPrivateKeyKey: validKey,
				},
			},
			msg: "present but empty TLS certificate",
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
	tests := []struct {
		secret *v1.Secret
		msg    string
	}{
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "oidc-secret", Namespace: "default"},
				Data:       map[string][]byte{ClientSecretKey: []byte("some-secret")},
			},
			msg: "Valid OIDC secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "oidc-secret", Namespace: "default"},
				Type:       "some-type",
				Data:       map[string][]byte{ClientSecretKey: []byte("some-secret")},
			},
			msg: "OIDC secret with an unrecognized type",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "oidc-secret", Namespace: "default"},
				Type:       SecretTypeOIDC,
				Data:       map[string][]byte{ClientSecretKey: nil},
			},
			msg: "Empty client secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "oidc-secret", Namespace: "default"},
				Type:       SecretTypeOIDC,
				Data:       map[string][]byte{ClientSecretKey: []byte(`pa\"ss`)},
			},
			msg: "Escaped quote",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "oidc-secret", Namespace: "default"},
				Type:       SecretTypeOIDC,
				Data:       map[string][]byte{ClientSecretKey: []byte(`path\\secret`)},
			},
			msg: "Escaped backslash",
		},
	}

	for _, test := range tests {
		if err := ValidateOIDCSecret(test.secret); err != nil {
			t.Errorf("ValidateOIDCSecret() returned error %v for the case of %s", err, test.msg)
		}
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
			},
			msg: "Missing client-secret for OIDC secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "oidc-secret",
					Namespace: "default",
				},
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
				Data: map[string][]byte{
					"client-secret": []byte("hello\t\n"),
				},
			},
			msg: "Invalid newline in OIDC client secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "oidc-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"client-secret": []byte(`foo"; access_log /dev/null; set $dummy "`),
				},
			},
			msg: "Unescaped quote breakout in OIDC client secret",
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
				Data: map[string][]byte{
					"license.jwt": []byte(base64.StdEncoding.EncodeToString([]byte("license-token"))),
				},
			},
			msg: "Valid license secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "license-token",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"license.jwt": nil,
				},
			},
			msg: "License secret with empty value",
		},
	}

	for _, tests := range tests {
		err := ValidateLicenseSecret(tests.secret)
		if err != nil {
			t.Errorf("ValidateLicenseSecret() returned error %v", err)
		}
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

func TestValidateSecretForRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		secret *v1.Secret
		role   SecretRole
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
			role: RoleTLS,
			msg:  "Valid TLS secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "ingress-mtls-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"ca.crt": validCACert,
				},
			},
			role: RoleCA,
			msg:  "Valid CA secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "jwk-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"jwk": nil,
				},
			},
			role: RoleJWK,
			msg:  "Valid JWK secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "htpasswd-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"htpasswd": nil,
				},
			},
			role: RoleHtpasswd,
			msg:  "Valid Htpasswd secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "oidc-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"client-secret": nil,
				},
			},
			role: RoleOIDC,
			msg:  "Valid OIDC secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"client1": []byte("cGFzc3dvcmQ="),
				},
			},
			role: RoleAPIKey,
			msg:  "Valid API Key secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"license.jwt": []byte(nil),
				},
			},
			role: RoleLicense,
			msg:  "Valid license secret",
		},
		{
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{
					Name:      "api-key",
					Namespace: "default",
				},
				Data: map[string][]byte{
					BundleTokenKey: []byte("cGFzc3dvcmQ="),
				},
			},
			role: RoleWAFBundle,
			msg:  "Valid WAF Bundle secret",
		},
	}

	for _, test := range tests {
		err := ValidateSecretForRole(test.secret, test.role)
		if err != nil {
			t.Errorf("ValidateSecret() returned error %v for the case of %s", err, test.msg)
		}
	}
}

func TestValidateSecretForRoleMissingRequiredKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		role SecretRole
		data map[string][]byte
		want string
	}{
		{
			name: "TLS certificate",
			role: RoleTLS,
			data: map[string][]byte{v1.TLSPrivateKeyKey: validKey},
			want: `secret is missing required key "tls.crt"`,
		},
		{
			name: "TLS private key",
			role: RoleTLS,
			data: map[string][]byte{v1.TLSCertKey: validCert},
			want: `secret is missing required key "tls.key"`,
		},
		{
			name: "CA",
			role: RoleCA,
			want: `secret is missing required key "ca.crt"`,
		},
		{
			name: "JWK",
			role: RoleJWK,
			want: `secret is missing required key "jwk"`,
		},
		{
			name: "Htpasswd",
			role: RoleHtpasswd,
			want: `secret is missing required key "htpasswd"`,
		},
		{
			name: "OIDC",
			role: RoleOIDC,
			want: `secret is missing required key "client-secret"`,
		},
		{
			name: "License",
			role: RoleLicense,
			want: `secret is missing required key "license.jwt"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateSecretForRole(
				&v1.Secret{Data: test.data},
				test.role,
			)
			if err == nil {
				t.Fatal("expected a missing-key error")
			}
			if err.Error() != test.want {
				t.Errorf("error = %q, want %q", err, test.want)
			}
		})
	}
}

func TestValidateSecretForRoleUnknownRole(t *testing.T) {
	t.Parallel()

	err := ValidateSecretForRole(&v1.Secret{}, SecretRole("unknown"))
	if err == nil {
		t.Fatal("expected an error")
	}

	const want = `unknown secret role "unknown"`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestReservedKeysCoversAllRoles(t *testing.T) {
	t.Parallel()
	reserved := reservedKeys()
	for _, role := range allRoles {
		if role == RoleAPIKey {
			continue
		}
		for _, key := range KnownKeys(role) {
			if _, ok := reserved[key]; !ok {
				t.Errorf("key %q of role %q is missing from reservedKeys", key, role)
			}
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

func TestValidateWAFBundleSecret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		secret  *v1.Secret
		wantErr bool
	}{
		{
			name: "valid with token",
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "waf-creds", Namespace: "default"},
				Data:       map[string][]byte{BundleTokenKey: []byte("my-api-token")},
			},
		},
		{
			name: "valid with username+password",
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "waf-creds", Namespace: "default"},
				Data:       map[string][]byte{BundleUsernameKey: []byte("admin"), BundlePasswordKey: []byte("secret")},
			},
		},
		{
			name: "unrecognized type",
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "waf-creds", Namespace: "default"},
				Type:       "some-type",
				Data:       map[string][]byte{BundleTokenKey: []byte("tok")},
			},
		},
		{
			name: "missing token and username",
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "waf-creds", Namespace: "default"},
				Data:       map[string][]byte{"other": []byte("value")},
			},
			wantErr: true,
		},
		{
			name: "username without password",
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "waf-creds", Namespace: "default"},
				Data:       map[string][]byte{BundleUsernameKey: []byte("admin")},
			},
			wantErr: true,
		},
		{
			name: "password without username",
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "waf-creds", Namespace: "default"},
				Data:       map[string][]byte{BundlePasswordKey: []byte("admin")},
			},
			wantErr: true,
		},
		{
			name: "empty token",
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "waf-creds", Namespace: "default"},
				Data:       map[string][]byte{BundleTokenKey: []byte(nil)},
			},
			wantErr: false,
		},
		{
			name: "empty username and password",
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "waf-creds", Namespace: "default"},
				Data:       map[string][]byte{BundleUsernameKey: []byte(nil), BundlePasswordKey: []byte(nil)},
			},
			wantErr: false,
		},
		{
			name: "token with username",
			secret: &v1.Secret{
				ObjectMeta: meta_v1.ObjectMeta{Name: "waf-creds", Namespace: "default"},
				Data: map[string][]byte{
					BundleTokenKey:    []byte("token"),
					BundleUsernameKey: []byte("username"),
				},
			},
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateWAFBundleSecret(tc.secret)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateWAFBundleSecret() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

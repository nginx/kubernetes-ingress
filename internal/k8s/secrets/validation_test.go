package secrets

import (
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
	validCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDLjCCAhYCCQDAOF9tLsaXWjANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0
ZDEbMBkGA1UEAwwSY2FmZS5leGFtcGxlLmNvbSAgMB4XDTE4MDkxMjE2MTUzNVoX
DTIzMDkxMTE2MTUzNVowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMSEwHwYD
VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxGTAXBgNVBAMMEGNhZmUuZXhh
bXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCp6Kn7sy81
p0juJ/cyk+vCAmlsfjtFM2muZNK0KtecqG2fjWQb55xQ1YFA2XOSwHAYvSdwI2jZ
ruW8qXXCL2rb4CZCFxwpVECrcxdjm3teViRXVsYImmJHPPSyQgpiobs9x7DlLc6I
BA0ZjUOyl0PqG9SJexMV73WIIa5rDVSF2r4kSkbAj4Dcj7LXeFlVXH2I5XwXCptC
n67JCg42f+k8wgzcRVp8XZkZWZVjwq9RUKDXmFB2YyN1XEWdZ0ewRuKYUJlsm692
skOrKQj0vkoPn41EE/+TaVEpqLTRoUY3rzg7DkdzfdBizFO2dsPNFx2CW0jXkNLv
Ko25CZrOhXAHAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKHFCcyOjZvoHswUBMdL
RdHIb383pWFynZq/LuUovsVA58B0Cg7BEfy5vWVVrq5RIkv4lZ81N29x21d1JH6r
jSnQx+DXCO/TJEV5lSCUpIGzEUYaUPgRyjsM/NUdCJ8uHVhZJ+S6FA+CnOD9rn2i
ZBePCI5rHwEXwnnl8ywij3vvQ5zHIuyBglWr/Qyui9fjPpwWUvUm4nv5SMG9zCV7
PpuwvuatqjO1208BjfE/cZHIg8Hw9mvW9x9C+IQMIMDE7b/g6OcK7LGTLwlFxvA8
7WjEequnayIphMhKRXVf1N349eN98Ez38fOTHTPbdJjFA/PcC+Gyme+iGt5OQdFh
yRE=
-----END CERTIFICATE-----`)

	validKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqeip+7MvNadI7if3MpPrwgJpbH47RTNprmTStCrXnKhtn41k
G+ecUNWBQNlzksBwGL0ncCNo2a7lvKl1wi9q2+AmQhccKVRAq3MXY5t7XlYkV1bG
CJpiRzz0skIKYqG7Pcew5S3OiAQNGY1DspdD6hvUiXsTFe91iCGuaw1Uhdq+JEpG
wI+A3I+y13hZVVx9iOV8FwqbQp+uyQoONn/pPMIM3EVafF2ZGVmVY8KvUVCg15hQ
dmMjdVxFnWdHsEbimFCZbJuvdrJDqykI9L5KD5+NRBP/k2lRKai00aFGN684Ow5H
c33QYsxTtnbDzRcdgltI15DS7yqNuQmazoVwBwIDAQABAoIBAQCPSdSYnQtSPyql
FfVFpTOsoOYRhf8sI+ibFxIOuRauWehhJxdm5RORpAzmCLyL5VhjtJme223gLrw2
N99EjUKb/VOmZuDsBc6oCF6QNR58dz8cnORTewcotsJR1pn1hhlnR5HqJJBJask1
ZEnUQfcXZrL94lo9JH3E+Uqjo1FFs8xxE8woPBqjZsV7pRUZgC3LhxnwLSExyFo4
cxb9SOG5OmAJozStFoQ2GJOes8rJ5qfdvytgg9xbLaQL/x0kpQ62BoFMBDdqOePW
KfP5zZ6/07/vpj48yA1Q32PzobubsBLd3Kcn32jfm1E7prtWl+JeOFiOznBQFJbN
4qPVRz5hAoGBANtWyxhNCSLu4P+XgKyckljJ6F5668fNj5CzgFRqJ09zn0TlsNro
FTLZcxDqnR3HPYM42JERh2J/qDFZynRQo3cg3oeivUdBVGY8+FI1W0qdub/L9+yu
edOZTQ5XmGGp6r6jexymcJim/OsB3ZnYOpOrlD7SPmBvzNLk4MF6gxbXAoGBAMZO
0p6HbBmcP0tjFXfcKE77ImLm0sAG4uHoUx0ePj/2qrnTnOBBNE4MvgDuTJzy+caU
k8RqmdHCbHzTe6fzYq/9it8sZ77KVN1qkbIcuc+RTxA9nNh1TjsRne74Z0j1FCLk
hHcqH0ri7PYSKHTE8FvFCxZYdbuB84CmZihvxbpRAoGAIbjqaMYPTYuklCda5S79
YSFJ1JzZe1Kja//tDw1zFcgVCKa31jAwciz0f/lSRq3HS1GGGmezhPVTiqLfeZqc
R0iKbhgbOcVVkJJ3K0yAyKwPTumxKHZ6zImZS0c0am+RY9YGq5T7YrzpzcfvpiOU
ffe3RyFT7cfCmfoOhDCtzukCgYB30oLC1RLFOrqn43vCS51zc5zoY44uBzspwwYN
TwvP/ExWMf3VJrDjBCH+T/6sysePbJEImlzM+IwytFpANfiIXEt/48Xf60Nx8gWM
uHyxZZx/NKtDw0V8vX1POnq2A5eiKa+8jRARYKJLYNdfDuwolxvG6bZhkPi/4EtT
3Y18sQKBgHtKbk+7lNJVeswXE5cUG6EDUsDe/2Ua7fXp7FcjqBEoap1LSw+6TXp0
ZgrmKE8ARzM47+EJHUviiq/nupE15g0kJW3syhpU9zZLO7ltB0KIkO9ZRcmUjo8Q
cpLlHMAqbLJ8WYGJCkhiWxyal6hYTyWY4cVkC0xtTl/hUE9IeNKo
-----END RSA PRIVATE KEY-----`)

	invalidCert = []byte(`-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----`)

	invalidKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----`)

	validCACert = validCert

	invalidCACertWithNoPEMBlock []byte

	invalidCACertWithWrongPEMBlock = []byte(`-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----`)

	invalidCACert = []byte(`-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----`)
)

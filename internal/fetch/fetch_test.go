package fetch

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestS3FetcherOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expectedFields func(f *S3Fetcher) bool
		name           string
		options        []Option
	}{
		{
			name:    "default options",
			options: []Option{},
			expectedFields: func(f *S3Fetcher) bool {
				return f.timeout == defaultTimeout &&
					f.accessKeyID == "" &&
					f.secretAccessKey == ""
			},
		},
		{
			name:    "with timeout",
			options: []Option{WithTimeout(5 * time.Second)},
			expectedFields: func(f *S3Fetcher) bool {
				return f.timeout == 5*time.Second
			},
		},
		{
			name:    "with credentials",
			options: []Option{WithCredentials("access-key", "secret-key")},
			expectedFields: func(f *S3Fetcher) bool {
				return f.accessKeyID == "access-key" && f.secretAccessKey == "secret-key"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := NewWithT(t)

			fetcher, err := NewS3Fetcher("http://localhost:9000", tc.options...)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(tc.expectedFields(fetcher)).To(BeTrue())
		})
	}
}

func TestNewS3Fetcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		endpointURL string
		options     []Option
		expectError bool
	}{
		{
			name:        "valid endpoint",
			endpointURL: "http://localhost:9000",
			options:     []Option{},
			expectError: false,
		},
		{
			name:        "valid https endpoint",
			endpointURL: "https://storage.example.svc.cluster.local",
			options:     []Option{},
			expectError: false,
		},
		{
			name:        "with all options",
			endpointURL: "http://localhost:9000",
			options: []Option{
				WithTimeout(10 * time.Second),
				WithCredentials("key", "secret"),
			},
			expectError: false,
		},
		{
			name:        "endpoint without scheme gets http prepended",
			endpointURL: "storage.example.svc.cluster.local:8333",
			options:     []Option{},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := NewWithT(t)

			fetcher, err := NewS3Fetcher(tc.endpointURL, tc.options...)
			if tc.expectError {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(fetcher).ToNot(BeNil())
				g.Expect(fetcher.client).ToNot(BeNil())
				g.Expect(fetcher.endpointURL).To(HavePrefix("http"))
			}
		})
	}
}

func TestGetObjectError(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)

	// Create fetcher pointing to non-existent endpoint
	fetcher, err := NewS3Fetcher(
		"http://localhost:1",
		WithTimeout(100*time.Millisecond),
	)
	g.Expect(err).ToNot(HaveOccurred())

	// Attempt to get object - should fail
	ctx := context.Background()
	_, err = fetcher.GetObject(ctx, "test-bucket", "test-key")
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("failed to get object"))
}

func TestTLSConfigFromSecret(t *testing.T) {
	t.Parallel()

	// Valid CA certificate
	validCACert := []byte(`-----BEGIN CERTIFICATE-----
MIIDSDCCAjACCQDKWvrpwiIyCDANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuc2lzY28xDjAMBgNVBAoM
BU5HSU5YMQwwCgYDVQQLDANLSUMxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTIw
MTExMjIxMjg0MloXDTMwMTExMDIxMjg0MlowZjELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbnNpc2NvMQ4wDAYDVQQKDAVOR0lOWDEM
MAoGA1UECwwDS0lDMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMrlKMqrHfMR4mgaL2zZG2DYYfKCFVmINjlYuOeC
FDTcRgQKtu2YcCxZYBADwHZxEf6NIKtVsMWLhSNS/Nc0BmtiQM/IExhlCiDC6Sl8
ONrI3w7qJzN6IUERB6tVlQt07rgM0V26UTYu0Ikv1Y8trfLYPZckzBkorQjpcium
qoP2BJf4yyc9LqpxtlWKxelkunVL5ijMEzpj9gEE26TEHbsdEbhoR8g0OeHZqH7e
mXCnSIBR0A/o/s6noGNX+F19lY7Tgw77jOuQQ5Ysi+7nhN2lKvcC819RX7oMpgvt
V5B3nI0mF6BaznjeTs4yQcr1Sm3UTVBwX9ZuvL7RbIXkUm8CAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAgm04w6OIWGj6tka9ccccnblF0oZzeEAIywjvR5sDcPdvLIeM
eesJy6rFH4DBmMygpcIxJGrSOzZlF3LMvw7zK4stqNtm1HiprF8bzxfTffVYncg6
hVKErHtZ2FZRj/2TMJ01aRDZSuVbL6UJiokpU6xxT7yy0dFZkKrjUR349gKxRqJw
Am2as0bhi51EqK1GEx3m4c0un2vNh5qP2hv6e/Qze6P96vefNaSk9QMFfuB1kSAk
fGpkiL7bjmjnhKwAmf8jDWDZltB6S56Qy2QjPR8JoOusbYxar4c6EcIwVHv6mdgP
yZxWqQsgtSfFx+Pwon9IPKuq0jQYgeZPSxRMLA==
-----END CERTIFICATE-----`)

	// Valid cert/key pair for testing
	validClientCert := []byte(`-----BEGIN CERTIFICATE-----
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

	validClientKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
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

	tests := []struct {
		checkResult        func(_ *testing.T, g Gomega, cfg *tls.Config)
		name               string
		caCert             []byte
		clientCert         []byte
		clientKey          []byte
		insecureSkipVerify bool
		expectError        bool
	}{
		{
			name:               "empty config with insecure skip verify",
			caCert:             nil,
			clientCert:         nil,
			clientKey:          nil,
			insecureSkipVerify: true,
			expectError:        false,
			checkResult: func(_ *testing.T, g Gomega, cfg *tls.Config) {
				g.Expect(cfg.InsecureSkipVerify).To(BeTrue())
				g.Expect(cfg.RootCAs).To(BeNil())
				g.Expect(cfg.Certificates).To(BeEmpty())
			},
		},
		{
			name:               "with CA certificate only",
			caCert:             validCACert,
			clientCert:         nil,
			clientKey:          nil,
			insecureSkipVerify: false,
			expectError:        false,
			checkResult: func(_ *testing.T, g Gomega, cfg *tls.Config) {
				g.Expect(cfg.InsecureSkipVerify).To(BeFalse())
				g.Expect(cfg.RootCAs).ToNot(BeNil())
				g.Expect(cfg.Certificates).To(BeEmpty())
			},
		},
		{
			name:               "with client cert and key",
			caCert:             nil,
			clientCert:         validClientCert,
			clientKey:          validClientKey,
			insecureSkipVerify: false,
			expectError:        false,
			checkResult: func(_ *testing.T, g Gomega, cfg *tls.Config) {
				g.Expect(cfg.Certificates).To(HaveLen(1))
			},
		},
		{
			name:               "invalid CA certificate",
			caCert:             []byte("not a valid certificate"),
			clientCert:         nil,
			clientKey:          nil,
			insecureSkipVerify: false,
			expectError:        true,
			checkResult:        nil,
		},
		{
			name:               "invalid client cert/key pair",
			caCert:             nil,
			clientCert:         []byte("not a valid cert"),
			clientKey:          []byte("not a valid key"),
			insecureSkipVerify: false,
			expectError:        true,
			checkResult:        nil,
		},
		{
			name:               "client cert without key is ignored",
			caCert:             nil,
			clientCert:         validClientCert,
			clientKey:          nil,
			insecureSkipVerify: false,
			expectError:        false,
			checkResult: func(_ *testing.T, g Gomega, cfg *tls.Config) {
				g.Expect(cfg.Certificates).To(BeEmpty())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := NewWithT(t)

			cfg, err := TLSConfigFromSecret(tc.caCert, tc.clientCert, tc.clientKey, tc.insecureSkipVerify)
			if tc.expectError {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(cfg).ToNot(BeNil())
				g.Expect(cfg.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
				if tc.checkResult != nil {
					tc.checkResult(t, g, cfg)
				}
			}
		})
	}
}

func TestUpdateTLSConfig(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)

	// Create fetcher without TLS
	fetcher, err := NewS3Fetcher("http://localhost:9000")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fetcher.tlsConfig).To(BeNil())

	// Update with a new TLS config
	newTLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // testing
	}

	err = fetcher.UpdateTLSConfig(newTLSConfig)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fetcher.tlsConfig).To(Equal(newTLSConfig))
	g.Expect(fetcher.client).ToNot(BeNil()) // Client should be recreated
}

func TestUpdateCredentials(t *testing.T) {
	t.Parallel()
	g := NewWithT(t)

	// Create fetcher without credentials
	fetcher, err := NewS3Fetcher("http://localhost:9000")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fetcher.accessKeyID).To(BeEmpty())
	g.Expect(fetcher.secretAccessKey).To(BeEmpty())

	// Update with new credentials
	err = fetcher.UpdateCredentials("admin", "my-secret-key")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(fetcher.accessKeyID).To(Equal("admin"))
	g.Expect(fetcher.secretAccessKey).To(Equal("my-secret-key"))
	g.Expect(fetcher.client).ToNot(BeNil()) // Client should be recreated
}

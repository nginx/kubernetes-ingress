package main

import (
	v1 "k8s.io/api/core/v1"
)

// yamlSecret encapsulates all the data that we need to create the tls secrets
// that kubernetes needs as tls files.
//
// secretName   - this is what virtualservers and other objects reference
// fileName     - every secret needs to have an actual file on the disk. This is going to be the name of the file that's placed in the ./common-secrets directory
// symlinks     - a slice of paths that will symlink to the actual file. These paths are relative to the project root. For example: []string{"examples/custom-resources/oidc/tls-secret.yaml"}
// valid        - whether the generated kubernetes secret file should be valid. An invalid secret will not have the data["tls.key"] property set in the yaml file.
// templateData - has information about issuer, subject, common name (main domain), and dnsNames (subject alternate names).
// secretType   - if left empty, it will be the default v1.SecretTypeTLS value. The type is "k8s.io/api/core/v1".SecretType, which is an alias for strings.
// usedIn       - not used in the generation, it's only so we can keep track on which py tests used the specific certs
type yamlSecret struct {
	secretName   string
	fileName     string
	symlinks     []string
	valid        bool
	templateData templateData
	secretType   v1.SecretType
	usedIn       []string
}

var yamlSecrets = []yamlSecret{
	{
		secretName: "tls-secret",
		fileName:   "tls-secret.yaml",
		templateData: templateData{
			country:            []string{"IE"},
			organization:       []string{"F5 NGINX"},
			organizationalUnit: []string{"NGINX Ingress Controller"},
			locality:           []string{"Cork"},
			province:           []string{"Cork"},
			commonName:         "example.com",
			dnsNames:           []string{"foo.bar.example.com", "*.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/examples/custom-resources/api-key/cafe-secret.yaml",
			"/examples/custom-resources/backup-directive/transport-server/app-tls-secret.yaml",
			"/examples/custom-resources/backup-directive/virtual-server/cafe-secret.yaml",
			"/examples/custom-resources/basic-auth/cafe-secret.yaml",
			"/examples/custom-resources/basic-configuration/cafe-secret.yaml",
			"/examples/custom-resources/cache-policy/cafe-secret.yaml",
			"/examples/custom-resources/cross-namespace-configuration/cafe-secret.yaml",
			"/examples/custom-resources/custom-ip-listeners/virtualserver/cafe-secret.yaml",
			"/examples/custom-resources/custom-listeners/cafe-secret.yaml",
			"/examples/custom-resources/egress-mtls/egress-mtls-secret.yaml",
			"/examples/custom-resources/external-dns/cafe-secret.yaml",
			"/examples/custom-resources/externalname-services/transport-server/app-tls-secret.yaml",
			"/examples/custom-resources/foreign-namespace-upstreams/cafe-secret.yaml",
			"/examples/custom-resources/grpc-upstreams/greeter-secret.yaml",
			"/examples/custom-resources/ingress-mtls/tls-secret.yaml",
			"/examples/custom-resources/jwks/tls-secret.yaml",
			"/examples/custom-resources/oidc-fclo/tls-secret.yaml",
			"/examples/custom-resources/oidc/tls-secret.yaml",
			"/examples/custom-resources/rate-limit-tiered-jwt-claim/cafe-secret.yaml",
			"/examples/custom-resources/service-insight/service-insight-secret.yaml",
			"/examples/custom-resources/tls-passthrough/app-tls-secret.yaml",
			"/examples/custom-resources/transport-server-sni/cafe-secret.yaml",
			"/examples/custom-resources/transport-server-sni/mongo-secret.yaml",
			"/examples/ingress-resources/app-protect-dos/webapp-secret.yaml",
			"/examples/ingress-resources/app-protect-waf/cafe-secret.yaml",
			"/examples/ingress-resources/basic-auth/cafe-secret.yaml",
			"/examples/ingress-resources/complete-example/cafe-secret.yaml",
			"/examples/ingress-resources/mergeable-ingress-types/cafe-secret.yaml",
			"/examples/ingress-resources/proxy-set-headers/mergeable-ingress/cafe-secret.yaml",
			"/examples/ingress-resources/proxy-set-headers/standard-ingress/cafe-secret.yaml",
			"/examples/ingress-resources/rate-limit/cafe-secret.yaml",
			"/examples/ingress-resources/security-monitoring/cafe-secret.yaml",
			"/tests/data/appprotect/appprotect-secret.yaml",
			"/tests/data/dos/tls-secret.yaml",
			"/tests/data/egress-mtls/secret/tls-secret.yaml",
			"/tests/data/ingress-mtls/secret/tls-secret.yaml",
			"/tests/data/mgmt-configmap-keys/ssl-cert.yaml",
			"/tests/data/prometheus/secret.yaml",
			"/tests/data/service-insight/secret.yaml",
			"/tests/data/smoke/smoke-secret.yaml",
			"/tests/data/transport-server-tcp-load-balance/tcp-tls-secret.yaml",
			"/tests/data/upgrade-test-resources/secret.yaml",
			"/tests/data/virtual-server-certmanager/tls-secret.yaml",
			"/tests/data/virtual-server-grpc/tls-secret.yaml",
			"/tests/data/virtual-server-route-grpc/tls-secret.yaml",
			"/tests/data/watch-secret-namespace/tls-secret.yaml",
		},
	},

	// ==== the below ones are needed for specific pytests ===
	{
		secretName: "tls-secret",
		fileName:   "tls-secret-gb.yaml",
		templateData: templateData{
			country:      []string{"GB"},
			organization: []string{"nginx"},
			locality:     []string{"Cork"},
			province:     []string{"Cambridgeshire"},
			commonName:   "cafe.example.com",
			dnsNames:     []string{"example.com", "*.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/tests/data/tls/new-tls-secret.yaml",
			"/tests/data/virtual-server-tls/new-tls-secret.yaml",
		},
		usedIn: []string{
			"tests/suite/test_tls.py - needed for subject info and common name",
			"tests/suite/test_virtual_server_tls.py - needed for subject info and common name",
		},
	},

	{
		secretName: "default-server-secret",
		fileName:   "tls-secret-default.yaml",
		templateData: templateData{
			country:            []string{"IE"},
			organization:       []string{"F5 NGINX"},
			organizationalUnit: []string{"NGINX Ingress Controller"},
			locality:           []string{"Cork"},
			province:           []string{"Cork"},
			commonName:         "NGINXIngressController",
			dnsNames:           []string{"*.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/examples/shared-examples/default-server-secret/default-server-secret.yaml",
			"/tests/data/common/default-server-secret.yaml",
		},
		usedIn: []string{
			"tests/suite/test_default_server.py - needed for secret name and common name",
		},
	},

	{
		secretName: "default-server-secret",
		fileName:   "tls-secret-default-gb.yaml",
		templateData: templateData{
			country:      []string{"GB"},
			organization: []string{"nginx"},
			locality:     []string{"Cork"},
			province:     []string{"Cambridgeshire"},
			commonName:   "cafe.example.com",
			dnsNames:     []string{"example.com", "*.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/tests/data/default-server/new-tls-secret.yaml",
		},
		usedIn: []string{
			"tests/suite/test_default_server.py - needed for secret name and common name",
		},
	},

	{
		secretName: "default-server-secret",
		fileName:   "tls-secret-invalid.yaml",
		templateData: templateData{
			country:            []string{"IE"},
			organization:       []string{"F5 NGINX"},
			organizationalUnit: []string{"NGINX Ingress Controller"},
			locality:           []string{"Cork"},
			province:           []string{"Cork"},
			commonName:         "example.com",
			dnsNames:           []string{"*.example.com"},
		},
		valid: secretShouldHaveInvalidTLSCrt,
		symlinks: []string{
			"/tests/data/default-server/invalid-tls-secret.yaml",
		},
		usedIn: []string{
			"tests/suite/test_default_server.py - needed for the secret name",
		},
	},

	{
		secretName: "tls-secret",
		fileName:   "tls-secret-us.yaml",
		templateData: templateData{
			country:      []string{"US"},
			organization: []string{"Internet Widgits Pty Ltd"},
			locality:     []string{"San Francisco"},
			province:     []string{"CA"},
			commonName:   "cafe.example.com",
			dnsNames:     []string{"example.com", "*.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/tests/data/tls/tls-secret.yaml",
			"/tests/data/virtual-server-tls/tls-secret.yaml",
		},
		usedIn: []string{
			"tests/suite/test_tls.py - needed for subject info and common name",
			"tests/suite/test_virtual_server_tls.py - needed for subject info and common name",
		},
	},
	{
		secretName: "tls-secret",
		fileName:   "tls-secret-invalid-type-some.yaml",
		templateData: templateData{
			country:            []string{"IE"},
			organization:       []string{"F5 NGINX"},
			organizationalUnit: []string{"NGINX Ingress Controller"},
			locality:           []string{"Cork"},
			province:           []string{"Cork"},
			commonName:         "example.com",
			dnsNames:           []string{"*.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/tests/data/tls/invalid-tls-secret.yaml",
		},
		secretType: "some type",
		usedIn: []string{
			"tests/suite/test_tls.py - needed for the secretType",
		},
	},

	{
		secretName: "wildcard-tls-secret",
		fileName:   "tls-secret-invalid-type-broken.yaml",
		templateData: templateData{
			country:            []string{"IE"},
			organization:       []string{"F5 NGINX"},
			organizationalUnit: []string{"NGINX Ingress Controller"},
			locality:           []string{"Cork"},
			province:           []string{"Cork"},
			commonName:         "example.com",
			dnsNames:           []string{"*.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/tests/data/wildcard-tls-secret/invalid-wildcard-tls-secret.yaml",
		},
		secretType: "broken",
		usedIn: []string{
			"tests/suite/test_wildcard_tls_secret.py - needed for the secret name and secret type",
		},
	},

	{
		secretName: "wildcard-tls-secret",
		fileName:   "wildcard-tls-secret.yaml",
		templateData: templateData{
			country:            []string{"ES"},
			organization:       []string{"nginx"},
			organizationalUnit: []string{"example.com"},
			locality:           []string{"Cork"},
			province:           []string{"CanaryIslands"},
			commonName:         "example.com",
			dnsNames:           []string{"*.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/tests/data/wildcard-tls-secret/wildcard-tls-secret.yaml",
		},
		usedIn: []string{
			"tests/suite/test_wildcard_tls_secret.py - subject info",
		},
	},

	{
		secretName: "wildcard-tls-secret",
		fileName:   "wildcard-tls-secret-gb.yaml",
		templateData: templateData{
			country:      []string{"GB"},
			organization: []string{"nginx"},
			province:     []string{"Cambridgeshire"},
			commonName:   "example.com",
			dnsNames:     []string{"*.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/tests/data/wildcard-tls-secret/gb-wildcard-tls-secret.yaml",
		},
		usedIn: []string{
			"tests/suite/test_wildcard_tls_secret.py - subject info",
		},
	},

	{
		secretName: "egress-tls-secret",
		fileName:   "egress-tls-secret.yaml",
		templateData: templateData{
			country:            []string{"IE"},
			organization:       []string{"F5 NGINX"},
			organizationalUnit: []string{"NGINX Ingress Controller"},
			locality:           []string{"Cork"},
			province:           []string{"Cork"},
			commonName:         "example.com",
			dnsNames:           []string{"foo.bar.example.com", "*.example.com"},
		},
		valid:    secretShouldHaveValidTLSCrt,
		symlinks: []string{},
	},

	{
		secretName: "tls-secret",
		fileName:   "vs-tls-secret.yaml",
		templateData: templateData{
			country:            []string{"IE"},
			organization:       []string{"F5 NGINX"},
			organizationalUnit: []string{"NGINX Ingress Controller"},
			locality:           []string{"Cork"},
			province:           []string{"Cork"},
			commonName:         "virtual-server.example.com",
			dnsNames:           []string{"virtual-server.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/tests/data/ap-waf-grpc/tls-secret.yaml",
		},
		usedIn: []string{
			"suite/test_app_protect_waf_policies_grpc.py::TestAppProtectVSGrpc - needed for the common name",
		},
	},

	{
		secretName: "app-tls-secret",
		fileName:   "app-tls-secret.yaml",
		templateData: templateData{
			country:            []string{"IE"},
			organization:       []string{"F5 NGINX"},
			organizationalUnit: []string{"NGINX Ingress Controller"},
			locality:           []string{"Cork"},
			province:           []string{"Cork"},
			commonName:         "app.example.com",
			dnsNames:           []string{"app.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"/tests/data/common/app/secure/secret/app-tls-secret.yaml",
		},
		usedIn: []string{
			"suite/test_transport_server_backup_service.py - needed for the common name and secret name",
		},
	},
}

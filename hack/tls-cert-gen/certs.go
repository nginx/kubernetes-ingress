package main

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
			commonName:         "example.com,*.example.com",
			dnsNames:           []string{"foo.bar.example.com"},
		},
		valid: secretShouldHaveValidTLSCrt,
		symlinks: []string{
			"examples/custom-resources/oidc-fclo/tls-secret-symlinked.yaml",
		},
	},
	{
		secretName: "tls-secret",
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
	},
	{
		secretName: "tls-secret",
		fileName:   "tls-secret-invalid-type.yaml",
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
	},
}

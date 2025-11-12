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
			commonName:         "example.com",
			dnsNames:           []string{"*.example.com"},
		},
		valid: secretShouldBeValid,
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
		valid: secretShouldBeInvalid,
		symlinks: []string{
			"/tests/data/default-server/invalid-tls-secret.yaml",
		},
	},
}

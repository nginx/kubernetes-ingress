package main

import (
	"encoding/base64"
	"fmt"
	"log/slog"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const apiKeyType string = "nginx.org/apikey" //gosec:disable G101 -- constant as this is a descriptor a kubernetes secret type, not a hard coded secret

type apiKeysSecret struct {
	SecretName string            `json:"secretName"`
	Namespace  string            `json:"namespace,omitempty"`
	FileName   string            `json:"filename"`
	Symlinks   []string          `json:"symlinks,omitempty"`
	UsedIn     []string          `json:"usedIn,omitempty"`
	Entries    map[string]string `json:"entries"`
	SecretType v1.SecretType     `json:"secretType,omitempty"`
}

func generateAPIKeyFile(logger *slog.Logger, secret apiKeysSecret, projectRoot string) error {
	hashedEntries := make(map[string]string)

	for key, value := range secret.Entries {
		encoded := base64.StdEncoding.EncodeToString([]byte(value))
		hashedEntries[key] = encoded
	}

	fileContents, err := createKubeAPIKeySecretYaml(secret, hashedEntries)
	if err != nil {
		return fmt.Errorf("writing valid file for %s: %w", secret.FileName, err)
	}

	err = writeFiles(logger, fileContents, projectRoot, secret.FileName, secret.Symlinks)
	if err != nil {
		return fmt.Errorf("writing file for %s: %w", secret.FileName, err)
	}

	return nil
}

func createKubeAPIKeySecretYaml(secret apiKeysSecret, hashedEntries map[string]string) ([]byte, error) {
	s := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: secret.SecretName,
		},
		StringData: hashedEntries,
		Type:       v1.SecretType(apiKeyType),
	}

	if secret.SecretType != "" {
		s.Type = secret.SecretType
	}

	if secret.Namespace != "" {
		s.Namespace = secret.Namespace
	}

	return yaml.Marshal(s)
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	log "github.com/nginx/kubernetes-ingress/internal/logger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type jwkSecret struct {
	SecretName string        `json:"secretName"`
	Namespace  string        `json:"namespace,omitempty"`
	FileName   string        `json:"filename"`
	Symlinks   []string      `json:"symlinks,omitempty"`
	UsedIn     []string      `json:"usedIn,omitempty"`
	Key        string        `json:"key"`
	Kid        string        `json:"kid"`
	Kty        string        `json:"kty"`
	SecretType v1.SecretType `json:"secretType,omitempty"`
	JwksKey    string        `json:"jwksKey,omitempty"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	K   string `json:"k,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func generateJwksFile(logger *slog.Logger, secret jwkSecret, projectRoot string) error {
	jwks, err := generateJwks(secret.Kid, secret.Kty, secret.Key)
	if err != nil {
		return fmt.Errorf("generating JWKS for secret %s: %w", secret.SecretName, err)
	}

	fileContents, err := createKubeJwksSecretYaml(secret, jwks)
	if err != nil {
		return fmt.Errorf("writing valid file for %s: %w", secret.FileName, err)
	}

	err = writeFiles(logger, fileContents, projectRoot, secret.FileName, secret.Symlinks)
	if err != nil {
		return fmt.Errorf("writing file for %s: %w", secret.FileName, err)
	}

	return nil
}

func generateJwks(kid, kty, key string) ([]byte, error) {
	jwks := JWKS{
		Keys: []JWK{
			{
				Kty: "Oct",  // key type
				Kid: "0001", // any unique identifier
				K:   base64.StdEncoding.EncodeToString([]byte(key)),
			},
		},
	}

	if kty != "" {
		jwks.Keys[0].Kty = kty
	}
	if kid != "" {
		jwks.Keys[0].Kid = kid
	}

	return json.Marshal(jwks)
}

func createKubeJwksSecretYaml(secret jwkSecret, data []byte) ([]byte, error) {
	key := "jwk"
	if secret.JwksKey != "" {
		key = secret.JwksKey
	}
	s := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: secret.SecretName,
		},
		Type: "nginx.org/jwk",
		Data: map[string][]byte{
			key: data,
		},
	}

	if secret.SecretType != "" {
		s.Type = secret.SecretType
	}

	if secret.Namespace != "" {
		s.Namespace = secret.Namespace
	}

	return yaml.Marshal(s)
}

func removeJwksFiles(logger *slog.Logger, secret jwkSecret) error {
	filePath := filepath.Join(projectRoot, realSecretDirectory, secret.FileName)
	log.Debugf(logger, "Removing file %s", filePath)
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		err := os.Remove(filepath.Join(projectRoot, realSecretDirectory, secret.FileName))
		if err != nil {
			return fmt.Errorf("failed to remove file: %s %w", secret.FileName, err)
		}
	}

	for _, symlink := range secret.Symlinks {
		log.Debugf(logger, "Removing symlink %s", symlink)
		if _, err := os.Lstat(filepath.Join(projectRoot, symlink)); !os.IsNotExist(err) {
			err = os.Remove(filepath.Join(projectRoot, symlink))
			if err != nil {
				return fmt.Errorf("failed to remove symlink: %s %w", symlink, err)
			}
		}
	}
	return nil
}

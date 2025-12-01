package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	log "github.com/nginx/kubernetes-ingress/internal/logger"
	"golang.org/x/crypto/bcrypt"
	"sigs.k8s.io/yaml"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type htpasswdEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type htpasswdSecret struct {
	SecretName  string          `json:"secretName"`
	Namespace   string          `json:"namespace,omitempty"`
	FileName    string          `json:"filename"`
	Symlinks    []string        `json:"symlinks,omitempty"`
	UsedIn      []string        `json:"usedIn,omitempty"`
	Entries     []htpasswdEntry `json:"entries"`
	SecretType  v1.SecretType   `json:"secretType,omitempty"`
	HtpasswdKey string          `json:"htpasswdKey,omitempty"`
}

func generateHtpasswdFile(secret htpasswdSecret, projectRoot string) error {
	data := []byte{}
	for _, entry := range secret.Entries {
		hashedPassword, err := hashPassword(entry.Password)
		if err != nil {
			return fmt.Errorf("hashing password for user %s: %w", entry.Username, err)
		}
		line := fmt.Sprintf("%s:%s\n", entry.Username, hashedPassword)
		data = append(data, []byte(line)...)
	}

	fileContents, err := createKubeHTPasswdSecretYaml(secret, data)
	if err != nil {
		return fmt.Errorf("writing valid file for %s: %w", secret.FileName, err)
	}

	err = writeFiles(fileContents, projectRoot, secret.FileName, secret.Symlinks)
	if err != nil {
		return fmt.Errorf("writing file for %s: %w", secret.FileName, err)
	}

	return nil
}

func hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedBytes), nil
}

func createKubeHTPasswdSecretYaml(secret htpasswdSecret, data []byte) ([]byte, error) {
	key := "htpasswd"
	if secret.HtpasswdKey != "" {
		key = secret.HtpasswdKey
	}
	s := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: secret.SecretName,
		},
		StringData: map[string]string{
			key: string(data),
		},
		Type: "nginx.org/htpasswd",
	}

	if secret.SecretType != "" {
		s.Type = secret.SecretType
	}

	if secret.Namespace != "" {
		s.Namespace = secret.Namespace
	}

	sb, err := yaml.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshaling kubernetes secret into yaml %v: %w", s, err)
	}

	return sb, nil
}

func removeHtpasswdFiles(logger *slog.Logger, secret htpasswdSecret) error {
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

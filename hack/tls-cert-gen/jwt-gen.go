package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/nginx/kubernetes-ingress/internal/logger"
)

type jwtSecret struct {
	FileName string                 `json:"filename"`
	Symlinks []string               `json:"symlinks,omitempty"`
	UsedIn   []string               `json:"usedIn,omitempty"`
	Kid      string                 `json:"kid"`
	Issuer   string                 `json:"issuer"`
	Subject  string                 `json:"subject"`
	Claims   map[string]interface{} `json:"claims"`
	Key      string                 `json:"key"`
}

func generateJwtFile(secret jwtSecret, projectRoot string) error {
	jwt, err := generateJwt(secret.Claims, secret.Key, secret.Kid)
	if err != nil {
		return fmt.Errorf("generating JWT for secret %s: %w", secret.FileName, err)
	}
	fileContents := []byte(jwt)
	err = writeFiles(fileContents, projectRoot, secret.FileName, secret.Symlinks)
	if err != nil {
		return fmt.Errorf("writing file for %s: %w", secret.FileName, err)
	}

	return nil
}

func generateJwt(claims map[string]interface{}, key, kid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	token.Header["kid"] = kid
	return token.SignedString([]byte(key))
}

func removeJwtFiles(logger *slog.Logger, secret jwtSecret) error {
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

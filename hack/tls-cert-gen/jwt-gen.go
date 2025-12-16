package main

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/golang-jwt/jwt/v5"
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
	Invalid  bool                   `json:"invalid,omitempty"`
}

func generateJwtFile(logger *slog.Logger, secret jwtSecret, projectRoot string) error {
	jwt, err := generateJwt(secret.Claims, secret.Key, secret.Kid)
	if err != nil {
		return fmt.Errorf("generating JWT for secret %s: %w", secret.FileName, err)
	}
	if secret.Invalid {
		// Make the JWT invalid by removing the payload part
		parts := strings.Split(jwt, ".")
		jwt = parts[0] + ".." + parts[2]
	}
	fileContents := []byte(jwt)
	err = writeFiles(logger, fileContents, projectRoot, secret.FileName, secret.Symlinks)
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

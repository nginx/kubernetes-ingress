package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	log "github.com/nginx/kubernetes-ingress/internal/logger"
)

// generateTLSSecretFiles wraps creating the TLS certificate and key, and writes the actual
// file, and any symbolic links to the disk.
func generateTLSSecretFiles(logger *slog.Logger, secret yamlSecret, projectRoot string) error {
	// This part creates the tls keys (certificate and key) based on the
	// issuer, subject, and dns names data.
	td, err := renderX509Template(secret.TemplateData)
	if err != nil {
		return fmt.Errorf("printing x509.Certificate based on templatedata: %w", err)
	}

	// Pass in the same template to make it a self-signed certificate
	tlsKeys, err := generateTLSKeyPair(td, td, nil)
	if err != nil {
		return fmt.Errorf("failed generating TLS keys for hosts: (%s: %v): %w", secret.TemplateData.CommonName, secret.TemplateData.DNSNames, err)
	}

	// This part takes the created certificate and key, still in bytes, and
	// embeds them into a kubernetes tls secret yaml format. At this point the
	// fileContents is still a byte slice waiting to be written to a file.
	//
	// If the incoming secret is not valid, then the created yaml file will have
	// an empty tls.key value.
	fileContents, err := createKubeTLSSecretYaml(secret, secret.Valid, tlsKeys)
	if err != nil {
		return fmt.Errorf("writing valid file for %s: %w", secret.FileName, err)
	}

	err = writeFiles(logger, fileContents, projectRoot, secret.FileName, secret.Symlinks)
	if err != nil {
		return fmt.Errorf("writing file for %s: %w", secret.FileName, err)
	}

	return nil
}

func removeSecretFiles(logger *slog.Logger, secret yamlSecret) error {
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

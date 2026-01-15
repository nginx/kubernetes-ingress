package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

type embedCrts struct {
	Ca      embedCa `json:"ca,omitempty"`
	EmptyCa emptyCA `json:"emptyCa,omitempty"`
}

type embedCa struct {
	emptyCA
	TemplateData TemplateData `json:"templateData,omitempty"`
}

type emptyCA struct {
	CertName string `json:"certName,omitempty"`
	KeyName  string `json:"keyName,omitempty"`
}

func generateEmbedCerts(logger *slog.Logger, embeds embedCrts, filenames map[string]struct{}, cleanPtr *bool) (map[string]struct{}, error) {
	filenames, err := checkForUniqueAndCleanEmbeds(logger, filenames, embeds, cleanPtr)
	if err != nil {
		return filenames, fmt.Errorf("checking for unique and cleaning embed certs: %w", err)
	}

	caTemplate, err := renderX509Template(embeds.Ca.TemplateData)
	if err != nil {
		return filenames, fmt.Errorf("rendering CA template for bundle: %w", err)
	}

	// as it is a CA certificate, we need to modify certain parts of it
	caTemplate.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign // so we can sign another certificate and a CRL with it
	caTemplate.IsCA = true                                              // because it is a CA
	caTemplate.ExtKeyUsage = nil                                        // CA certificates should not have ExtKeyUsage

	// Need this here otherwise the certs go out of sync
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return filenames, fmt.Errorf("failed to generate private key: %w", err)
	}

	// the CA in the bundle is self-signed
	ca, err := generateTLSKeyPair(caTemplate, caTemplate, caPrivateKey)
	if err != nil {
		return filenames, fmt.Errorf("generating CA: %w", err)
	}

	// Write the CA cert and key files
	err = writeEmbedCerts(embeds.Ca.CertName, ca.cert)
	if err != nil {
		return filenames, fmt.Errorf("writing CA cert file for %s: %w", embeds.Ca.CertName, err)
	}

	err = writeEmbedCerts(embeds.Ca.KeyName, ca.key)
	if err != nil {
		return filenames, fmt.Errorf("writing CA key file for %s: %w", embeds.Ca.KeyName, err)
	}

	// generate the invalid cert and key
	emptyBytes := []byte("")

	certOut := &bytes.Buffer{}

	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: emptyBytes}); err != nil {
		return filenames, fmt.Errorf("failed to write empty data to cert bytes buffer: %w", err)
	}

	err = writeEmbedCerts(embeds.EmptyCa.CertName, certOut.Bytes())
	if err != nil {
		return filenames, fmt.Errorf("writing empty CA cert file for %s: %w", embeds.EmptyCa.CertName, err)
	}

	keyOut := &bytes.Buffer{}

	if err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: emptyBytes}); err != nil {
		return filenames, fmt.Errorf("failed to write empty data to key bytes buffer: %w", err)
	}

	err = writeEmbedCerts(embeds.EmptyCa.KeyName, keyOut.Bytes())
	if err != nil {
		return filenames, fmt.Errorf("writing empty CA key file for %s: %w", embeds.EmptyCa.KeyName, err)
	}

	return filenames, nil
}

func checkForUniqueAndCleanEmbeds(logger *slog.Logger, filenames map[string]struct{}, embeds embedCrts, cleanPtr *bool) (map[string]struct{}, error) {
	var err error

	for _, embedName := range []string{
		embeds.Ca.CertName,
		embeds.Ca.KeyName,
		embeds.EmptyCa.CertName,
		embeds.EmptyCa.KeyName,
	} {
		filenames, err = checkForUniqueAndClean(logger, filenames, embedName, nil, cleanPtr)
		if err != nil {
			return filenames, fmt.Errorf("checking for unique and cleaning keys: %w", err)
		}
	}

	return filenames, nil
}

func writeEmbedCerts(path string, fileContents []byte) error {
	err := os.WriteFile(filepath.Join(projectRoot, path), fileContents, 0o600)
	if err != nil {
		return fmt.Errorf("write file to path: %s: %w", path, err)
	}

	return nil
}

func generateEmbedIgnores(embeds embedCrts) []string {
	filesToIgnore := make([]string, 0)

	filesToIgnore = append(filesToIgnore, "\n"+
		"# Certificates and keys generated for embedding into the\n"+
		"# `internal/k8s/secrets` package.\n")

	filesToIgnore = append(filesToIgnore,
		embeds.Ca.CertName,
		embeds.Ca.KeyName,
		embeds.EmptyCa.CertName,
		embeds.EmptyCa.KeyName,
	)

	return filesToIgnore
}

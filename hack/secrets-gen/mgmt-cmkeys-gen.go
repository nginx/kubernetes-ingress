package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"time"
)

type MgmtCMKeysBundle struct {
	CaWithCrl TLSSecret `json:"caWithCrl,omitempty"`
	Client    TLSSecret `json:"client,omitempty"`
}

func generateMgmtCMKeysBundles(logger *slog.Logger, bundles []MgmtCMKeysBundle, filenames map[string]struct{}, cleanPtr *bool) (map[string]struct{}, error) {
	for _, bundle := range bundles {
		filenames, err := checkForUniqueAndClean(logger, filenames, bundle.Client.FileName, bundle.Client.Symlinks, cleanPtr)
		if err != nil {
			return filenames, fmt.Errorf("checking for unique and cleaning keys for client: %w", err)
		}

		filenames, err = checkForUniqueAndClean(logger, filenames, bundle.CaWithCrl.FileName, bundle.CaWithCrl.Symlinks, cleanPtr)
		if err != nil {
			return filenames, fmt.Errorf("checking for unique and cleaning keys for ca + crl: %w", err)
		}

		// generate the client TLS secret files
		err = generateTLSSecretFiles(logger, bundle.Client)
		if err != nil {
			return filenames, fmt.Errorf("generating client TLS secret files: %w", err)
		}

		/**
		Generate the CA with CRL TLS secret files
		*/
		caTemplate, ca, err := generateSigningCertificateAuthority(bundle.CaWithCrl.TemplateData)
		if err != nil {
			return filenames, fmt.Errorf("error generating signing certificate authority: %w", err)
		}

		// Now would be the time to write the CA + CRL into the file. In order to
		// write the CRL, we need to create it first. The client cert being revoked
		// will have its serial number hardcoded and manually created to be 2.
		revokedCertificateSerialNumber := big.NewInt(2)

		crlTemplate := x509.RevocationList{
			Issuer: caTemplate.Subject, // signed by the caCrl
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   revokedCertificateSerialNumber, // serial of the certificate being revoked
					RevocationTime: time.Now(),                     // revoke it from now
				},
			},
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(31 * 24 * time.Hour), // 31 days from now
			Number:     big.NewInt(1),                       // ID of the CRL itself
		}

		crlOut := bytes.Buffer{}
		crl, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, &caTemplate, ca.privateKey)
		if err != nil {
			return filenames, fmt.Errorf("creating revocation list: %w", err)
		}
		err = pem.Encode(&crlOut, &pem.Block{
			Type:  "X509 CRL",
			Bytes: crl,
		})
		if err != nil {
			return filenames, fmt.Errorf("encoding revocation list: %w", err)
		}

		crlContents, err := createYamlCA(bundle.CaWithCrl.SecretName, ca, crlOut.Bytes())
		if err != nil {
			return filenames, fmt.Errorf("marshaling bundle CA with CRL %s to yaml: %w", bundle.CaWithCrl.FileName, err)
		}

		err = writeFiles(logger, crlContents, bundle.CaWithCrl.FileName, bundle.CaWithCrl.Symlinks)
		if err != nil {
			return filenames, fmt.Errorf("writing bundle CA %s to project root: %w", bundle.CaWithCrl.FileName, err)
		}
	}

	return filenames, nil
}

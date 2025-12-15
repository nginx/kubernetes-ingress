package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //gosec:disable G505 -- A Certificate Revocation List needs a Subject Key Identifier, and per RFC5280, that needs to be an SHA1 hash https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	log "github.com/nginx/kubernetes-ingress/internal/logger"
)

type mtlsBundle struct {
	Ca     yamlSecret `json:"ca"`
	Client yamlSecret `json:"client,omitempty"`
	Server yamlSecret `json:"server,omitempty"`
	Crl    bool       `json:"crl,omitempty"`
}

//gocyclo:ignore
func generateMTLSBundleFiles(logger *slog.Logger, bundle mtlsBundle, projectRoot string) error {
	// Render the CA x509.Certificate template
	caTemplate, err := renderX509Template(bundle.Ca.TemplateData)
	if err != nil {
		return fmt.Errorf("rendering CA template for bundle: %w", err)
	}

	// as it is a CA certificate, we need to modify certain parts of it
	caTemplate.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign // so we can sign another certificate and a CRL with it
	caTemplate.IsCA = true                                              // because it is a CA
	caTemplate.ExtKeyUsage = nil                                        // CA certificates should not have ExtKeyUsage

	// Need this here otherwise the certs go out of sync
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	caPubKey := publicKey(caPrivateKey)

	// pub is crypto.PublicKey
	caPkBytes, _ := x509.MarshalPKIXPublicKey(caPubKey)
	caSki := sha1.Sum(caPkBytes) //gosec:disable G401 -- A Certificate Revocation List needs a Subject Key Identifier, and per RFC5280, that needs to be an SHA1 hash https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2

	caTemplate.SubjectKeyId = caSki[:]

	// the CA in the bundle is self-signed
	ca, err := generateTLSKeyPair(caTemplate, caTemplate, caPrivateKey)
	if err != nil {
		return fmt.Errorf("generating CA: %w", err)
	}

	// This is needed for signing the client and server certs below
	caCertBytes, _ := pem.Decode(ca.cert)
	caCert, err := x509.ParseCertificate(caCertBytes.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CA cert for bundle: %w", err)
	}

	// Write the CA to disk
	caContents, err := createYamlCA(bundle.Ca.SecretName, ca, nil)
	if err != nil {
		return fmt.Errorf("marshaling bundle CA %s to yaml: %w", bundle.Ca.FileName, err)
	}

	err = writeFiles(logger, caContents, projectRoot, bundle.Ca.FileName, bundle.Ca.Symlinks)
	if err != nil {
		return fmt.Errorf("writing bundle CA %s to project root: %w", bundle.Ca.FileName, err)
	}

	// =================== Client certificate ===================
	if bundle.Client.FileName != "" {
		clientTemplate, err := renderX509Template(bundle.Client.TemplateData)
		if err != nil {
			return fmt.Errorf("generating client template for bundle: %w", err)
		}

		// because this is a client certificate, we need to swap out the issuer
		clientTemplate.Issuer = caCert.Subject
		clientTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		clientTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

		client, err := generateTLSKeyPair(clientTemplate, *caCert, caPrivateKey) // signed by the CA from above
		if err != nil {
			return fmt.Errorf("generating signed client cert for bundle: %w", err)
		}

		_, err = tls.X509KeyPair(client.cert, client.key)
		if err != nil {
			return fmt.Errorf("generated client certificate validation failed: %w", err)
		}

		clientChild, _ := pem.Decode(client.cert)
		clientCert, err := x509.ParseCertificate(clientChild.Bytes)
		if err != nil {
			return fmt.Errorf("parsing client cert for bundle: %w", err)
		}
		err = clientCert.CheckSignatureFrom(caCert)
		if err != nil {
			return fmt.Errorf("checking client is signed by CA: %w", err)
		}

		// Write the signed client certificate to disk
		clientContents, err := createKubeTLSSecretYaml(bundle.Client, true, client)
		if err != nil {
			return fmt.Errorf("marshaling bundle client %s to yaml: %w", bundle.Client.FileName, err)
		}

		err = writeFiles(logger, clientContents, projectRoot, bundle.Client.FileName, bundle.Client.Symlinks)
		if err != nil {
			return fmt.Errorf("writing bundle client %s to project root: %w", bundle.Client.FileName, err)
		}
	}
	// =================== Server certificate ===================
	if bundle.Server.FileName != "" {
		serverTemplate, err := renderX509Template(bundle.Server.TemplateData)
		if err != nil {
			return fmt.Errorf("generating server template for bundle: %w", err)
		}

		// because this is a server certificate, we need to swap out the issuer
		serverTemplate.Issuer = caCert.Subject

		server, err := generateTLSKeyPair(serverTemplate, *caCert, caPrivateKey) // signed by the CA from above
		if err != nil {
			return fmt.Errorf("generating signed server cert for bundle: %w", err)
		}

		_, err = tls.X509KeyPair(server.cert, server.key)
		if err != nil {
			return fmt.Errorf("generated server certificate validation failed: %w", err)
		}

		serverChild, _ := pem.Decode(server.cert)
		serverCert, err := x509.ParseCertificate(serverChild.Bytes)
		if err != nil {
			return fmt.Errorf("parsing server cert for bundle: %w", err)
		}
		err = serverCert.CheckSignatureFrom(caCert)
		if err != nil {
			return fmt.Errorf("checking server is signed by CA: %w", err)
		}

		// Write the signed server certificate to disk
		serverContents, err := createOpaqueSecretYaml(bundle.Server, true, server, ca.cert)
		if err != nil {
			return fmt.Errorf("marshaling bundle server %s to yaml: %w", bundle.Server.FileName, err)
		}

		err = writeFiles(logger, serverContents, projectRoot, bundle.Server.FileName, bundle.Server.Symlinks)
		if err != nil {
			return fmt.Errorf("writing bundle server %s to project root: %w", bundle.Server.FileName, err)
		}
	}
	if bundle.Crl {
		// =================== CA Revocation List ===================
		crlTemplate := x509.RevocationList{
			Issuer: caTemplate.Subject,
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(52),
					RevocationTime: time.Now(),
				},
			},
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(31 * 24 * time.Hour),
			Number:     big.NewInt(1),
		}

		crlOut := bytes.Buffer{}
		crl, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, caPrivateKey)
		if err != nil {
			return fmt.Errorf("creating revocation list: %w", err)
		}
		err = pem.Encode(&crlOut, &pem.Block{
			Type:  "X509 CRL",
			Bytes: crl,
		})
		if err != nil {
			return fmt.Errorf("encoding revocation list: %w", err)
		}

		crlContents, err := createYamlCA(bundle.Ca.SecretName, ca, crlOut.Bytes())
		if err != nil {
			return fmt.Errorf("marshaling bundle CA with CRL %s to yaml: %w", bundle.Ca.FileName, err)
		}

		ext := filepath.Ext(bundle.Ca.FileName)
		crlFilename := strings.ReplaceAll(bundle.Ca.FileName, ext, "-crl"+ext)
		log.Debugf(logger, "changing file name from %s to %s", bundle.Ca.FileName, crlFilename)

		crlSymlinks := make([]string, len(bundle.Ca.Symlinks))
		for i, s := range bundle.Ca.Symlinks {
			ext = filepath.Ext(s)
			newSymlink := strings.ReplaceAll(s, ext, "-crl"+ext)

			log.Debugf(logger, "changing symlink from %s to %s", s, newSymlink)

			crlSymlinks[i] = newSymlink
		}

		err = writeFiles(logger, crlContents, projectRoot, crlFilename, crlSymlinks)
		if err != nil {
			return fmt.Errorf("writing bundle CRL %s to project root: %w", bundle.Ca.FileName, err)
		}
	}
	return nil
}

// nolint cyclo:ignore
func removeBundleFiles(logger *slog.Logger, bundle mtlsBundle) error {
	for _, secret := range []yamlSecret{bundle.Ca, bundle.Client, bundle.Server} {
		if secret.FileName == "" {
			continue
		}
		filePath := filepath.Join(projectRoot, realSecretDirectory, secret.FileName)
		log.Debugf(logger, "Removing file %s", filePath)
		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			err := os.Remove(filepath.Join(projectRoot, realSecretDirectory, secret.FileName))
			if err != nil {
				return fmt.Errorf("failed to remove file: %s %w", secret.FileName, err)
			}
		}

		if bundle.Crl && secret.SecretType == secrets.SecretTypeCA {
			ext := filepath.Ext(bundle.Ca.FileName)
			crlFilename := strings.ReplaceAll(bundle.Ca.FileName, ext, "-crl"+ext)
			log.Debugf(logger, "Removing file %s", crlFilename)
			if _, err := os.Stat(crlFilename); !os.IsNotExist(err) {
				err := os.Remove(filepath.Join(projectRoot, realSecretDirectory, crlFilename))
				if err != nil {
					return fmt.Errorf("failed to remove file: %s %w", secret.FileName+"_crl", err)
				}
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
			if bundle.Crl && secret.SecretType == secrets.SecretTypeCA {
				ext := filepath.Ext(symlink)
				newSymlink := strings.ReplaceAll(symlink, ext, "-crl"+ext)
				log.Debugf(logger, "Removing symlink %s", newSymlink)
				if _, err := os.Lstat(filepath.Join(projectRoot, newSymlink)); !os.IsNotExist(err) {
					err = os.Remove(filepath.Join(projectRoot, newSymlink))
					if err != nil {
						return fmt.Errorf("failed to remove symlink: %s %w", newSymlink, err)
					}
				}
			}
		}
	}
	return nil
}

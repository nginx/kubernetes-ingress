package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //gosec:disable G505 -- A Certificate Revocation List needs a Subject Key Identifier, and per RFC5280, that needs to be an SHA1 hash https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"time"
)

//gocyclo:ignore
func printMTLSBundle(bundle mtlsBundle, projectRoot string) error {
	// Render the CA x509.Certificate template
	caTemplate, err := renderX509Template(bundle.ca.templateData)
	if err != nil {
		return fmt.Errorf("rendering CA template for bundle: %w", err)
	}

	// as it is a CA certificate, we need to modify certain parts of it
	caTemplate.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign // so we can sign another certificate and a CRL with it
	caTemplate.IsCA = true                                              // because it is a CA

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
	caContents, err := createYamlCA(bundle.ca.secretName, ca, nil)
	if err != nil {
		return fmt.Errorf("marshaling bundle CA %s to yaml: %w", bundle.ca.fileName, err)
	}

	err = writeFiles(caContents, projectRoot, bundle.ca.fileName, bundle.ca.symlinks)
	if err != nil {
		return fmt.Errorf("writing bundle CA %s to project root: %w", bundle.ca.fileName, err)
	}

	// =================== Client certificate ===================
	clientTemplate, err := renderX509Template(bundle.client.templateData)
	if err != nil {
		return fmt.Errorf("generating client template for bundle: %w", err)
	}

	// because this is a client certificate, we need to swap out the issuer
	clientTemplate.Issuer = caCert.Subject

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
	fmt.Printf("\nclient is signed by CA\n")

	// Write the signed client certificate to disk
	clientContents, err := createKubeTLSSecretYaml(bundle.client, true, client)
	if err != nil {
		return fmt.Errorf("marshaling bundle client %s to yaml: %w", bundle.client.fileName, err)
	}

	err = writeFiles(clientContents, projectRoot, bundle.client.fileName, bundle.client.symlinks)
	if err != nil {
		return fmt.Errorf("writing bundle CA %s to project root: %w", bundle.ca.fileName, err)
	}

	// =================== Server certificate ===================
	serverTemplate, err := renderX509Template(bundle.server.templateData)
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
	fmt.Printf("\nserver is signed by CA\n")

	// Write the signed server certificate to disk
	serverContents, err := createOpaqueSecretYaml(bundle.server, true, server, ca.cert)
	if err != nil {
		return fmt.Errorf("marshaling bundle server %s to yaml: %w", bundle.server.fileName, err)
	}

	err = writeFiles(serverContents, projectRoot, bundle.server.fileName, bundle.server.symlinks)
	if err != nil {
		return fmt.Errorf("writing bundle server %s to project root: %w", bundle.server.fileName, err)
	}

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

	// Need this here otherwise the certs go out of sync
	bogusPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	bogusPublicKey := publicKey(bogusPrivateKey)

	// pub is crypto.PublicKey
	bogusPkBytes, _ := x509.MarshalPKIXPublicKey(bogusPublicKey)
	bogusSki := sha1.Sum(bogusPkBytes) //gosec:disable G401 -- A Certificate Revocation List needs a Subject Key Identifier, and per RFC5280, that needs to be an SHA1 hash https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2

	bogusCATemplate := x509.Certificate{
		PublicKey: bogusPublicKey,
		Issuer: pkix.Name{
			Country:      []string{"ES"},
			Organization: []string{"Acme"},
			Locality:     []string{"Baltimore"},
			Province:     []string{"MD"},
			CommonName:   "Test CA, emailAddress=test@example.com",
		},
		Subject: pkix.Name{
			Country:      []string{"ES"},
			Organization: []string{"Acme"},
			Locality:     []string{"Baltimore"},
			Province:     []string{"MD"},
			CommonName:   "Test CA, emailAddress=test@example.com",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(31 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		IsCA:         true,
		SubjectKeyId: bogusSki[:],
	}

	crl, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, &bogusCATemplate, bogusPrivateKey)
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

	crlContents, err := createYamlCA(bundle.ca.secretName, ca, crlOut.Bytes())
	if err != nil {
		return fmt.Errorf("marshaling bundle CA with CRL %s to yaml: %w", bundle.ca.fileName, err)
	}

	ext := filepath.Ext(bundle.ca.fileName)
	fmt.Printf("what is the ext: >%s<\n", ext)
	crlFilename := strings.ReplaceAll(bundle.ca.fileName, ext, "-crl"+ext)
	fmt.Printf("changing file name from %s to %s\n", bundle.ca.fileName, crlFilename)

	crlSymlinks := make([]string, len(bundle.ca.symlinks))
	for i, s := range bundle.ca.symlinks {
		ext = filepath.Ext(s)
		newSymlink := strings.ReplaceAll(s, ext, "-crl"+ext)

		fmt.Printf("changing symlink from %s to %s\n", s, newSymlink)

		crlSymlinks[i] = newSymlink

	}

	err = writeFiles(crlContents, projectRoot, crlFilename, crlSymlinks)
	if err != nil {
		return fmt.Errorf("writing bundle CRL %s to project root: %w", bundle.ca.fileName, err)
	}

	return nil
}

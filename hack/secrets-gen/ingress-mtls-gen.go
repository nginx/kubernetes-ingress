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
	"time"
)

type IngressMtls struct {
	Ca         CertificateInfo `json:"ca"`
	Crl        CertificateInfo `json:"crl"`
	Client     FilePaths       `json:"client"`
	Valid      ClientCerts     `json:"valid"`
	Invalid    ClientCerts     `json:"invalid"`
	NotRevoked ClientCerts     `json:"not-revoked"`
	Revoked    ClientCerts     `json:"revoked"`
}

type CertificateInfo struct {
	SecretName string `json:"secretName"`
	FilePaths
	RawCRL FilePaths `json:"rawCRL"`
}

type FilePaths struct {
	FileName string   `json:"fileName"`
	Symlinks []string `json:"symlinks"`
}
type ClientCerts struct {
	Cert FilePaths `json:"cert"`
	Key  FilePaths `json:"key"`
}

//gocyclo:ignore
func generateIngressMtlsSecrets(logger *slog.Logger, details IngressMtls, filenames map[string]struct{}, cleanPtr *bool) (map[string]struct{}, error) {
	/**
	========================================================================================
	Generate the CA that is not used to sign the CRL
	========================================================================================
	*/
	filenames, ca, err := generateStandardCertificateAuthority(logger, details, filenames, cleanPtr)
	if err != nil {
		return filenames, fmt.Errorf("generating certificate authority: %w", err)
	}

	/**
	========================================================================================
	Generate the Certificate Authority that will sign the CRL and some client certs
	========================================================================================
	*/
	filenames, caCrl, err := generateCRLAndCertificateAuthority(logger, details, filenames, cleanPtr)
	if err != nil {
		return filenames, fmt.Errorf("generating certificate authority: %w", err)
	}

	/**
	========================================================================================
	Generate the client certificates
	========================================================================================
	*/

	err = generateValidClientCert(logger, ca, projectRoot, details)
	if err != nil {
		return filenames, fmt.Errorf("generating valid client cert: %w", err)
	}

	err = generateNotRevokedClientCert(logger, caCrl, projectRoot, details)
	if err != nil {
		return filenames, fmt.Errorf("generating not-revoked client cert: %w", err)
	}

	err = generateRevokedClientCert(logger, caCrl, projectRoot, details)
	if err != nil {
		return filenames, fmt.Errorf("generating revoked client cert: %w", err)
	}

	err = generateInvalidClientCert(logger, ca, projectRoot, details)
	if err != nil {
		return filenames, fmt.Errorf("generating invalid client cert: %w", err)
	}

	return filenames, nil
}

// generateValidClientCert creates a client certificate that is valid.
// - signed by ../../secret/ca.crt
// - not signed by ca-crl.crt
// - client-key.pem goes with it
// - serial number is random (not 2)
// - not revoked by ../crl/webapp.crl (nor ../../secret/crl.crl)
// - files: valid/client-cert.pem, valid/client-key.pem
func generateValidClientCert(logger *slog.Logger, ca *JITTLSKey, projectRoot string, details IngressMtls) (err error) {
	caPem, _ := pem.Decode(ca.cert)
	caCert, err := x509.ParseCertificate(caPem.Bytes)
	if err != nil {
		return fmt.Errorf("parsing client cert for bundle: %w", err)
	}

	td := TemplateData{
		Country:            []string{"US"},
		Organization:       []string{"NGINX"},
		OrganizationalUnit: []string{"KIC"},
		Locality:           []string{"San Francisco"},
		Province:           []string{"CA"},
		CommonName:         "kic.nginx.com",
		DNSNames:           []string{"virtual-server.example.com"},
		EmailAddress:       "kubernetes@nginx.com",
		CA:                 false,
	}

	clientTemplate, err := renderX509Template(td)
	if err != nil {
		return fmt.Errorf("generating client template with renderX509Template: %w", err)
	}

	// because this is a client certificate, we need to swap out the issuer
	clientTemplate.Issuer = caCert.Subject
	clientTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	clientTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	client, err := generateTLSKeyPair(clientTemplate, *caCert, ca.privateKey) // signed by the CA from above
	if err != nil {
		return fmt.Errorf("generating signed client cert with generateTLSKeyPair: %w", err)
	}

	_, err = tls.X509KeyPair(client.cert, client.key)
	if err != nil {
		return fmt.Errorf("generated client certificate validation with tls.X509KeyPair: %w", err)
	}

	clientChild, _ := pem.Decode(client.cert)
	clientCert, err := x509.ParseCertificate(clientChild.Bytes)
	if err != nil {
		return fmt.Errorf("parsing client cert with x509.ParseCertificate: %w", err)
	}
	err = clientCert.CheckSignatureFrom(caCert)
	if err != nil {
		return fmt.Errorf("checking client is signed by CA with clientCert.CheckSignatureFrom: %w", err)
	}

	err = writeFiles(logger, client.cert, projectRoot, details.Valid.Cert.FileName, details.Valid.Cert.Symlinks)
	if err != nil {
		return fmt.Errorf("writing valid certificate %s to project root: %w", details.Crl.FileName, err)
	}

	err = writeFiles(logger, client.key, projectRoot, details.Valid.Key.FileName, details.Valid.Key.Symlinks)
	if err != nil {
		return fmt.Errorf("writing valid key %s to project root: %w", details.Crl.FileName, err)
	}

	return nil
}

// generateNotRevokedClientCert creates a client certificate that is valid and
// not revoked by the CRL. This one will be serial number 1.
// - serial is 1
// - not revoked by ../crl/webapp.crl (nor ../../secret/crl.crl)
// - signed by ../../secret/ca-crl.crt
// - not signed by ../../secret/ca.crt
// - client-key.pem goes with it
// Serial Number: 1 (0x1)
// Issuer: same as the CA that signed it
// Subject: C=US, ST=MD, L=Baltimore, O=Test Server, Limited, CN=Test Server
func generateNotRevokedClientCert(logger *slog.Logger, ca *JITTLSKey, projectRoot string, details IngressMtls) error {
	caPem, _ := pem.Decode(ca.cert)
	caCert, err := x509.ParseCertificate(caPem.Bytes)
	if err != nil {
		return fmt.Errorf("parsing client cert for bundle: %w", err)
	}

	td := TemplateData{
		Country:      []string{"US"},
		Organization: []string{"Test Server, Limited"},
		Locality:     []string{"Baltimore"},
		Province:     []string{"MD"},
		CommonName:   "Test Server",
		DNSNames:     nil,
		CA:           false,
	}

	clientTemplate, err := renderX509Template(td)
	if err != nil {
		return fmt.Errorf("generating client template with renderX509Template: %w", err)
	}

	// because this is a client certificate, we need to swap out the issuer
	clientTemplate.Issuer = caCert.Subject
	clientTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	clientTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	clientTemplate.SerialNumber = big.NewInt(1) // serial number 1

	client, err := generateTLSKeyPair(clientTemplate, *caCert, ca.privateKey) // signed by the CA from above
	if err != nil {
		return fmt.Errorf("generating signed client cert with generateTLSKeyPair: %w", err)
	}

	_, err = tls.X509KeyPair(client.cert, client.key)
	if err != nil {
		return fmt.Errorf("generated client certificate validation with tls.X509KeyPair: %w", err)
	}

	clientChild, _ := pem.Decode(client.cert)
	clientCert, err := x509.ParseCertificate(clientChild.Bytes)
	if err != nil {
		return fmt.Errorf("parsing client cert with x509.ParseCertificate: %w", err)
	}
	err = clientCert.CheckSignatureFrom(caCert)
	if err != nil {
		return fmt.Errorf("checking client is signed by CA with clientCert.CheckSignatureFrom: %w", err)
	}

	err = writeFiles(logger, client.cert, projectRoot, details.NotRevoked.Cert.FileName, details.NotRevoked.Cert.Symlinks)
	if err != nil {
		return fmt.Errorf("writing not-revoked certificate %s to project root: %w", details.NotRevoked.Cert.FileName, err)
	}

	err = writeFiles(logger, client.key, projectRoot, details.NotRevoked.Key.FileName, details.NotRevoked.Key.Symlinks)
	if err != nil {
		return fmt.Errorf("writing not-revoked key %s to project root: %w", details.NotRevoked.Key.FileName, err)
	}

	return nil
}

// generateRevokedClientCert creates a client certificate that is revoked by the
// CRL. This one will be serial number 2.
// - serial is 2
// - revoked by ../crl/webapp.crl (and also ../../secret/crl.crl)
// - signed by ../../secret/ca-crl.crt
// - not signed by ../../secret/ca.crt
// - client-key.pem goes with it
func generateRevokedClientCert(logger *slog.Logger, ca *JITTLSKey, projectRoot string, details IngressMtls) error {
	caPem, _ := pem.Decode(ca.cert)
	caCert, err := x509.ParseCertificate(caPem.Bytes)
	if err != nil {
		return fmt.Errorf("parsing client cert for bundle: %w", err)
	}

	td := TemplateData{
		Country:      []string{"US"},
		Organization: []string{"Test Server, Limited"},
		Locality:     []string{"Baltimore"},
		Province:     []string{"MD"},
		CommonName:   "Test Server",
		DNSNames:     nil,
		CA:           false,
	}

	clientTemplate, err := renderX509Template(td)
	if err != nil {
		return fmt.Errorf("generating client template with renderX509Template: %w", err)
	}

	// because this is a client certificate, we need to swap out the issuer
	clientTemplate.Issuer = caCert.Subject
	clientTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	clientTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	clientTemplate.SerialNumber = big.NewInt(2) // serial number 2

	client, err := generateTLSKeyPair(clientTemplate, *caCert, ca.privateKey) // signed by the CA from above
	if err != nil {
		return fmt.Errorf("generating signed client cert with generateTLSKeyPair: %w", err)
	}

	_, err = tls.X509KeyPair(client.cert, client.key)
	if err != nil {
		return fmt.Errorf("generated client certificate validation with tls.X509KeyPair: %w", err)
	}

	clientChild, _ := pem.Decode(client.cert)
	clientCert, err := x509.ParseCertificate(clientChild.Bytes)
	if err != nil {
		return fmt.Errorf("parsing client cert with x509.ParseCertificate: %w", err)
	}
	err = clientCert.CheckSignatureFrom(caCert)
	if err != nil {
		return fmt.Errorf("checking client is signed by CA with clientCert.CheckSignatureFrom: %w", err)
	}

	err = writeFiles(logger, client.cert, projectRoot, details.Revoked.Cert.FileName, details.Revoked.Cert.Symlinks)
	if err != nil {
		return fmt.Errorf("writing revoked certificate %s to project root: %w", details.Revoked.Cert.FileName, err)
	}

	err = writeFiles(logger, client.key, projectRoot, details.Revoked.Key.FileName, details.Revoked.Key.Symlinks)
	if err != nil {
		return fmt.Errorf("writing revoked key %s to project root: %w", details.Revoked.Key.FileName, err)
	}

	return nil
}

// generateInvalidClientCert creates a client certificate that is invalid.
// I think it's the same as the valid one, except with bytes chopped off from
// the end before encoding it.
func generateInvalidClientCert(logger *slog.Logger, ca *JITTLSKey, projectRoot string, details IngressMtls) error {
	caPem, _ := pem.Decode(ca.cert)
	caCert, err := x509.ParseCertificate(caPem.Bytes)
	if err != nil {
		return fmt.Errorf("parsing client cert for bundle: %w", err)
	}

	td := TemplateData{
		Country:            []string{"US"},
		Organization:       []string{"NGINX"},
		OrganizationalUnit: []string{"KIC"},
		Locality:           []string{"San Francisco"},
		Province:           []string{"CA"},
		CommonName:         "kic.nginx.com",
		DNSNames:           []string{"virtual-server.example.com"},
		EmailAddress:       "kubernetes@nginx.com",
		CA:                 false,
	}

	clientTemplate, err := renderX509Template(td)
	if err != nil {
		return fmt.Errorf("generating client template with renderX509Template: %w", err)
	}

	// because this is a client certificate, we need to swap out the issuer
	clientTemplate.Issuer = caCert.Subject
	clientTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	clientTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	client, err := generateTLSKeyPair(clientTemplate, *caCert, ca.privateKey) // signed by the CA from above
	if err != nil {
		return fmt.Errorf("generating signed client cert with generateTLSKeyPair: %w", err)
	}

	_, err = tls.X509KeyPair(client.cert, client.key)
	if err != nil {
		return fmt.Errorf("generated client certificate validation with tls.X509KeyPair: %w", err)
	}

	clientChild, _ := pem.Decode(client.cert)
	clientCert, err := x509.ParseCertificate(clientChild.Bytes)
	if err != nil {
		return fmt.Errorf("parsing client cert with x509.ParseCertificate: %w", err)
	}
	err = clientCert.CheckSignatureFrom(caCert)
	if err != nil {
		return fmt.Errorf("checking client is signed by CA with clientCert.CheckSignatureFrom: %w", err)
	}

	// remove bytes from the certificate and key to make them invalid
	invalidCert := make([]byte, len(client.cert))
	invalidKey := make([]byte, len(client.key))
	copy(invalidCert, client.cert)
	copy(invalidKey, client.key)

	invalidCert = append(invalidCert[:45], invalidCert[52:]...)
	invalidKey = append(invalidKey[:45], invalidKey[52:]...)

	err = writeFiles(logger, invalidCert, projectRoot, details.Invalid.Cert.FileName, details.Invalid.Cert.Symlinks)
	if err != nil {
		return fmt.Errorf("writing invalid certificate %s to project root: %w", details.Invalid.Cert.FileName, err)
	}

	err = writeFiles(logger, invalidKey, projectRoot, details.Invalid.Key.FileName, details.Invalid.Key.Symlinks)
	if err != nil {
		return fmt.Errorf("writing invalid key %s to project root: %w", details.Invalid.Key.FileName, err)
	}

	return nil
}

// generateStandardCertificateAuthority generates a signing certificate that is
// used to sign some of the client certificates.
//
// Issuer: C=US, ST=CA, L=San Francisco, O=NGINX, OU=KIC, CN=kic.nginx.com,
// emailAddress=kubernetes@nginx.com
func generateStandardCertificateAuthority(logger *slog.Logger, details IngressMtls, filenames map[string]struct{}, cleanPtr *bool) (map[string]struct{}, *JITTLSKey, error) {
	/**
	Check for filename uniqueness
	*/
	filenames, err := checkForUniqueAndClean(logger, filenames, details.Ca.FileName, details.Ca.Symlinks, cleanPtr)
	if err != nil {
		return filenames, nil, fmt.Errorf("checking for unique and clean filenames for CA: %w", err)
	}

	td := TemplateData{
		Country:            []string{"US"},
		Organization:       []string{"NGINX"},
		OrganizationalUnit: []string{"KIC"},
		Locality:           []string{"San Francisco"},
		Province:           []string{"CA"},
		CommonName:         "kic.nginx.com",
		EmailAddress:       "kubernetes@nginx.com",
		CA:                 true,
		Client:             false,
	}

	caTemplate, err := generateSigningCertificateAuthority(td)
	if err != nil {
		return filenames, nil, fmt.Errorf("error generating signing certificate authority: %w", err)
	}

	// as it is a CA certificate, we need to modify certain parts of it
	caTemplate.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign // so we can sign another certificate and a CRL with it
	caTemplate.IsCA = true                                              // because it is a CA
	caTemplate.ExtKeyUsage = nil

	// Need this here otherwise the certs go out of sync
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return filenames, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	caPubKey := publicKey(caPrivateKey)

	// pub is crypto.PublicKey
	caPkBytes, _ := x509.MarshalPKIXPublicKey(caPubKey)
	caSki := sha1.Sum(caPkBytes) //gosec:disable G401 -- A Certificate Revocation List needs a Subject Key Identifier, and per RFC5280, that needs to be an SHA1 hash https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2

	caTemplate.SubjectKeyId = caSki[:]

	// the CA in the bundle is self-signed
	ca, err := generateTLSKeyPair(caTemplate, caTemplate, caPrivateKey)
	if err != nil {
		return filenames, nil, fmt.Errorf("generating CA: %w", err)
	}

	// Write the CA to disk
	caContents, err := createYamlCA(details.Ca.SecretName, ca, nil)
	if err != nil {
		return filenames, nil, fmt.Errorf("marshaling bundle CA %s to yaml: %w", details.Ca.FileName, err)
	}

	err = writeFiles(logger, caContents, projectRoot, details.Ca.FileName, details.Ca.Symlinks)
	if err != nil {
		return filenames, nil, fmt.Errorf("writing bundle CA %s to project root: %w", details.Ca.FileName, err)
	}

	return filenames, ca, nil
}

// generateCRLAndCertificateAuthority generates a signing certificate that will be
// used to sign the CRL and some of the client certificates.
// Issuer: C=US, ST=Maryland, L=Baltimore, O=Test CA, Limited,
// OU=Server Research Department, CN=Test CA, emailAddress=test@example.com
func generateCRLAndCertificateAuthority(logger *slog.Logger, details IngressMtls, filenames map[string]struct{}, cleanPtr *bool) (map[string]struct{}, *JITTLSKey, error) {
	filenames, err := checkForUniqueAndClean(logger, filenames, details.Crl.FileName, details.Crl.Symlinks, cleanPtr)
	if err != nil {
		return nil, nil, fmt.Errorf("checking for unique and clean filenames for CRL CA: %w", err)
	}

	td := TemplateData{
		Country:            []string{"US"},
		Organization:       []string{"Test CA, Limited"},
		OrganizationalUnit: []string{"Server Research Department"},
		Locality:           []string{"Baltimore"},
		Province:           []string{"Maryland"},
		CommonName:         "Test CA",
		EmailAddress:       "test@example.com",
		CA:                 true,
		Client:             false,
	}

	caCrlTemplate, err := generateSigningCertificateAuthority(td)
	if err != nil {
		return filenames, nil, fmt.Errorf("error generating signing certificate authority: %w", err)
	}

	// as it is a CA certificate, we need to modify certain parts of it
	caCrlTemplate.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign // so we can sign another certificate and a CRL with it
	caCrlTemplate.IsCA = true                                              // because it is a CA
	caCrlTemplate.ExtKeyUsage = nil

	// Need this here otherwise the certs go out of sync
	caCrlPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return filenames, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	caCrlPubKey := publicKey(caCrlPrivateKey)

	// pub is crypto.PublicKey
	caCrlPkBytes, _ := x509.MarshalPKIXPublicKey(caCrlPubKey)
	caCrlSki := sha1.Sum(caCrlPkBytes) //gosec:disable G401 -- A Certificate Revocation List needs a Subject Key Identifier, and per RFC5280, that needs to be an SHA1 hash https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2

	caCrlTemplate.SubjectKeyId = caCrlSki[:]

	// the CA in the bundle is self-signed
	caCrl, err := generateTLSKeyPair(caCrlTemplate, caCrlTemplate, caCrlPrivateKey)
	if err != nil {
		return filenames, nil, fmt.Errorf("generating CA: %w", err)
	}

	// Now would be the time to write the CA + CRL into the file. In order to
	// write the CRL, we need to create it first. The client cert being revoked
	// will have its serial number hardcoded and manually created to be 2.
	revokedCertificateSerialNumber := big.NewInt(2)

	crlTemplate := x509.RevocationList{
		Issuer: caCrlTemplate.Subject, // signed by the caCrl
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
	crl, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, &caCrlTemplate, caCrlPrivateKey)
	if err != nil {
		return filenames, nil, fmt.Errorf("creating revocation list: %w", err)
	}
	err = pem.Encode(&crlOut, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	})
	if err != nil {
		return filenames, nil, fmt.Errorf("encoding revocation list: %w", err)
	}

	crlContents, err := createYamlCA(details.Crl.SecretName, caCrl, crlOut.Bytes())
	if err != nil {
		return filenames, nil, fmt.Errorf("marshaling bundle CA with CRL %s to yaml: %w", details.Crl.FileName, err)
	}

	err = writeFiles(logger, crlContents, projectRoot, details.Crl.FileName, details.Crl.Symlinks)
	if err != nil {
		return filenames, nil, fmt.Errorf("writing bundle CA %s to project root: %w", details.Ca.FileName, err)
	}

	err = writeFiles(logger, crlOut.Bytes(), projectRoot, details.Crl.RawCRL.FileName, details.Crl.RawCRL.Symlinks)
	if err != nil {
		return filenames, nil, fmt.Errorf("writing raw CRL %s to project root: %w", details.Crl.RawCRL.FileName, err)
	}

	return filenames, caCrl, nil
}

// generateCertificateAuthority creates a generic CA certificate based on the
// provided TemplateData. It is used by two other functions, factored out to
// reduce repetition.
func generateSigningCertificateAuthority(td TemplateData) (x509.Certificate, error) {
	cert, err := renderX509Template(td)
	if err != nil {
		return x509.Certificate{}, fmt.Errorf("error rendering certificate template: %w", err)
	}

	// as it is a CA certificate, we need to modify certain parts of it
	cert.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign // so we can sign another certificate and a CRL with it
	cert.IsCA = true                                              // because it is a CA
	cert.ExtKeyUsage = nil

	return cert, nil
}

func checkForUniqueAndClean(logger *slog.Logger, filenames map[string]struct{}, fileName string, symlinks []string, cleanPtr *bool) (map[string]struct{}, error) {
	if _, ok := filenames[fileName]; ok {
		return filenames, fmt.Errorf("duplicated filename %s", fileName)
	}
	filenames[fileName] = struct{}{}

	for _, symlink := range symlinks {
		if _, ok := filenames[symlink]; ok {
			return filenames, fmt.Errorf("duplicated symlink for file %s: %s", fileName, symlink)
		}
		filenames[symlink] = struct{}{}
	}

	if *cleanPtr {
		err := removeFiles(logger, fileName, symlinks)
		if err != nil {
			return nil, fmt.Errorf("cleaning up files: %w", err)
		}
	}

	return filenames, nil
}

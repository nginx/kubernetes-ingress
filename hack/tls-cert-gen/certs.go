package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	v1 "k8s.io/api/core/v1"
)

// yamlSecret encapsulates all the data that we need to create the tls secrets
// that kubernetes needs as tls files.
//
// secretName   - this is what virtualservers and other objects reference
// fileName     - every secret needs to have an actual file on the disk. This is going to be the name of the file that's placed in the ./common-secrets directory
// symlinks     - a slice of paths that will symlink to the actual file. These paths are relative to the project root. For example: []string{"examples/custom-resources/oidc/tls-secret.yaml"}
// valid        - whether the generated kubernetes secret file should be valid. An invalid secret will not have the data["tls.key"] property set in the yaml file.
// TemplateData - has information about issuer, subject, common name (main domain), and dnsNames (subject alternate names).
// secretType   - if left empty, it will be the default v1.SecretTypeTLS value. The type is "k8s.io/api/core/v1".SecretType, which is an alias for strings.
// usedIn       - not used in the generation, it's only so we can keep track on which py tests used the specific certs
type yamlSecret struct {
	SecretName   string        `json:"secretName"`
	Namespace    string        `json:"namespace,omitempty"`
	FileName     string        `json:"filename"`
	Symlinks     []string      `json:"symlinks,omitempty"`
	Valid        bool          `json:"valid,omitempty"`
	TemplateData TemplateData  `json:"TemplateData"`
	SecretType   v1.SecretType `json:"secretType,omitempty"`
	UsedIn       []string      `json:"usedIn,omitempty"`
}

// TemplateData is a subset of the x509.Certificate info: it pulls in some of
// the Issuer, Subject, and DNSNames properties from that struct. Motivation for
// this is to provide a complete but limited struct we need to fill out for
// every tls certificate we want to use for testing or examples.
//
// Making decisions on what data to leave out of the x509.Certificate struct is
// therefore no longer a concern.
type TemplateData struct {
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	CommonName         string   `json:"commonName,omitempty"`
	DNSNames           []string `json:"dnsNames,omitempty"`
	EmailAddress       string   `json:"emailAddress,omitempty"`
	CA                 bool     `json:"ca,omitempty"`
	Client             bool     `json:"client,omitempty"`
}

// JITTLSKey is a Just In Time TLS key representation. The only two parts that
// we need here are the bytes for the cert and the key. These two will be
// written as the data.tls.cert and data.tls.key properties of the kubernetes
// core.Secret type.
//
// This does not hold the hosts information, because that's being assembled
// elsewhere, but the data does actually contain the passed in hosts.
type JITTLSKey struct {
	cert       []byte
	key        []byte
	privateKey *ecdsa.PrivateKey
}

// generateTLSKeyPair is roughly the same function as crypto/tls/generate_cert.go in the
// go standard library. Notable differences:
//   - this one returns the cert/key as bytes rather than writing them as files
//   - takes two templates (x509.Certificate). If they are the same, it's going
//     to be a self-signed certificate
//   - keys are always valid from "now" until 4 days in the future. Given the
//     short usage window of the keys, this is enough
func generateTLSKeyPair(template, parent x509.Certificate, parentPriv *ecdsa.PrivateKey) (*JITTLSKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	if parentPriv == nil {
		parentPriv = priv
	}

	pub := publicKey(parentPriv)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &parent, pub, parentPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut := &bytes.Buffer{}

	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("failed to write data to cert bytes buffer: %w", err)
	}

	keyOut := &bytes.Buffer{}

	privBytes, err := x509.MarshalPKCS8PrivateKey(parentPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, fmt.Errorf("failed to write data to keybytes buffer: %w", err)
	}

	return &JITTLSKey{
		cert:       certOut.Bytes(),
		key:        keyOut.Bytes(),
		privateKey: parentPriv,
	}, nil
}

func renderX509Template(td TemplateData) (x509.Certificate, error) {
	validFrom := time.Now()
	validUntil := validFrom.Add(31 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return x509.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	var eku x509.ExtKeyUsage
	eku = x509.ExtKeyUsageServerAuth

	if td.Client {
		eku = x509.ExtKeyUsageClientAuth
	}
	return x509.Certificate{
		Issuer: pkix.Name{
			Country:      td.Country,
			Organization: td.Organization,
		},
		Subject: pkix.Name{
			Country:            td.Country,
			Organization:       td.Organization,
			OrganizationalUnit: td.OrganizationalUnit,
			Locality:           td.Locality,
			Province:           td.Province,
			CommonName:         td.CommonName,
		},
		DNSNames:              td.DNSNames,
		SerialNumber:          serialNumber,
		NotBefore:             validFrom,
		NotAfter:              validUntil,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku, x509.ExtKeyUsageAny, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  td.CA,
		EmailAddresses:        []string{td.EmailAddress},
	}, nil
}

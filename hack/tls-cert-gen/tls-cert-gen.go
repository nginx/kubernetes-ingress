package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	log "github.com/nginx/kubernetes-ingress/internal/logger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	secretShouldHaveValidTLSCrt   = true
	secretShouldHaveInvalidTLSCrt = false
	realSecretDirectory           = "common-secrets/"
)

var projectRoot = "" // this will be redefined in main()

// JITTLSKey is a Just In Time TLS key representation. The only two parts that
// we need here are the bytes for the cert and the key. These two will be
// written as the data.tls.cert and data.tls.key properties of the kubernetes
// core.Secret type.
//
// This does not hold the hosts information, because that's being assembled
// elsewhere, but the data does actually contain the passed in hosts.
type JITTLSKey struct {
	cert []byte
	key  []byte
}

// templateData is a subset of the x509.Certificate info: it pulls in some of
// the Issuer, Subject, and DNSNames properties from that struct. Motivation for
// this is to provide a complete but limited struct we need to fill out for
// every tls certificate we want to use for testing or examples.
//
// Making decisions on what data to leave out of the x509.Certificate struct is
// therefore no longer a concern.
type templateData struct {
	country            []string
	organization       []string
	organizationalUnit []string
	locality           []string
	province           []string
	commonName         string
	dnsNames           []string
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	var err error

	projectRoot, err = filepath.Abs("../..")
	if err != nil {
		log.Fatalf(logger, "filepath.Abs: %v", err)
	}

	filenames := make(map[string]struct{})

	for _, secret := range yamlSecrets {
		if _, ok := filenames[secret.fileName]; ok {
			log.Fatalf(logger, "secret contains duplicated files: %v", secret.fileName)
		}

		filenames[secret.fileName] = struct{}{}

		for _, symlink := range secret.symlinks {
			if _, ok := filenames[symlink]; ok {
				log.Fatalf(logger, "secret contains duplicated symlink for file %s: %s", secret.fileName, symlink)
			}

			filenames[symlink] = struct{}{}
		}

		err = printYaml(secret, projectRoot)
		if err != nil {
			log.Fatalf(logger, "Failed to print tls key: %v: %v", secret, err)
		}
	}
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

// printYaml wraps creating the TLS certificate and key, and writes the actual
// file, and any symbolic links to the disk.
func printYaml(secret yamlSecret, projectRoot string) error {
	// This part creates the tls keys (certificate and key) based on the
	// issuer, subject, and dnsnames data.
	tlsKeys, err := printTLS(secret.templateData)
	if err != nil {
		return fmt.Errorf("failed generating TLS keys for hosts: (%s: %v): %w", secret.templateData.commonName, secret.templateData.dnsNames, err)
	}

	// This part takes the created certificate and key, still in bytes, and
	// embeds them into a kubernetes tls secret yaml format. At this point the
	// fileContents is still a byteslice waiting to be written to a file.
	//
	// If the incoming secret is not valid, then the created yaml file will have
	// an empty tls.key value.
	fileContents, err := createYamlSecret(secret, secret.valid, tlsKeys)
	if err != nil {
		return fmt.Errorf("writing valid file for %s: %w", secret.fileName, err)
	}

	// This part takes care of writing the yaml file onto disk, and creating the
	// symbolic links for them. os.WriteFile will truncate the files first if
	// they exist. The SymLink function needs the symlink target to not exist,
	// so we need to walk and remove those beforehand.
	realFilePath := filepath.Join(projectRoot, realSecretDirectory, secret.fileName)
	err = os.WriteFile(realFilePath, fileContents, 0o600)
	if err != nil {
		return fmt.Errorf("write kubernetes secret to file %s: %w", secret.fileName, err)
	}

	fmt.Printf("Wrote real file: %s\n", realFilePath)

	// Remove and create symlinks
	for _, symlinkTarget := range secret.symlinks {
		absSymlinkTarget := filepath.Join(projectRoot, symlinkTarget)

		// Figure out the relative path between the directories. Involving files
		// will produce an inaccurate relative path here.
		relativeDirectory, err := filepath.Rel(filepath.Dir(absSymlinkTarget), filepath.Dir(realFilePath))
		if err != nil {
			return fmt.Errorf("relative target path relative to %s: %w", absSymlinkTarget, err)
		}

		// Attach the real file to the end of the relative directory path.
		relativeTarget := filepath.Join(relativeDirectory, filepath.Base(realFilePath))

		if _, err = os.Lstat(absSymlinkTarget); err == nil {
			// symlink exists, delete it
			err = os.Remove(absSymlinkTarget)
			if err != nil {
				return fmt.Errorf("symlink target remove %s: %w", absSymlinkTarget, err)
			}
		}

		err = os.Symlink(relativeTarget, absSymlinkTarget)
		if err != nil {
			return fmt.Errorf("symlink %s to %s: %w", symlinkTarget, realFilePath, err)
		}

		fmt.Printf(""+
			" - symlink target: %s\n"+
			" - absolute file: %s\n\n", relativeTarget, absSymlinkTarget)
	}

	return nil
}

// printTLS is roughly the same function as crypto/tls/generate_cert.go in the
// go standard library. Notable differences:
//   - this one returns the cert/key as bytes rather than writing them as files
//   - this one does not take input as flags or anything other
//   - only exception is a comma-separated list of domains the generated cert
//     should be valid for
//   - it defaults to ecdsa.P256 key type, and therefore does not have the code
//     for the other key types
//   - keys are always valid from "now" until 4 days in the future. Given the
//     short usage window of the keys, this is enough
//   - all keys are certificate authorities (isCA is set to true for all)
func printTLS(templateData templateData) (*JITTLSKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	validFrom := time.Now()
	validUntil := validFrom.Add(31 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		Issuer: pkix.Name{
			Country:      templateData.country,
			Organization: templateData.organization,
		},
		Subject: pkix.Name{
			Country:            templateData.country,
			Organization:       templateData.organization,
			OrganizationalUnit: templateData.organizationalUnit,
			Locality:           templateData.locality,
			Province:           templateData.province,
			CommonName:         templateData.commonName,
		},
		DNSNames:              templateData.dnsNames,
		SerialNumber:          serialNumber,
		NotBefore:             validFrom,
		NotAfter:              validUntil,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut := &bytes.Buffer{}

	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("failed to write data to cert bytes buffer: %w", err)
	}

	keyOut := &bytes.Buffer{}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, fmt.Errorf("failed to write data to keybytes buffer: %w", err)
	}

	return &JITTLSKey{
		cert: certOut.Bytes(),
		key:  keyOut.Bytes(),
	}, nil
}

// createYamlSecret takes in the generated TLS key in printTLS, and marshals it
// into a yaml file contents and returns that as a byteslice.
func createYamlSecret(secret yamlSecret, isValid bool, tlsKeys *JITTLSKey) ([]byte, error) {
	s := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: secret.secretName,
		},
		Data: map[string][]byte{
			v1.TLSCertKey:       tlsKeys.cert,
			v1.TLSPrivateKeyKey: tlsKeys.key,
		},
		Type: v1.SecretTypeTLS,
	}

	if secret.secretType == secrets.SecretTypeCA {
		s.Data[configs.CACrlKey] = s.Data[v1.TLSCertKey]
	}

	if !isValid {
		s.Data[v1.TLSCertKey] = []byte(``)
	}

	if secret.secretType != "" {
		s.Type = secret.secretType
	}

	sb, err := yaml.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshaling kubernetes secret into yaml %v: %w", s, err)
	}

	return sb, nil
}

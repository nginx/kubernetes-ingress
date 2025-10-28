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
	"net"
	"os"
	"strings"
	"time"

	log "github.com/nginx/kubernetes-ingress/internal/logger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var tlsKeys = []yamlSecret{
	{
		secretName: "a-test-secret",
		fileName:   "a-test-secret.yaml",
		hosts:      []string{"example.com", "example.test"},
	},
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	var err error

	for _, tlsKey := range tlsKeys {
		err = printYaml(tlsKey)
		if err != nil {
			log.Fatalf(logger, "Failed to print tls key: %v: %v", tlsKey, err)
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
func printTLS(host string) (*JITTLSKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	validFrom := time.Now()
	validUntil := validFrom.Add(4 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: validFrom,
		NotAfter:  validUntil,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		IsCA: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
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

type yamlSecret struct {
	secretName string
	fileName   string
	hosts      []string
}

func printYaml(secret yamlSecret) error {
	tlsKeys, err := printTLS(strings.Join(secret.hosts, ","))
	if err != nil {
		return fmt.Errorf("failed generating TLS keys for hosts: %v: %w", secret.hosts, err)
	}

	s := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "v1-secret-thing",
		},
		Data: map[string][]byte{
			v1.TLSCertKey:       tlsKeys.cert,
			v1.TLSPrivateKeyKey: tlsKeys.key,
		},
		Type: v1.SecretTypeTLS,
	}

	sb, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("failed to marshal kubernetes secret: %w", err)
	}

	err = os.WriteFile(secret.fileName, sb, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write kubernetes secret to file %s: %w", secret.fileName, err)
	}

	return nil
}

package grpc

import (
	"crypto/tls"
	"fmt"
)

const (
	// DefaultTLSPort is the TCP port the gRPC server listens on in TLS mode.
	DefaultTLSPort = 8443
)

// TLSConfig holds the paths to TLS certificate files, loaded from a
// Kubernetes Secret mounted into both containers.
type TLSConfig struct {
	// CertPath is the path to the server TLS certificate (tls.crt).
	CertPath string
	// KeyPath is the path to the server TLS private key (tls.key).
	KeyPath string
	// CAPath is the path to the CA certificate (ca.crt) used by the agent
	// to verify the server. Both containers mount the same Secret, so the
	// agent reads ca.crt from the same mount.
	CAPath string
}

// LoadTLSCert loads the TLS server certificate and key from disk.
func LoadTLSCert(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load TLS cert from %s and %s: %w", certPath, keyPath, err)
	}
	return cert, nil
}

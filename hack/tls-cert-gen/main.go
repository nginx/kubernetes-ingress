package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/nginx/kubernetes-ingress/internal/configs"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	log "github.com/nginx/kubernetes-ingress/internal/logger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	realSecretDirectory = "common-secrets/"
)

var projectRoot = "" // this will be redefined in main()

type secretsTypes struct {
	Certs     []yamlSecret     `json:"certs,omitempty"`
	Mtls      []mtlsBundle     `json:"mtls,omitempty"`
	Htpasswds []htpasswdSecret `json:"htpasswds,omitempty"`
	Jwks      []jwkSecret      `json:"jwks,omitempty"`
}

var secretsTypesData secretsTypes

// nolint:gocyclo
func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	var err error

	cleanPtr := flag.Bool("clean", false, "only clean the generated files")
	secretsPathPtr := flag.String("secrets-path", "../secrets.json", "path to the secrets.json file")
	flag.Parse()

	rawSecretsData, err := os.ReadFile(*secretsPathPtr)
	if err != nil {
		log.Fatalf(logger, "os.ReadFile: %v", err)
	}
	err = yaml.Unmarshal(rawSecretsData, &secretsTypesData)
	if err != nil {
		log.Fatalf(logger, "yaml.Unmarshal: %v", err)
	}

	projectRoot, err = filepath.Abs("../..")
	if err != nil {
		log.Fatalf(logger, "filepath.Abs: %v", err)
	}

	filenames := make(map[string]struct{})
	filenames, err = generateTLSCerts(logger, secretsTypesData.Certs, filenames, cleanPtr)
	if err != nil {
		log.Fatalf(logger, "generateTLSCerts: %v", err)
	}

	// Create MTLS bundles rather than individual certificates
	filenames, err = generateMTLSBundles(logger, secretsTypesData.Mtls, filenames, cleanPtr)
	if err != nil {
		log.Fatalf(logger, "generateMTLSBundles: %v", err)
	}

	filenames, err = generateHtpasswdFiles(logger, secretsTypesData.Htpasswds, filenames, cleanPtr)
	if err != nil {
		log.Fatalf(logger, "generateHtpasswdFiles: %v", err)
	}

	_, err = generateJwksFiles(logger, secretsTypesData.Jwks, filenames, cleanPtr)
	if err != nil {
		log.Fatalf(logger, "generateJwksFiles: %v", err)
	}
}

func generateJwksFiles(logger *slog.Logger, secrets []jwkSecret, filenames map[string]struct{}, cleanPtr *bool) (map[string]struct{}, error) {
	for _, secret := range secrets {
		if _, ok := filenames[secret.FileName]; ok {
			return nil, fmt.Errorf("secret contains duplicated files: %v", secret.FileName)
		}

		filenames[secret.FileName] = struct{}{}

		for _, symlink := range secret.Symlinks {
			if _, ok := filenames[symlink]; ok {
				return nil, fmt.Errorf("secret contains duplicated symlink for file %s: %s", secret.FileName, symlink)
			}

			filenames[symlink] = struct{}{}
		}

		if *cleanPtr {
			err := removeJwksFiles(logger, secret)
			if err != nil {
				return nil, fmt.Errorf("failed to remove secret files: %s %w", secret.FileName, err)
			}
			continue
		}
		err := generateJwksFile(secret, projectRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to print JWKS file: %s %w", secret.FileName, err)
		}
	}
	return filenames, nil
}

func generateHtpasswdFiles(logger *slog.Logger, secrets []htpasswdSecret, filenames map[string]struct{}, cleanPtr *bool) (map[string]struct{}, error) {
	for _, secret := range secrets {
		if _, ok := filenames[secret.FileName]; ok {
			return nil, fmt.Errorf("secret contains duplicated files: %v", secret.FileName)
		}

		filenames[secret.FileName] = struct{}{}

		for _, symlink := range secret.Symlinks {
			if _, ok := filenames[symlink]; ok {
				return nil, fmt.Errorf("secret contains duplicated symlink for file %s: %s", secret.FileName, symlink)
			}

			filenames[symlink] = struct{}{}
		}

		if *cleanPtr {
			err := removeHtpasswdFiles(logger, secret)
			if err != nil {
				return nil, fmt.Errorf("failed to remove secret files: %s %w", secret.FileName, err)
			}
			continue
		}
		err := generateHtpasswdFile(secret, projectRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to print htpasswd file: %s %w", secret.FileName, err)
		}
	}
	return filenames, nil
}

func generateMTLSBundles(logger *slog.Logger, secrets []mtlsBundle, filenames map[string]struct{}, cleanPtr *bool) (map[string]struct{}, error) {
	for _, bundle := range secrets {
		// generate bundle ca cert file and symlinks
		if _, ok := filenames[bundle.Ca.FileName]; ok {
			return nil, fmt.Errorf("bundle ca contains duplicated files: %v", bundle.Ca.FileName)
		}

		filenames[bundle.Ca.FileName] = struct{}{}

		for _, symlink := range bundle.Ca.Symlinks {
			if _, ok := filenames[symlink]; ok {
				return nil, fmt.Errorf("bundle ca contains duplicated symlink for file %s: %s", bundle.Ca.FileName, symlink)
			}

			filenames[symlink] = struct{}{}
		}

		// generate bundle client cert file and symlinks
		if _, ok := filenames[bundle.Client.FileName]; ok {
			return nil, fmt.Errorf("bundle client contains duplicated files: %v", bundle.Client.FileName)
		}
		filenames[bundle.Client.FileName] = struct{}{}

		for _, symlink := range bundle.Client.Symlinks {
			if _, ok := filenames[symlink]; ok {
				return nil, fmt.Errorf("bundle client contains duplicated symlink for file %s: %s", bundle.Client.FileName, symlink)
			}

			filenames[symlink] = struct{}{}
		}

		// generate bundle server cert file and symlinks
		if _, ok := filenames[bundle.Server.FileName]; ok {
			return nil, fmt.Errorf("bundle server contains duplicated files: %v", bundle.Server.FileName)
		}
		filenames[bundle.Server.FileName] = struct{}{}

		for _, symlink := range bundle.Server.Symlinks {
			if _, ok := filenames[symlink]; ok {
				return nil, fmt.Errorf("bundle server contains duplicated symlink for file %s: %s", bundle.Server.FileName, symlink)
			}

			filenames[symlink] = struct{}{}
		}

		if *cleanPtr {
			err := removeBundleFiles(logger, bundle)
			if err != nil {
				return nil, fmt.Errorf("failed to remove bundle files: %w", err)
			}
			continue
		}

		err := generateMTLSBundleFiles(bundle, projectRoot)
		if err != nil {
			return nil, fmt.Errorf("generateMTLSBundleFiles: %w", err)
		}
	}
	return filenames, nil
}

func generateTLSCerts(logger *slog.Logger, secrets []yamlSecret, filenames map[string]struct{}, cleanPtr *bool) (map[string]struct{}, error) {
	for _, secret := range secrets {
		if _, ok := filenames[secret.FileName]; ok {
			return nil, fmt.Errorf("secret contains duplicated files: %v", secret.FileName)
		}

		filenames[secret.FileName] = struct{}{}

		for _, symlink := range secret.Symlinks {
			if _, ok := filenames[symlink]; ok {
				return nil, fmt.Errorf("secret contains duplicated symlink for file %s: %s", secret.FileName, symlink)
			}

			filenames[symlink] = struct{}{}
		}

		if *cleanPtr {
			err := removeSecretFiles(logger, secret)
			if err != nil {
				return nil, fmt.Errorf("failed to remove secret files: %s %w", secret.FileName, err)
			}
			continue
		}
		err := generateTLSSecretFiles(secret, projectRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to print tls key: %s %w", secret.FileName, err)
		}
	}
	return filenames, nil
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

func writeFiles(fileContents []byte, projectRoot, fileName string, symlinks []string) error {
	var err error

	// This part takes care of writing the yaml file onto disk, and creating the
	// symbolic links for them. os.WriteFile will truncate the files first if
	// they exist. The SymLink function needs the symlink target to not exist,
	// so we need to walk and remove those beforehand.
	realFilePath := filepath.Join(projectRoot, realSecretDirectory, fileName)
	err = os.WriteFile(realFilePath, fileContents, 0o600)
	if err != nil {
		return fmt.Errorf("write kubernetes secret to file %s: %w", fileName, err)
	}

	fmt.Printf("Wrote real file: %s\n", realFilePath)

	// Remove and create symlinks
	for _, symlinkTarget := range symlinks {
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

// createKubeTLSSecretYaml takes in the generated TLS key in generateTLSKeyPair, and marshals it
// into a yaml file contents and returns that as a byteslice.
func createKubeTLSSecretYaml(secret yamlSecret, isValid bool, tlsKeys *JITTLSKey) ([]byte, error) {
	s := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: secret.SecretName,
		},
		Data: map[string][]byte{
			v1.TLSCertKey:       tlsKeys.cert,
			v1.TLSPrivateKeyKey: tlsKeys.key,
		},
		Type: v1.SecretTypeTLS,
	}

	if !isValid {
		s.Data[v1.TLSCertKey] = []byte(``)
	}

	if secret.SecretType != "" {
		s.Type = secret.SecretType
	}

	if secret.Namespace != "" {
		s.Namespace = secret.Namespace
	}

	sb, err := yaml.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshaling kubernetes secret into yaml %v: %w", s, err)
	}

	return sb, nil
}

// createOpaqueSecretYaml takes in the generated TLS key in generateTLSKeyPair, and marshals it
// into a yaml file contents and returns that as a byteslice.
func createOpaqueSecretYaml(secret yamlSecret, isValid bool, keyPair *JITTLSKey, caCert []byte) ([]byte, error) {
	s := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: secret.SecretName,
		},
		Data: map[string][]byte{
			v1.TLSCertKey:       keyPair.cert,
			v1.TLSPrivateKeyKey: keyPair.key,
			configs.CACrtKey:    caCert,
		},
		Type: v1.SecretTypeOpaque,
	}

	if !isValid {
		s.Data[v1.TLSCertKey] = []byte(``)
	}

	if secret.SecretType != "" {
		s.Type = secret.SecretType
	}

	sb, err := yaml.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshaling kubernetes secret into yaml %v: %w", s, err)
	}

	return sb, nil
}

// createYamlCA takes in the generated TLS key in generateTLSKeyPair, and marshals it
// into a yaml file contents and returns that as a byteslice.
func createYamlCA(secretName string, tlsKeys *JITTLSKey, crl []byte) ([]byte, error) {
	s := v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		Data: map[string][]byte{
			configs.CACrtKey: tlsKeys.cert,
		},
		Type: secrets.SecretTypeCA,
	}

	if crl != nil {
		s.Data[configs.CACrlKey] = crl
	}

	sb, err := yaml.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshaling kubernetes secret into yaml %v: %w", s, err)
	}

	return sb, nil
}

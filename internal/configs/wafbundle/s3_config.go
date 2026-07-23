package wafbundle

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Data keys the F5 WAF Policy Controller (PLM) writes to its S3 credentials,
// CA, and mTLS Secrets. Unexported: the S3ConfigSpec + LoadS3Config surface
// is enough for consumers.
const (
	// s3AccessKeyIDDefault is SeaweedFS's default access key ID.
	s3AccessKeyIDDefault = "admin"

	s3CredentialsSecretKey = "seaweedfs_admin_secret"
	s3CASecretKey          = "ca.crt"
	s3ClientCertSecretKey  = "tls.crt"
	s3ClientKeySecretKey   = "tls.key"
)

// SecretSource is the port through which LoadS3Config reads Kubernetes
// Secrets. Production wiring passes KubeClientSecretSource; tests pass an
// in-memory fake.
type SecretSource interface {
	GetSecret(namespace, name string) (*corev1.Secret, error)
}

// KubeClientSecretSource is the production SecretSource: direct API GETs
// via a kubernetes.Interface. Suitable for low read frequency (PLM: 1-3
// GETs per bundle fetch, and bundle fetches only happen on APPolicy /
// APLogConf status transitions).
type KubeClientSecretSource struct {
	Client kubernetes.Interface
}

// GetSecret fetches the named Secret from the given namespace via the Kubernetes API.
func (s *KubeClientSecretSource) GetSecret(namespace, name string) (*corev1.Secret, error) {
	if s.Client == nil {
		return nil, errors.New("s3: kube client is nil")
	}
	return s.Client.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
}

// S3ConfigSpec is the input to LoadS3Config. Secret refs are pre-parsed
// NamespacedName values (parse+validate happens once, upstream in flags.go
// via validatePLMSecretRef). A zero-value NamespacedName in CA or ClientSSL
// means "not set" — those Secrets are optional and skipped.
type S3ConfigSpec struct {
	Endpoint           string
	Credentials        types.NamespacedName
	CA                 types.NamespacedName
	ClientSSL          types.NamespacedName
	InsecureSkipVerify bool
}

// LoadS3Config reads the Secrets named by spec via src and assembles a
// ready-to-use S3Config. Stateless: safe to call at the point of each
// bundle fetch so that rotated Secrets are picked up on the very next fetch.
//
// Credentials is required. CA and ClientSSL are optional (skipped when
// Name is empty), but a ref that points at a Secret which lacks the
// required key is a hard error.
func LoadS3Config(src SecretSource, spec S3ConfigSpec) (S3Config, error) {
	if spec.Endpoint == "" {
		return S3Config{}, errors.New("s3: endpoint must not be empty")
	}
	if spec.Credentials.Name == "" {
		return S3Config{}, errors.New("s3: credentials secret ref must be set")
	}
	out := S3Config{
		Endpoint:           spec.Endpoint,
		AccessKeyID:        s3AccessKeyIDDefault,
		InsecureSkipVerify: spec.InsecureSkipVerify,
	}

	creds, err := src.GetSecret(spec.Credentials.Namespace, spec.Credentials.Name)
	if err != nil {
		return S3Config{}, fmt.Errorf("s3: get credentials secret %s: %w", spec.Credentials, err)
	}
	secretVal, ok := creds.Data[s3CredentialsSecretKey]
	if !ok || len(secretVal) == 0 {
		return S3Config{}, fmt.Errorf(
			"s3: credentials secret %s missing required key %q",
			spec.Credentials, s3CredentialsSecretKey)
	}
	out.SecretAccessKey = string(secretVal)

	if err := loadCACert(src, spec.CA, &out); err != nil {
		return S3Config{}, err
	}
	if err := loadClientSSL(src, spec.ClientSSL, &out); err != nil {
		return S3Config{}, err
	}

	return out, nil
}

// loadCACert reads the optional CA Secret named by ref into out.CACert. A
// zero-value ref is a no-op; a ref that lacks the ca.crt key is a hard error.
func loadCACert(src SecretSource, ref types.NamespacedName, out *S3Config) error {
	if ref.Name == "" {
		return nil
	}
	ca, err := src.GetSecret(ref.Namespace, ref.Name)
	if err != nil {
		return fmt.Errorf("s3: get CA secret %s: %w", ref, err)
	}
	caPem, ok := ca.Data[s3CASecretKey]
	if !ok || len(caPem) == 0 {
		return fmt.Errorf("s3: CA secret %s missing required key %q", ref, s3CASecretKey)
	}
	out.CACert = caPem
	return nil
}

// loadClientSSL reads the optional client mTLS Secret named by ref into
// out.ClientCert/ClientKey. A zero-value ref is a no-op; a ref that lacks
// tls.crt or tls.key is a hard error.
func loadClientSSL(src SecretSource, ref types.NamespacedName, out *S3Config) error {
	if ref.Name == "" {
		return nil
	}
	cs, err := src.GetSecret(ref.Namespace, ref.Name)
	if err != nil {
		return fmt.Errorf("s3: get client-ssl secret %s: %w", ref, err)
	}
	cert, hasCert := cs.Data[s3ClientCertSecretKey]
	key, hasKey := cs.Data[s3ClientKeySecretKey]
	if !hasCert || len(cert) == 0 || !hasKey || len(key) == 0 {
		return fmt.Errorf(
			"s3: client-ssl secret %s missing required keys %q and %q",
			ref, s3ClientCertSecretKey, s3ClientKeySecretKey)
	}
	out.ClientCert = cert
	out.ClientKey = key
	return nil
}

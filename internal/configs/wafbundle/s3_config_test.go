package wafbundle

import (
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

// fakeSecretSource is an in-memory SecretSource keyed by "namespace/name".
type fakeSecretSource struct {
	items map[string]*corev1.Secret
}

var errFakeNotFound = errors.New("fake: not found")

func (f *fakeSecretSource) GetSecret(namespace, name string) (*corev1.Secret, error) {
	if s, ok := f.items[namespace+"/"+name]; ok {
		return s, nil
	}
	return nil, errFakeNotFound
}

func newFakeSource(items ...*corev1.Secret) *fakeSecretSource {
	f := &fakeSecretSource{items: make(map[string]*corev1.Secret, len(items))}
	for _, s := range items {
		f.items[s.Namespace+"/"+s.Name] = s
	}
	return f
}

func secretOf(name string, data map[string][]byte) *corev1.Secret {
	s := &corev1.Secret{Data: data}
	s.Namespace = "plm"
	s.Name = name
	return s
}

func plmNN(name string) types.NamespacedName {
	return types.NamespacedName{Namespace: "plm", Name: name}
}

func TestLoadS3ConfigRequiresEndpoint(t *testing.T) {
	t.Parallel()
	_, err := LoadS3Config(newFakeSource(), S3ConfigSpec{
		Credentials: plmNN("creds"),
	})
	if err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("expected 'endpoint' error, got %v", err)
	}
}

func TestLoadS3ConfigRequiresCredentialsRef(t *testing.T) {
	t.Parallel()
	_, err := LoadS3Config(newFakeSource(), S3ConfigSpec{Endpoint: "http://filer:8333"})
	if err == nil || !strings.Contains(err.Error(), "credentials secret ref must be set") {
		t.Errorf("expected credentials-ref error, got %v", err)
	}
}

func TestLoadS3ConfigMinimalHappyPath(t *testing.T) {
	t.Parallel()
	src := newFakeSource(secretOf("creds", map[string][]byte{
		s3CredentialsSecretKey: []byte("s3cret-value"),
	}))
	got, err := LoadS3Config(src, S3ConfigSpec{
		Endpoint:    "http://filer:8333",
		Credentials: plmNN("creds"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Endpoint != "http://filer:8333" {
		t.Errorf("Endpoint = %q", got.Endpoint)
	}
	if got.AccessKeyID != s3AccessKeyIDDefault {
		t.Errorf("AccessKeyID = %q, want %q", got.AccessKeyID, s3AccessKeyIDDefault)
	}
	if got.SecretAccessKey != "s3cret-value" {
		t.Errorf("SecretAccessKey = %q", got.SecretAccessKey)
	}
	if len(got.CACert) != 0 || len(got.ClientCert) != 0 {
		t.Errorf("expected no CA/client cert, got CA=%d client=%d", len(got.CACert), len(got.ClientCert))
	}
}

func TestLoadS3ConfigWithCAAndClientCert(t *testing.T) {
	t.Parallel()
	src := newFakeSource(
		secretOf("creds", map[string][]byte{s3CredentialsSecretKey: []byte("s")}),
		secretOf("ca", map[string][]byte{s3CASecretKey: []byte("---CA-PEM---")}),
		secretOf("cli", map[string][]byte{
			s3ClientCertSecretKey: []byte("---CERT-PEM---"),
			s3ClientKeySecretKey:  []byte("---KEY-PEM---"),
		}),
	)
	got, err := LoadS3Config(src, S3ConfigSpec{
		Endpoint:    "https://filer:8333",
		Credentials: plmNN("creds"),
		CA:          plmNN("ca"),
		ClientSSL:   plmNN("cli"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got.CACert) != "---CA-PEM---" {
		t.Errorf("CACert = %q", got.CACert)
	}
	if string(got.ClientCert) != "---CERT-PEM---" || string(got.ClientKey) != "---KEY-PEM---" {
		t.Errorf("client cert/key mismatch: cert=%q key=%q", got.ClientCert, got.ClientKey)
	}
}

func TestLoadS3ConfigInsecureSkipVerifyPropagates(t *testing.T) {
	t.Parallel()
	src := newFakeSource(secretOf("creds", map[string][]byte{s3CredentialsSecretKey: []byte("s")}))
	got, err := LoadS3Config(src, S3ConfigSpec{
		Endpoint:           "http://filer:8333",
		Credentials:        plmNN("creds"),
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify not propagated")
	}
}

func TestLoadS3ConfigMissingCredentialsSecret(t *testing.T) {
	t.Parallel()
	_, err := LoadS3Config(newFakeSource(), S3ConfigSpec{
		Endpoint:    "http://filer:8333",
		Credentials: plmNN("creds"),
	})
	if err == nil || !errors.Is(err, errFakeNotFound) {
		t.Errorf("expected wrapped not-found error, got %v", err)
	}
}

func TestLoadS3ConfigMissingCredentialsKey(t *testing.T) {
	t.Parallel()
	src := newFakeSource(secretOf("creds", map[string][]byte{"wrong-key": []byte("x")}))
	_, err := LoadS3Config(src, S3ConfigSpec{
		Endpoint:    "http://filer:8333",
		Credentials: plmNN("creds"),
	})
	if err == nil || !strings.Contains(err.Error(), s3CredentialsSecretKey) {
		t.Errorf("expected error mentioning %q, got %v", s3CredentialsSecretKey, err)
	}
}

func TestLoadS3ConfigEmptyCredentialsValue(t *testing.T) {
	t.Parallel()
	src := newFakeSource(secretOf("creds", map[string][]byte{s3CredentialsSecretKey: {}}))
	_, err := LoadS3Config(src, S3ConfigSpec{
		Endpoint:    "http://filer:8333",
		Credentials: plmNN("creds"),
	})
	if err == nil {
		t.Fatalf("expected error for empty credentials value")
	}
}

func TestLoadS3ConfigCARefWithoutCACertKey(t *testing.T) {
	t.Parallel()
	src := newFakeSource(
		secretOf("creds", map[string][]byte{s3CredentialsSecretKey: []byte("s")}),
		secretOf("ca", map[string][]byte{"wrong": []byte("x")}),
	)
	_, err := LoadS3Config(src, S3ConfigSpec{
		Endpoint:    "http://filer:8333",
		Credentials: plmNN("creds"),
		CA:          plmNN("ca"),
	})
	if err == nil || !strings.Contains(err.Error(), s3CASecretKey) {
		t.Errorf("expected error mentioning %q, got %v", s3CASecretKey, err)
	}
}

func TestLoadS3ConfigClientSSLRefWithoutBothKeys(t *testing.T) {
	t.Parallel()
	src := newFakeSource(
		secretOf("creds", map[string][]byte{s3CredentialsSecretKey: []byte("s")}),
		secretOf("cli", map[string][]byte{s3ClientCertSecretKey: []byte("cert")}), // key missing
	)
	_, err := LoadS3Config(src, S3ConfigSpec{
		Endpoint:    "http://filer:8333",
		Credentials: plmNN("creds"),
		ClientSSL:   plmNN("cli"),
	})
	if err == nil || !strings.Contains(err.Error(), s3ClientKeySecretKey) {
		t.Errorf("expected error mentioning %q, got %v", s3ClientKeySecretKey, err)
	}
}

func TestKubeClientSecretSourceRejectsNilClient(t *testing.T) {
	t.Parallel()
	src := &KubeClientSecretSource{}
	if _, err := src.GetSecret("plm", "creds"); err == nil || !strings.Contains(err.Error(), "kube client is nil") {
		t.Errorf("expected 'kube client is nil' error, got %v", err)
	}
}

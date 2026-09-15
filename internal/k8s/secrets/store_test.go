package secrets

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeSecretFileManager struct {
	AddedOrUpdated map[SecretRefKey]*api_v1.Secret
	Deleted        map[SecretRefKey]bool
}

func newFakeSecretFileManager() *fakeSecretFileManager {
	return &fakeSecretFileManager{
		AddedOrUpdated: map[SecretRefKey]*api_v1.Secret{},
		Deleted:        map[SecretRefKey]bool{},
	}
}

func (m *fakeSecretFileManager) AddOrUpdateSecret(secret *api_v1.Secret, role SecretRole) Materialized {
	key := getResourceKey(&secret.ObjectMeta)
	m.AddedOrUpdated[RefKey(key, role)] = secret

	paths := m.SecretPaths(key, role)
	if role == RoleCA {
		if _, hasCRL := secret.Data[CACrlKey]; hasCRL {
			paths.CRLPath = fakeCRLPath(key)
		}
	}
	return paths
}

func (m *fakeSecretFileManager) DeleteSecret(key string, role SecretRole) {
	m.Deleted[RefKey(key, role)] = true
}

func (m *fakeSecretFileManager) SecretPaths(key string, role SecretRole) Materialized {
	return Materialized{Path: fakePath(key, role)}
}

func (m *fakeSecretFileManager) Reset() {
	m.AddedOrUpdated = map[SecretRefKey]*api_v1.Secret{}
	m.Deleted = map[SecretRefKey]bool{}
}

func fakePath(key string, role SecretRole) string {
	return fmt.Sprintf("/etc/nginx/secrets/%s_%s", role, strings.ReplaceAll(key, "/", "_"))
}

func fakeCRLPath(key string) string {
	return fmt.Sprintf("/etc/nginx/secrets/crl_%s", strings.ReplaceAll(key, "/", "_"))
}

var (
	validSecret = &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "tls-secret",
			Namespace: "default",
		},
		Type: api_v1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": validCert,
			"tls.key": validKey,
		},
	}
	invalidSecret = &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "tls-secret",
			Namespace: "default",
		},
		Type: api_v1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": invalidCert,
			"tls.key": validKey,
		},
	}
	caSecret = &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{Name: "ca-secret", Namespace: "default"},
		Type:       api_v1.SecretTypeOpaque,
		Data:       map[string][]byte{CAKey: validCACert},
	}
	caSecretWithCRL = &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{Name: "ca-secret", Namespace: "default"},
		Type:       api_v1.SecretTypeOpaque,
		Data:       map[string][]byte{CAKey: validCACert, CACrlKey: validCACert},
	}
	dualRoleSecret = &api_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{Name: "dual-secret", Namespace: "default"},
		Type:       api_v1.SecretTypeOpaque,
		Data: map[string][]byte{
			api_v1.TLSCertKey:       validCert,
			api_v1.TLSPrivateKeyKey: validKey,
			CAKey:                   validCACert,
		},
	}
)

func errorComparer(e1, e2 error) bool {
	if e1 == nil || e2 == nil {
		return errors.Is(e1, e2)
	}

	return e1.Error() == e2.Error()
}

func TestAddOrUpdateSecret(t *testing.T) {
	t.Parallel()
	manager := newFakeSecretFileManager()

	store := NewLocalSecretStore(manager)

	// Add the valid secret

	expectedManager := newFakeSecretFileManager()

	store.AddOrUpdateSecret(validSecret)

	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("AddOrUpdateSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Get the secret

	expectedSecretRef := &SecretReference{
		Secret: validSecret,
		Path:   fakePath("default/tls-secret", RoleTLS),
		Error:  nil,
	}
	expectedManager = newFakeSecretFileManager()
	expectedManager.AddedOrUpdated[RefKey("default/tls-secret", RoleTLS)] = validSecret

	manager.Reset()
	secretRef := store.GetSecret("default/tls-secret", RoleTLS)

	if diff := cmp.Diff(expectedSecretRef, secretRef, cmp.Comparer(errorComparer)); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Make the secret invalid
	expectedManager = newFakeSecretFileManager()
	expectedManager.Deleted[RefKey("default/tls-secret", RoleTLS)] = true

	manager.Reset()
	store.AddOrUpdateSecret(invalidSecret)

	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("AddOrUpdateSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Get the secret

	expectedSecretRef = &SecretReference{
		Secret: invalidSecret,
		Path:   fakePath("default/tls-secret", RoleTLS),
		Error:  errors.New("failed to validate TLS cert and key: x509: malformed certificate"),
	}
	expectedManager = newFakeSecretFileManager()

	manager.Reset()
	secretRef = store.GetSecret("default/tls-secret", RoleTLS)

	if diff := cmp.Diff(expectedSecretRef, secretRef, cmp.Comparer(errorComparer)); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Restore the valid secret

	expectedManager = newFakeSecretFileManager()
	expectedManager.AddedOrUpdated[RefKey("default/tls-secret", RoleTLS)] = validSecret

	manager.Reset()
	store.AddOrUpdateSecret(validSecret)

	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("AddOrUpdateSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Get the secret

	expectedSecretRef = &SecretReference{
		Secret: validSecret,
		Path:   fakePath("default/tls-secret", RoleTLS),
		Error:  nil,
	}
	expectedManager = newFakeSecretFileManager()

	manager.Reset()
	secretRef = store.GetSecret("default/tls-secret", RoleTLS)

	if diff := cmp.Diff(expectedSecretRef, secretRef, cmp.Comparer(errorComparer)); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Update the secret

	expectedManager = newFakeSecretFileManager()
	expectedManager.AddedOrUpdated[RefKey("default/tls-secret", RoleTLS)] = validSecret

	manager.Reset()
	// for the test, it is ok to use the same version
	store.AddOrUpdateSecret(validSecret)

	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("AddOrUpdateSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Get the secret

	expectedSecretRef = &SecretReference{
		Secret: validSecret,
		Path:   fakePath("default/tls-secret", RoleTLS),
		Error:  nil,
	}
	expectedManager = newFakeSecretFileManager()

	manager.Reset()
	secretRef = store.GetSecret("default/tls-secret", RoleTLS)

	if diff := cmp.Diff(expectedSecretRef, secretRef, cmp.Comparer(errorComparer)); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestDeleteSecretNonExisting(t *testing.T) {
	t.Parallel()
	manager := newFakeSecretFileManager()
	store := NewLocalSecretStore(manager)

	expectedManager := newFakeSecretFileManager()

	store.DeleteSecret("default/tls-secret")

	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("DeleteSecret() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestDeleteSecretValidSecret(t *testing.T) {
	t.Parallel()
	manager := newFakeSecretFileManager()
	store := NewLocalSecretStore(manager)

	// Add the valid secret

	expectedManager := newFakeSecretFileManager()

	store.AddOrUpdateSecret(validSecret)

	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("AddOrUpdateSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Get the secret

	expectedSecretRef := &SecretReference{
		Secret: validSecret,
		Path:   fakePath("default/tls-secret", RoleTLS),
		Error:  nil,
	}
	expectedManager = newFakeSecretFileManager()
	expectedManager.AddedOrUpdated[RefKey("default/tls-secret", RoleTLS)] = validSecret

	manager.Reset()
	secretRef := store.GetSecret("default/tls-secret", RoleTLS)

	if diff := cmp.Diff(expectedSecretRef, secretRef, cmp.Comparer(errorComparer)); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete the secret

	expectedManager = newFakeSecretFileManager()
	expectedManager.Deleted[RefKey("default/tls-secret", RoleTLS)] = true

	manager.Reset()
	store.DeleteSecret("default/tls-secret")

	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("DeleteSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Get the secret

	expectedSecretRef = &SecretReference{
		Path:  fakePath("default/tls-secret", RoleTLS),
		Error: errors.New("secret default/tls-secret doesn't exist"),
	}
	expectedManager = newFakeSecretFileManager()

	manager.Reset()
	secretRef = store.GetSecret("default/tls-secret", RoleTLS)

	if diff := cmp.Diff(expectedSecretRef, secretRef, cmp.Comparer(errorComparer)); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("GetSecret() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestDeleteSecretInvalidSecret(t *testing.T) {
	t.Parallel()
	manager := newFakeSecretFileManager()
	store := NewLocalSecretStore(manager)

	// Add invalid secret

	expectedManager := newFakeSecretFileManager()

	store.AddOrUpdateSecret(invalidSecret)

	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("AddOrUpdateSecret() returned unexpected result (-want +got):\n%s", diff)
	}

	// Delete invalid secret

	expectedManager = newFakeSecretFileManager()

	manager.Reset()
	store.DeleteSecret("default/tls-secret")

	if diff := cmp.Diff(expectedManager, manager); diff != "" {
		t.Errorf("DeleteSecret() returned unexpected result (-want +got):\n%s", diff)
	}
}

func TestSecretCount(t *testing.T) {
	t.Parallel()
	store := NewLocalSecretStore(newFakeSecretFileManager())

	store.AddOrUpdateSecret(validSecret)
	store.AddOrUpdateSecret(caSecret)
	if got := store.SecretCount(); got != 0 {
		t.Errorf("expected 0 before anything resolves, got %d", got)
	}

	store.GetSecret("default/tls-secret", RoleTLS)
	if got := store.SecretCount(); got != 1 {
		t.Errorf("expected 1 after one resolution, got %d", got)
	}

	// A failed resolution does not count.
	store.GetSecret("default/ca-secret", RoleTLS)
	if got := store.SecretCount(); got != 1 {
		t.Errorf("expected an invalid resolution not to count, got %d", got)
	}
}

func TestGetSecretRecoversWhenSecretBecomesValid(t *testing.T) {
	t.Parallel()
	manager := newFakeSecretFileManager()
	store := NewLocalSecretStore(manager)

	store.AddOrUpdateSecret(invalidSecret)

	ref := store.GetSecret("default/tls-secret", RoleTLS)
	if ref.Error == nil {
		t.Fatal("expected the invalid Secret to be rejected")
	}
	if len(manager.AddedOrUpdated) != 0 {
		t.Errorf("expected no file for an invalid Secret, got %v", manager.AddedOrUpdated)
	}

	manager.Reset()
	store.AddOrUpdateSecret(validSecret)

	wantKey := RefKey("default/tls-secret", RoleTLS)
	if _, written := manager.AddedOrUpdated[wantKey]; !written {
		t.Error("expected the Secret to be materialized when it became valid")
	}

	ref = store.GetSecret("default/tls-secret", RoleTLS)
	if ref.Error != nil {
		t.Errorf("expected the restored Secret to be valid, got %v", ref.Error)
	}
	if ref.Path != fakePath("default/tls-secret", RoleTLS) {
		t.Errorf("expected Path %q, got %q", fakePath("default/tls-secret", RoleTLS), ref.Path)
	}
}

func TestGetSecretTwoRoles(t *testing.T) {
	t.Parallel()
	manager := newFakeSecretFileManager()
	store := NewLocalSecretStore(manager)
	store.AddOrUpdateSecret(dualRoleSecret)

	tlsRef := store.GetSecret("default/dual-secret", RoleTLS)
	caRef := store.GetSecret("default/dual-secret", RoleCA)

	if tlsRef.Error != nil {
		t.Errorf("expected RoleTLS to resolve, got %v", tlsRef.Error)
	}
	if caRef.Error != nil {
		t.Errorf("expected RoleCA to resolve, got %v", caRef.Error)
	}
	if tlsRef.Path == caRef.Path {
		t.Errorf("expected distinct paths per role, both were %q", tlsRef.Path)
	}
	if len(manager.AddedOrUpdated) != 2 {
		t.Errorf("expected two files, got %v", manager.AddedOrUpdated)
	}
}

func TestGetSecretPopulatesPathOnEveryVerdict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		secret    *api_v1.Secret
		wantError bool
	}{
		{
			name:   "valid secret",
			secret: validSecret,
		},
		{
			name:      "secret that fails validation",
			secret:    invalidSecret,
			wantError: true,
		},
		{
			name:      "secret absent from the store",
			secret:    nil,
			wantError: true,
		},
	}

	wantPath := fakePath("default/tls-secret", RoleTLS)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := NewLocalSecretStore(newFakeSecretFileManager())
			if test.secret != nil {
				store.AddOrUpdateSecret(test.secret)
			}

			ref := store.GetSecret("default/tls-secret", RoleTLS)

			if test.wantError && ref.Error == nil {
				t.Fatal("GetSecret() expected a validation error, got none")
			}
			if !test.wantError && ref.Error != nil {
				t.Fatalf("GetSecret() unexpected error: %v", ref.Error)
			}
			if ref.Path != wantPath {
				t.Errorf("GetSecret() Path = %q, want %q whatever the verdict", ref.Path, wantPath)
			}
		})
	}
}

func TestGetSecretCRLPathOnlyOnValidVerdict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		secret      *api_v1.Secret
		key         string
		wantError   bool
		wantCRLPath string
	}{
		{
			name:        "valid CA secret carrying ca.crl",
			secret:      caSecretWithCRL,
			key:         "default/ca-secret",
			wantCRLPath: fakeCRLPath("default/ca-secret"),
		},
		{
			name:        "valid CA secret without ca.crl",
			secret:      caSecret,
			key:         "default/ca-secret",
			wantCRLPath: "",
		},
		{
			name:        "secret invalid for the CA role",
			secret:      validSecret,
			key:         "default/tls-secret",
			wantError:   true,
			wantCRLPath: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store := NewLocalSecretStore(newFakeSecretFileManager())
			store.AddOrUpdateSecret(test.secret)

			ref := store.GetSecret(test.key, RoleCA)

			if test.wantError && ref.Error == nil {
				t.Fatal("GetSecret() expected a validation error, got none")
			}
			if !test.wantError && ref.Error != nil {
				t.Fatalf("GetSecret() unexpected error: %v", ref.Error)
			}
			if ref.CRLPath != test.wantCRLPath {
				t.Errorf("GetSecret() CRLPath = %q, want %q", ref.CRLPath, test.wantCRLPath)
			}
			// Path is populated regardless, including on the error verdict.
			if ref.Path != fakePath(test.key, RoleCA) {
				t.Errorf("GetSecret() Path = %q, want %q", ref.Path, fakePath(test.key, RoleCA))
			}
		})
	}
}

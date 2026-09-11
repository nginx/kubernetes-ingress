package secrets

import (
	"fmt"
	"sync"

	api_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretReference holds a reference to a secret stored on the file system.
type SecretReference struct {
	Secret  *api_v1.Secret
	Path    string
	CRLPath string
	Error   error
}

// Materialised is what a file manager produced for one (key, role). CRLPath is set
// only for RoleCA, and only when the Secret carries ca.crl.
type Materialised struct {
	Path    string
	CRLPath string
}

// SecretFileManager manages secrets on the file system.
type SecretFileManager interface {
	AddOrUpdateSecret(secret *api_v1.Secret, role SecretRole) Materialised
	DeleteSecret(key string, role SecretRole)
	SecretPaths(key string, role SecretRole) Materialised
}

// SecretStore stores secrets that the Ingress Controller uses.
type SecretStore interface {
	AddOrUpdateSecret(secret *api_v1.Secret)
	DeleteSecret(key string)
	GetSecret(key string, role SecretRole) *SecretReference
	ResolvedRoles(key string) []SecretRole
	SecretCount() int
}

// storeKey identifies one cached validation verdict. The same Secret can be
// resolved in several roles with different verdicts, so the role is part of the key.
type storeKey struct {
	secret string
	role   SecretRole
}

// secretEntry is the store's bookkeeping for one (secret, role). Kept separate
// from SecretReference so materialisation state stays inside this package.
type secretEntry struct {
	ref          *SecretReference
	materialised bool
}

// SecretRefKey identifies a SecretReference within a resource's SecretRefs map.
// One resource can reference the same Secret in more than one role -- a
// VirtualServer with spec.tls.secret: foo plus an EgressMTLS policy with
// trustedCertSecret: foo -- so the role is part of the key.
type SecretRefKey struct {
	Key  string
	Role SecretRole
}

// LocalSecretStore implements SecretStore interface.
// It validates the secrets and manages them on the file system (via SecretFileManager).
type LocalSecretStore struct {
	secrets map[string]*api_v1.Secret
	refs    map[storeKey]*secretEntry
	manager SecretFileManager
	lock    sync.RWMutex
}

// NewLocalSecretStore creates a new LocalSecretStore.
func NewLocalSecretStore(manager SecretFileManager) *LocalSecretStore {
	return &LocalSecretStore{
		secrets: make(map[string]*api_v1.Secret),
		refs:    make(map[storeKey]*secretEntry),
		manager: manager,
	}
}

// AddOrUpdateSecret adds or updates a Secret and re-validates every role it has
// already been resolved in, re-materialising or removing files as each verdict
// changes. Roles nobody has resolved are untouched.
func (s *LocalSecretStore) AddOrUpdateSecret(secret *api_v1.Secret) {
	s.lock.Lock()
	defer s.lock.Unlock()

	key := getResourceKey(&secret.ObjectMeta)
	s.secrets[key] = secret

	for refKey, entry := range s.refs {
		if refKey.secret != key {
			continue
		}

		entry.ref.Secret = secret
		entry.ref.Error = ValidateSecretForRole(secret, refKey.role)

		paths := s.manager.SecretPaths(key, refKey.role)
		entry.ref.setPaths(paths)

		if entry.ref.Error != nil {
			if entry.materialised {
				s.manager.DeleteSecret(key, refKey.role)
				entry.materialised = false
			}
			continue
		}
		paths = s.manager.AddOrUpdateSecret(secret, refKey.role)
		entry.ref.setPaths(paths)
		entry.materialised = true
	}
}

// DeleteSecret removes a Secret and every file it materialised, fanning out over
// each role it was resolved in.
func (s *LocalSecretStore) DeleteSecret(key string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, exists := s.secrets[key]; !exists {
		return
	}
	delete(s.secrets, key)

	for refKey, entry := range s.refs {
		if refKey.secret != key {
			continue
		}
		if entry.materialised {
			s.manager.DeleteSecret(key, refKey.role)
		}
		delete(s.refs, refKey)
	}
}

// GetSecret returns the SecretReference for a Secret in the given role.
// If the secret is valid and not yet on disk it is materialised. Path and CRLPath are populated whatever
// the verdict, so callers always have a non-empty path to render. If the Secret is missing or invalid, the
// Error field is set.
func (s *LocalSecretStore) GetSecret(key string, role SecretRole) *SecretReference {
	s.lock.Lock()
	defer s.lock.Unlock()

	refKey := storeKey{secret: key, role: role}
	if entry, ok := s.refs[refKey]; ok {
		return entry.ref
	}

	paths := s.manager.SecretPaths(key, role)
	ref := &SecretReference{Path: paths.Path, CRLPath: paths.CRLPath}

	secret, exists := s.secrets[key]
	if !exists {
		ref.Error = fmt.Errorf("secret %s doesn't exist", key)
		s.refs[refKey] = &secretEntry{ref: ref}
		return ref
	}

	ref.Secret = secret
	ref.Error = ValidateSecretForRole(secret, role)

	entry := &secretEntry{ref: ref}
	if ref.Error == nil {
		paths = s.manager.AddOrUpdateSecret(secret, role)
		ref.setPaths(paths)
		entry.materialised = true
	}
	s.refs[refKey] = entry
	return ref
}

// SecretCount returns the number of distinct Secrets that resolved successfully in
// at least one role. It deliberately excludes Secrets the store holds but nothing
// references, which is the number reported to telemetry.
func (s *LocalSecretStore) SecretCount() int {
	s.lock.RLock()
	defer s.lock.RUnlock()

	resolved := make(map[string]struct{})
	for key, entry := range s.refs {
		if entry.ref.Error == nil {
			resolved[key.secret] = struct{}{}
		}
	}
	return len(resolved)
}

// ResolvedRoles returns the roles this Secret has been resolved in.
func (s *LocalSecretStore) ResolvedRoles(key string) []SecretRole {
	s.lock.RLock()
	defer s.lock.RUnlock()

	roles := []SecretRole{}
	for refKey, entry := range s.refs {
		if refKey.secret != key {
			continue
		}
		if entry.ref.Error == nil {
			roles = append(roles, refKey.role)
		}
	}
	return roles
}

func getResourceKey(meta *metav1.ObjectMeta) string {
	return fmt.Sprintf("%s/%s", meta.Namespace, meta.Name)
}

func (r *SecretReference) setPaths(paths Materialised) {
	r.Path = paths.Path
	r.CRLPath = paths.CRLPath
}

// RefKey builds the key under which a SecretReference for the given Secret and
// role is stored in a resource's SecretRefs map.
func RefKey(key string, role SecretRole) SecretRefKey {
	return SecretRefKey{Key: key, Role: role}
}

// FakeSecretStore is a fake implementation of SecretStore.
type FakeSecretStore struct {
	secrets map[string]*SecretReference
}

// NewFakeSecretsStore creates a new FakeSecretStore.
func NewFakeSecretsStore(secrets map[string]*SecretReference) *FakeSecretStore {
	return &FakeSecretStore{
		secrets: secrets,
	}
}

// NewEmptyFakeSecretsStore creates a new empty FakeSecretStore.
func NewEmptyFakeSecretsStore() *FakeSecretStore {
	return &FakeSecretStore{
		secrets: make(map[string]*SecretReference),
	}
}

// AddOrUpdateSecret is a fake implementation of AddOrUpdateSecret.
func (s *FakeSecretStore) AddOrUpdateSecret(secret *api_v1.Secret) {
	secretRef, exists := s.secrets[getResourceKey(&secret.ObjectMeta)]
	if !exists {
		secretRef = &SecretReference{Secret: secret}
	} else {
		secretRef.Secret = secret
	}
	s.secrets[getResourceKey(&secret.ObjectMeta)] = secretRef
}

// DeleteSecret is a fake implementation of DeleteSecret.
func (s *FakeSecretStore) DeleteSecret(_ string) {
}

// GetSecret is a fake implementation of GetSecret.
func (s *FakeSecretStore) GetSecret(key string, _ SecretRole) *SecretReference {
	secretRef, exists := s.secrets[key]
	if !exists {
		return &SecretReference{
			Error: fmt.Errorf("secret doesn't exist"),
		}
	}

	return secretRef
}

// SecretCount returns the number of secrets in the store.
func (s *FakeSecretStore) SecretCount() int {
	return len(s.secrets)
}

// ResolvedRoles is a fake implementation of ResolvedRoles. The fake store is not
// role-aware, so it reports no roles: callers then treat the update conservatively
// and force a reload. Per-role behaviour is covered by LocalSecretStore tests.
func (s *FakeSecretStore) ResolvedRoles(_ string) []SecretRole {
	return nil
}

package secrets

import (
	"fmt"
	"slices"
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

// Materialized is what a file manager produced for one (key, role). CRLPath is set
// only for RoleCA, and only when the Secret carries ca.crl.
type Materialized struct {
	Path    string
	CRLPath string
}

// SecretFileManager manages secrets on the file system.
type SecretFileManager interface {
	AddOrUpdateSecret(secret *api_v1.Secret, role SecretRole) Materialized
	DeleteSecret(key string, role SecretRole)
	SecretPaths(key string, role SecretRole) Materialized
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
// from SecretReference so materialization state stays inside this package.
type secretEntry struct {
	ref          *SecretReference
	materialized bool
}

// SecretRefKey identifies a SecretReference within a resource's SecretRefs map.
// One resource can reference the same Secret in more than one role -- a
// VirtualServer with spec.tls.secret: foo plus an EgressMTLS policy with
// trustedCertSecret: foo -- so the role is part of the key.
type SecretRefKey struct {
	Key  string
	Role SecretRole
}

// SecretResolverFunc resolves a Secret by key on demand when it is missing from the store.
type SecretResolverFunc func(key string) (*api_v1.Secret, error)

// LocalSecretStoreOption configures a LocalSecretStore.
type LocalSecretStoreOption func(*LocalSecretStore)

// WithSecretResolver sets a fallback resolver used when a Secret is not in the store.
func WithSecretResolver(resolver SecretResolverFunc) LocalSecretStoreOption {
	return func(s *LocalSecretStore) {
		s.resolver = resolver
	}
}

// LocalSecretStore implements SecretStore interface.
// It validates the secrets and manages them on the file system (via SecretFileManager).
type LocalSecretStore struct {
	secrets  map[string]*api_v1.Secret
	refs     map[storeKey]*secretEntry
	manager  SecretFileManager
	resolver SecretResolverFunc
	lock     sync.RWMutex
}

// NewLocalSecretStore creates a new LocalSecretStore.
func NewLocalSecretStore(manager SecretFileManager, opts ...LocalSecretStoreOption) *LocalSecretStore {
	s := &LocalSecretStore{
		secrets: make(map[string]*api_v1.Secret),
		refs:    make(map[storeKey]*secretEntry),
		manager: manager,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// AddOrUpdateSecret adds or updates a Secret and re-validates every role it has
// already been resolved in, re-materializing or removing files as each verdict
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

		err := ValidateSecretForRole(secret, refKey.role)
		paths := s.manager.SecretPaths(key, refKey.role)
		materialized := entry.materialized

		if err != nil {
			if materialized {
				s.manager.DeleteSecret(key, refKey.role)
				materialized = false
			}
		} else {
			paths = s.manager.AddOrUpdateSecret(secret, refKey.role)
			materialized = true
		}

		entry.ref = &SecretReference{
			Secret:  secret,
			Path:    paths.Path,
			CRLPath: paths.CRLPath,
			Error:   err,
		}
		entry.materialized = materialized
	}
}

// DeleteSecret removes a Secret and every file it materialized, fanning out over
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
		if entry.materialized {
			s.manager.DeleteSecret(key, refKey.role)
		}
		delete(s.refs, refKey)
	}
}

// HoldsSecret reports whether a Secret with the given key is currently cached in memory.
func (s *LocalSecretStore) HoldsSecret(key string) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	_, exists := s.secrets[key]
	return exists
}

// GetSecret returns the SecretReference for a Secret in the given role, materializing
// it if valid and not yet on disk. Path is set whatever the verdict so callers never
// render an empty path; inlined roles (OIDC, API key, WAF bundle, license) have none.
// CRLPath is set only on a valid RoleCA verdict. Error is set if missing or invalid.
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
	if !exists && s.resolver != nil {
		if resolved, err := s.resolver(key); err == nil && resolved != nil {
			secret = resolved
			s.secrets[key] = secret
			exists = true
		}
	}
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
		entry.materialized = true
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

	var roles []SecretRole
	for refKey, entry := range s.refs {
		if refKey.secret == key && entry.ref.Error == nil {
			roles = append(roles, refKey.role)
		}
	}

	slices.Sort(roles)
	return roles
}

func getResourceKey(meta *metav1.ObjectMeta) string {
	return fmt.Sprintf("%s/%s", meta.Namespace, meta.Name)
}

func (r *SecretReference) setPaths(paths Materialized) {
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
	secrets map[string]*api_v1.Secret
	refs    map[SecretRefKey]*SecretReference
	lock    sync.RWMutex
}

// NewFakeSecretsStore creates a new FakeSecretStore.
func NewFakeSecretsStore(refs map[SecretRefKey]*SecretReference) *FakeSecretStore {
	store := &FakeSecretStore{
		secrets: make(map[string]*api_v1.Secret),
		refs:    make(map[SecretRefKey]*SecretReference),
	}

	for key, ref := range refs {
		clone := *ref
		store.refs[key] = &clone

		if ref.Secret != nil {
			store.secrets[key.Key] = ref.Secret
		}
	}

	return store
}

// NewEmptyFakeSecretsStore creates a new empty FakeSecretStore.
func NewEmptyFakeSecretsStore() *FakeSecretStore {
	return NewFakeSecretsStore(nil)
}

// AddOrUpdateSecret is a fake implementation of AddOrUpdateSecret.
func (s *FakeSecretStore) AddOrUpdateSecret(secret *api_v1.Secret) {
	s.lock.Lock()
	defer s.lock.Unlock()

	key := getResourceKey(&secret.ObjectMeta)
	s.secrets[key] = secret

	for refKey, oldRef := range s.refs {
		if refKey.Key != key {
			continue
		}

		err := ValidateSecretForRole(secret, refKey.Role)
		paths := defaultFakeSecretPaths(key, refKey.Role)

		if oldRef.Path != "" {
			paths.Path = oldRef.Path
		}

		if err == nil && refKey.Role == RoleCA {
			if _, hasCRL := secret.Data[CACrlKey]; hasCRL {
				if oldRef.CRLPath != "" {
					paths.CRLPath = oldRef.CRLPath
				} else {
					paths.CRLPath = paths.Path + ".crl"
				}
			}
		}

		// Replace the published reference rather than mutating it.
		s.refs[refKey] = &SecretReference{
			Secret:  secret,
			Path:    paths.Path,
			CRLPath: paths.CRLPath,
			Error:   err,
		}
	}
}

// DeleteSecret is a fake implementation of DeleteSecret.
func (s *FakeSecretStore) DeleteSecret(key string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.secrets, key)

	for refKey := range s.refs {
		if refKey.Key == key {
			delete(s.refs, refKey)
		}
	}
}

// GetSecret is a fake implementation of GetSecret.
func (s *FakeSecretStore) GetSecret(key string, role SecretRole) *SecretReference {
	s.lock.Lock()
	defer s.lock.Unlock()

	refKey := RefKey(key, role)
	if ref, exists := s.refs[refKey]; exists {
		return ref
	}

	paths := defaultFakeSecretPaths(key, role)
	secret, exists := s.secrets[key]
	if !exists {
		ref := &SecretReference{
			Path:    paths.Path,
			CRLPath: paths.CRLPath,
			Error:   fmt.Errorf("secret %s doesn't exist", key),
		}
		s.refs[refKey] = ref
		return ref
	}

	ref := &SecretReference{
		Secret:  secret,
		Error:   ValidateSecretForRole(secret, role),
		Path:    paths.Path,
		CRLPath: paths.CRLPath,
	}
	s.refs[refKey] = ref

	return ref
}

// SecretCount returns the number of secrets in the store.
func (s *FakeSecretStore) SecretCount() int {
	s.lock.RLock()
	defer s.lock.RUnlock()

	resolved := make(map[string]struct{})
	for key, ref := range s.refs {
		if ref.Error == nil {
			resolved[key.Key] = struct{}{}
		}
	}

	return len(resolved)
}

// ResolvedRoles is a fake implementation of ResolvedRoles.
func (s *FakeSecretStore) ResolvedRoles(key string) []SecretRole {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var roles []SecretRole
	for refKey, ref := range s.refs {
		if refKey.Key == key && ref.Error == nil {
			roles = append(roles, refKey.Role)
		}
	}

	slices.Sort(roles)
	return roles
}

func defaultFakeSecretPaths(key string, role SecretRole) Materialized {
	switch role {
	case RoleTLS, RoleCA, RoleJWK, RoleHtpasswd:
		return Materialized{
			Path: fmt.Sprintf("/fake/secrets/%s/%s", role, key),
		}
	default:
		return Materialized{}
	}
}

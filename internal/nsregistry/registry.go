// Package nsregistry provides a concurrency-safe registry of namespace name to
// the informer group watching that namespace, generic over the group type.
package nsregistry

import "sync"

// Registry maps a namespace name to the informer group watching it.
//
// The sync queue worker updates it as watched namespaces change while the
// background status flush pool and the leader election callbacks read it, so
// every access goes through the lock.
type Registry[T any] struct {
	lock      sync.RWMutex
	informers map[string]*T
}

// New returns an empty registry.
func New[T any]() *Registry[T] {
	return &Registry[T]{informers: make(map[string]*T)}
}

// Get returns the informer group responsible for ns, or nil when ns is not
// watched.
//
// The returned pointer is not held against removal, so only callers on the same
// goroutine as Remove may use it. Anything else must use WithInformer.
func (r *Registry[T]) Get(ns string) *T {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.lookup(ns)
}

// WithInformer calls fn with the informer group responsible for ns and reports
// whether ns is watched.
//
// fn runs under the read lock, which is what holds the group against removal,
// so it must not block: read from a lister and return.
func (r *Registry[T]) WithInformer(ns string, fn func(nsi *T)) bool {
	r.lock.RLock()
	defer r.lock.RUnlock()

	nsi := r.lookup(ns)
	if nsi == nil {
		return false
	}
	fn(nsi)
	return true
}

// ForEach calls fn for every registered informer group. As with WithInformer,
// fn runs under the read lock and must not block.
func (r *Registry[T]) ForEach(fn func(nsi *T)) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	for _, nsi := range r.informers {
		fn(nsi)
	}
}

// Set registers the informer group for ns, replacing any existing entry.
func (r *Registry[T]) Set(ns string, nsi *T) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.informers[ns] = nsi
}

// Remove unregisters ns and returns the group it held, or nil when ns was not
// watched.
//
// It takes the write lock, so it cannot return while a WithInformer or ForEach
// call is still running and no later one can observe the entry. The caller owns
// the returned group and is responsible for stopping it.
func (r *Registry[T]) Remove(ns string) *T {
	r.lock.Lock()
	defer r.lock.Unlock()

	nsi, exists := r.informers[ns]
	if !exists {
		return nil
	}
	delete(r.informers, ns)
	return nsi
}

// Len reports how many namespaces are registered.
func (r *Registry[T]) Len() int {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return len(r.informers)
}

// lookup resolves ns to a group; callers must hold the lock. A registry holding
// the global ("") entry watches every namespace, so it wins over a per-namespace
// lookup.
func (r *Registry[T]) lookup(ns string) *T {
	if nsi, isGlobalNs := r.informers[""]; isGlobalNs {
		return nsi
	}
	nsi, exists := r.informers[ns]
	if !exists {
		return nil
	}
	return nsi
}

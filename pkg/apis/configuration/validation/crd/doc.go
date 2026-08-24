// Package crd contains envtest-backed unit tests that assert the
// CRD-level (OpenAPI schema + CEL x-kubernetes-validations) rules
// on Policy objects. The tests live under the `envtest` build tag
// so `make test` is not affected. Run them with `make test-crd`.
package crd

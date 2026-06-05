//go:build !debug

package main

import "k8s.io/client-go/rest"

// wrapTransportWithDebugTracking is a no-op in release builds.
// Build with `-tags debug` to enable K8s API call tracking on :6060/debug/api-stats.
func wrapTransportWithDebugTracking(_ *rest.Config) {}

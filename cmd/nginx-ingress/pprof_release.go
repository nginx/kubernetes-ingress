//go:build !debug

package main

// pprof is disabled in release builds.
// Build with `-tags debug` to enable the pprof HTTP server on :6060.

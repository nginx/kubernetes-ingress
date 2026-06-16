// Package wafbundle implements fetching and background polling of pre-compiled
// NGINX App Protect WAF policy bundles from remote sources (HTTPS endpoint,
// NGINX One Console, or NGINX Instance Manager).
package wafbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	// DefaultPollInterval is used when BundleSource.PollInterval is nil.
	DefaultPollInterval = 5 * time.Minute

	// DefaultTimeout is used when BundleSource.Timeout is nil.
	DefaultTimeout = 60 * time.Second

	// DefaultRetryAttempts is used when BundleSource.RetryAttempts is nil.
	DefaultRetryAttempts = 3

	// MaxBundleSize is the maximum accepted bundle body size (100 MiB).
	MaxBundleSize int64 = 100 << 20

	// BundleReloadDelay is a stabilization window inserted between an atomic bundle
	// file replacement and the NGINX reload. APP_PROTECT v5's waf-config-mgr detects
	// the new inode and performs its own internal re-read; triggering a reload before
	// that completes causes a transient "File Not Found".
	BundleReloadDelay = 2 * time.Second

	// n1cCompilePollInterval is how often to re-check the N1C compile status endpoint.
	n1cCompilePollInterval = 10 * time.Second

	// maxN1CCompilePolls is the maximum number of compile status polls before giving up.
	// With n1cCompilePollInterval=10s this gives a 5-minute ceiling.
	maxN1CCompilePolls = 30
)

// BundleType distinguishes policy bundles from log profile bundles.
type BundleType int

const (
	// PolicyBundle identifies a WAF policy bundle (apBundleSource).
	PolicyBundle BundleType = iota
	// LogProfileBundle identifies a security log profile bundle (apLogBundleSource).
	LogProfileBundle
)

// SourceType mirrors conf_v1.BundleSourceType without importing it here.
type SourceType string

const (
	// SourceTypeHTTPS fetches bundles from any HTTPS endpoint.
	SourceTypeHTTPS SourceType = "HTTPS"
	// SourceTypeNIM fetches bundles from NGINX Instance Manager.
	SourceTypeNIM SourceType = "NIM"
	// SourceTypeN1C fetches bundles from NGINX One Console.
	SourceTypeN1C SourceType = "N1C"
)

// BundleAuth carries authentication material resolved from a Kubernetes Secret.
type BundleAuth struct {
	// HTTPS: client mTLS credentials.
	TLSCert []byte
	TLSKey  []byte
	TLSCA   []byte

	// N1C: sent as "Authorization: APIToken <token>".
	APIToken string

	// NIM: bearer token takes precedence over Username+Password.
	BearerToken string
	Username    string
	Password    string
}

// Request carries all parameters needed to fetch a single bundle.
type Request struct {
	Type               SourceType
	BundleKind         BundleType
	URL                string
	Auth               *BundleAuth
	TLSCA              []byte
	InsecureSkipVerify bool
	PolicyName         string
	PolicyNamespace    string
	NAPRelease         string
	Timeout            time.Duration
	RetryAttempts      int
	VerifyChecksum     bool
	ETag               string
	LastModified       string
	LastHash           string
}

// Result is the outcome of a successful fetch.
type Result struct {
	Data         []byte
	Checksum     string
	ETag         string
	LastModified string
	Unchanged    bool
}

// nonTransientError wraps errors that must not be retried (4xx, compile failed, etc.).
type nonTransientError struct{ cause error }

func (e *nonTransientError) Error() string { return e.cause.Error() }
func (e *nonTransientError) Unwrap() error { return e.cause }

func isNonTransient(err error) bool {
	var nte *nonTransientError
	return errors.As(err, &nte)
}

// testBundleReloadDelay can be set to zero in tests to skip the stabilization delay.
var testBundleReloadDelay *time.Duration

// bundleReloadDelay returns the effective reload delay (zero if overridden by tests).
func bundleReloadDelay() time.Duration {
	if testBundleReloadDelay != nil {
		return *testBundleReloadDelay
	}
	return BundleReloadDelay
}

// ComputeChecksum returns the hex-encoded SHA-256 of b.
func ComputeChecksum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FetchedBundleFilename returns the deterministic on-disk filename for a fetched bundle.
// ns and name are validated Kubernetes DNS labels so the result is filesystem-safe.
func FetchedBundleFilename(ns, name, suffix string) string {
	return fmt.Sprintf("fetched_%s_%s_%s.tgz", ns, name, suffix)
}

// WriteAtomicBundle writes data to dst atomically (temp file + rename).
// Exported so the controller can call it for the initial fetch.
func WriteAtomicBundle(dst string, data []byte) error {
	return writeAtomic(dst, data)
}

func effectiveTimeout(r *Request) time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return DefaultTimeout
}

func effectiveRetries(r *Request) int {
	if r.RetryAttempts > 0 {
		return r.RetryAttempts
	}
	return DefaultRetryAttempts
}

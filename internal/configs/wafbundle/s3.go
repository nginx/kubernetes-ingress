package wafbundle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config carries the parameters needed to build an S3 client pointing at
// the SeaweedFS filer that the F5 WAF Policy Controller (PLM) publishes
// bundles to.
type S3Config struct {
	// Endpoint is the base URL of the SeaweedFS filer, e.g.
	// https://seaweed.plm.svc.cluster.local:8333. Must include the scheme.
	Endpoint string

	AccessKeyID     string
	SecretAccessKey string

	// CACert, when non-empty, is a PEM bundle appended to the system CA pool.
	CACert []byte

	// ClientCert + ClientKey, when both non-empty, enable mTLS to the filer.
	ClientCert []byte
	ClientKey  []byte //nolint:gosec // G117: PEM private-key bytes for mTLS, not a hardcoded credential

	// InsecureSkipVerify disables TLS verification. Dev/test only.
	InsecureSkipVerify bool
}

// Validate returns an error if the config is missing required fields.
func (c S3Config) Validate() error {
	if c.Endpoint == "" {
		return errors.New("s3: endpoint must not be empty")
	}
	if c.AccessKeyID == "" {
		return errors.New("s3: access key ID must not be empty")
	}
	if c.SecretAccessKey == "" {
		return errors.New("s3: secret access key must not be empty")
	}
	if (len(c.ClientCert) == 0) != (len(c.ClientKey) == 0) {
		return errors.New("s3: client cert and key must both be provided")
	}
	return nil
}

// S3Fetcher fetches WAF bundles from an S3-compatible object store, configured
// for the PLM SeaweedFS filer (path-style addressing, static credentials).
// A fresh S3 client is built per fetch call from the passed-in S3Config.
type S3Fetcher struct{}

// NewS3Fetcher returns a new S3Fetcher.
func NewS3Fetcher() *S3Fetcher { return &S3Fetcher{} }

// FetchPolicyBundle fetches a policy bundle from the s3://bucket/key URL in
// req.URL, using the credentials + TLS material in cfg.
//
// req.Type must be SourceTypePLM. When req.ExpectedChecksum is set, the
// downloaded bytes are rejected unless the hex SHA-256 matches. Transient
// network / 5xx errors are retried by the AWS SDK's own retryer; only the
// SHA mismatch is surfaced as non-transient so the poller stops re-fetching a
// poisoned bundle.
func (f *S3Fetcher) FetchPolicyBundle(ctx context.Context, req *Request, cfg S3Config) (Result, error) {
	return fetchS3Object(ctx, req, cfg)
}

// FetchLogProfileBundle fetches a log-profile bundle. Identical to
// FetchPolicyBundle at the transport level; separate method for symmetry
// with the Fetcher interface.
func (f *S3Fetcher) FetchLogProfileBundle(ctx context.Context, req *Request, cfg S3Config) (Result, error) {
	return fetchS3Object(ctx, req, cfg)
}

func fetchS3Object(ctx context.Context, req *Request, cfg S3Config) (Result, error) {
	if req == nil {
		return Result{}, newNonTransient(errors.New("s3: nil request"))
	}
	if req.Type != SourceTypePLM {
		return Result{}, newNonTransient(fmt.Errorf("s3: unsupported request type %q", req.Type))
	}
	bucket, key, err := parseS3URL(req.URL)
	if err != nil {
		return Result{}, newNonTransient(err)
	}
	client, err := buildS3Client(cfg, effectiveRetries(req))
	if err != nil {
		return Result{}, newNonTransient(err)
	}

	fetchCtx, cancel := context.WithTimeout(ctx, effectiveTimeout(req))
	defer cancel()

	out, err := client.GetObject(fetchCtx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return Result{}, fmt.Errorf("s3: get object %s/%s: %w", bucket, key, err)
	}
	defer func() { _ = out.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(out.Body, MaxBundleSize+1))
	if err != nil {
		return Result{}, fmt.Errorf("s3: read bundle body: %w", err)
	}
	if int64(len(body)) > MaxBundleSize {
		return Result{}, newNonTransient(fmt.Errorf("s3: bundle exceeds max size %d bytes", MaxBundleSize))
	}

	computed := ComputeChecksum(body)
	if req.ExpectedChecksum != "" && !strings.EqualFold(computed, req.ExpectedChecksum) {
		return Result{}, newNonTransient(fmt.Errorf(
			"s3: bundle sha256 mismatch: expected %s, got %s", req.ExpectedChecksum, computed))
	}

	return Result{Data: body, Checksum: computed}, nil
}

// parseS3URL splits an "s3://bucket/key" URL into its bucket and key.
func parseS3URL(rawURL string) (bucket, key string, err error) {
	if rawURL == "" {
		return "", "", errors.New("s3: url must not be empty")
	}
	u, parseErr := url.Parse(rawURL)
	if parseErr != nil {
		return "", "", fmt.Errorf("s3: parse url %q: %w", rawURL, parseErr)
	}
	if u.Scheme != "s3" {
		return "", "", fmt.Errorf("s3: url scheme must be s3, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("s3: url must contain a bucket, got %q", rawURL)
	}
	key = strings.TrimPrefix(u.Path, "/")
	if key == "" {
		return "", "", fmt.Errorf("s3: url must contain a key, got %q", rawURL)
	}
	return u.Host, key, nil
}

// buildS3Client constructs an aws-sdk-go-v2 S3 client pointing at cfg.Endpoint
// with static credentials and path-style addressing (required by SeaweedFS).
// maxAttempts caps the SDK's built-in retryer, which already backs off on
// transient 5xx / throttling / network errors and does not retry 4xx.
func buildS3Client(cfg S3Config, maxAttempts int) (*s3.Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	httpClient, err := buildS3HTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return s3.New(s3.Options{
		// SeaweedFS ignores the region, but the AWS SDK requires a non-empty value.
		Region:           "us-east-1",
		Credentials:      credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		BaseEndpoint:     aws.String(cfg.Endpoint),
		UsePathStyle:     true,
		HTTPClient:       httpClient,
		RetryMaxAttempts: maxAttempts,
	}), nil
}

// buildS3HTTPClient returns an HTTP client with TLS 1.2+ configured per cfg.
func buildS3HTTPClient(cfg S3Config) (*awshttp.BuildableClient, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	tlsCfg.InsecureSkipVerify = cfg.InsecureSkipVerify //nolint:gosec // documented dev/test only

	if len(cfg.CACert) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(cfg.CACert) {
			return nil, errors.New("s3: failed to parse CA certificate bundle")
		}
		tlsCfg.RootCAs = pool
	}
	if len(cfg.ClientCert) > 0 && len(cfg.ClientKey) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("s3: invalid client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) {
		t.TLSClientConfig = tlsCfg
	}), nil
}

// newNonTransient wraps err so isNonTransient returns true.
func newNonTransient(err error) error {
	if err == nil {
		return nil
	}
	return &nonTransientError{cause: err}
}

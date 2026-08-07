package wafbundle

import (
	"context"
	"fmt"
)

// PLMAwareFetcher is a Fetcher that dispatches SourceTypePLM requests to an
// S3Fetcher (SeaweedFS) and delegates every other source type to a wrapped
// Fetcher (typically the HTTPFetcher used for HTTPS/NIM/N1C).
//
// It exists to bridge the 3-arg S3Fetcher API onto the 2-arg Fetcher interface:
// the S3Config is not carried on the Request, so PLMAwareFetcher resolves it
// per-fetch from Kubernetes Secrets via LoadS3Config. Resolving on every fetch
// keeps rotated Secrets picked up automatically without a watcher.
type PLMAwareFetcher struct {
	delegate     Fetcher
	s3           *S3Fetcher
	secretSrc    SecretSource
	s3ConfigSpec S3ConfigSpec
}

// NewPLMAwareFetcher wraps delegate so that SourceTypePLM requests are served
// from s3 using credentials loaded via secretSrc + spec, and all other requests
// fall through to delegate.
func NewPLMAwareFetcher(delegate Fetcher, s3 *S3Fetcher, secretSrc SecretSource, spec S3ConfigSpec) *PLMAwareFetcher {
	return &PLMAwareFetcher{
		delegate:     delegate,
		s3:           s3,
		secretSrc:    secretSrc,
		s3ConfigSpec: spec,
	}
}

// FetchPolicyBundle dispatches on req.Type: PLM goes to S3, everything else to
// the wrapped fetcher.
func (f *PLMAwareFetcher) FetchPolicyBundle(ctx context.Context, req *Request) (Result, error) {
	if req != nil && req.Type == SourceTypePLM {
		cfg, err := f.loadS3Config()
		if err != nil {
			return Result{}, err
		}
		return f.s3.FetchPolicyBundle(ctx, req, cfg)
	}
	return f.delegate.FetchPolicyBundle(ctx, req)
}

// FetchLogProfileBundle dispatches on req.Type: PLM goes to S3, everything else
// to the wrapped fetcher.
func (f *PLMAwareFetcher) FetchLogProfileBundle(ctx context.Context, req *Request) (Result, error) {
	if req != nil && req.Type == SourceTypePLM {
		cfg, err := f.loadS3Config()
		if err != nil {
			return Result{}, err
		}
		return f.s3.FetchLogProfileBundle(ctx, req, cfg)
	}
	return f.delegate.FetchLogProfileBundle(ctx, req)
}

func (f *PLMAwareFetcher) loadS3Config() (S3Config, error) {
	cfg, err := LoadS3Config(f.secretSrc, f.s3ConfigSpec)
	if err != nil {
		return S3Config{}, newNonTransient(fmt.Errorf("plm: load s3 config: %w", err))
	}
	return cfg, nil
}

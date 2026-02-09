package configs

import (
	"os"
	"path"
)

type bundleValidator interface {
	// validate returns the full path to the bundle and an error if the file is not accessible
	validate(string) (string, error)
}

type internalBundleValidator struct {
	bundlePath string
}

type apiKeyClient struct {
	ClientID  string
	HashedKey string
}

func (i internalBundleValidator) validate(bundle string) (string, error) {
	bundle = path.Join(i.bundlePath, bundle)
	_, err := os.Stat(bundle)
	return bundle, err
}

func newInternalBundleValidator(b string) internalBundleValidator {
	return internalBundleValidator{
		bundlePath: b,
	}
}

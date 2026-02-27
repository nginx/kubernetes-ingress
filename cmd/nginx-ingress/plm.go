package main

import (
	"context"
	"crypto/tls"
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/fetch"
	"github.com/nginx/kubernetes-ingress/internal/k8s"
	"github.com/nginx/kubernetes-ingress/internal/k8s/secrets"
	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	api_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	plmCredentialsKey = "seaweedfs_admin_secret"
	plmAccessKeyID    = "adminKey"
	plmCAKey          = "ca.crt"
)

// createWAFFetcher builds an S3 fetcher from the PLM storage config.
// Returns nil if PLM storage URL is not set.
func createWAFFetcher(
	ctx context.Context,
	kubeClient *kubernetes.Clientset,
	cfg k8s.PLMStorageConfig,
	controllerNamespace string,
) fetch.Fetcher {
	if cfg.URL == "" {
		return nil
	}
	l := nl.LoggerFromContext(ctx)

	var opts []fetch.Option

	if cfg.CredentialsSecretName != "" {
		nsName := qualifyPLMSecretName(cfg.CredentialsSecretName, controllerNamespace)
		ns, name, err := k8s.ParseNamespaceName(nsName)
		if err != nil {
			nl.Fatalf(l, "Invalid PLM credentials secret name %v: %v", nsName, err)
		}
		secret, err := kubeClient.CoreV1().Secrets(ns).Get(ctx, name, meta_v1.GetOptions{})
		if err != nil {
			nl.Fatalf(l, "Failed to get PLM credentials secret %v: %v", nsName, err)
		}
		secretKey := string(secret.Data[plmCredentialsKey])
		opts = append(opts, fetch.WithCredentials(plmAccessKeyID, secretKey))
	}

	tlsCfg, err := buildPLMTLSConfig(ctx, kubeClient, cfg, controllerNamespace)
	if err != nil {
		nl.Fatalf(l, "Failed to build PLM TLS config: %v", err)
	}
	if tlsCfg != nil {
		opts = append(opts, fetch.WithTLSConfig(tlsCfg))
	}

	fetcher, err := fetch.NewS3Fetcher(cfg.URL, opts...)
	if err != nil {
		nl.Fatalf(l, "Failed to create WAF fetcher: %v", err)
	}
	return fetcher
}

// buildPLMTLSConfig constructs a *tls.Config from the PLM CA and client SSL secrets.
// Returns nil if no TLS customisation is needed.
func buildPLMTLSConfig(
	ctx context.Context,
	kubeClient *kubernetes.Clientset,
	cfg k8s.PLMStorageConfig,
	controllerNamespace string,
) (*tls.Config, error) {
	var caCert, clientCert, clientKey []byte

	if cfg.TLSCACertSecretName != "" {
		nsName := qualifyPLMSecretName(cfg.TLSCACertSecretName, controllerNamespace)
		secret, err := getAndValidateSecret(kubeClient, nsName, secrets.SecretTypeCA)
		if err != nil {
			return nil, err
		}
		caCert = secret.Data[plmCAKey]
	}

	if cfg.TLSClientSSLSecretName != "" {
		nsName := qualifyPLMSecretName(cfg.TLSClientSSLSecretName, controllerNamespace)
		secret, err := getAndValidateSecret(kubeClient, nsName, api_v1.SecretTypeTLS)
		if err != nil {
			return nil, err
		}
		clientCert = secret.Data[api_v1.TLSCertKey]
		clientKey = secret.Data[api_v1.TLSPrivateKeyKey]
	}

	if len(caCert) == 0 && len(clientCert) == 0 && !cfg.TLSInsecureSkipVerify {
		return nil, nil
	}

	return fetch.TLSConfigFromSecret(caCert, clientCert, clientKey, cfg.TLSInsecureSkipVerify)
}

// qualifyPLMSecretName prepends controllerNamespace if no namespace is present.
func qualifyPLMSecretName(name, controllerNamespace string) string {
	if strings.Contains(name, "/") {
		return name
	}
	return controllerNamespace + "/" + name
}

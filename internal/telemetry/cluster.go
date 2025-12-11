package telemetry

import (
	"context"
	"errors"
	"fmt"
	"strings"

	clusterInfo "github.com/nginx/kubernetes-ingress/internal/common_cluster_info"
	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// configMapFilteredKeys and mgmtConfigMapFilteredKeys are lists containing keys from the main ConfigMap and MGMT ConfigMap that are used by NIC
// These will need to be updated if new keys are added to the ConfigMap or MGMTConfigMap.
var configMapFilteredKeys = []string{
	"external-status-address",
	"server-tokens",
	"lb-method",
	"proxy-connect-timeout",
	"proxy-read-timeout",
	"proxy-send-timeout",
	"proxy-hide-headers",
	"proxy-pass-headers",
	"client-max-body-size",
	"server-names-hash-bucket-size",
	"server-names-hash-max-size",
	"map-hash-bucket-size",
	"map-hash-max-size",
	"http2",
	"redirect-to-https",
	"ssl-redirect",
	"hsts",
	"hsts-max-age",
	"hsts-include-subdomains",
	"hsts-behind-proxy",
	"proxy-protocol",
	"real-ip-header",
	"set-real-ip-from",
	"real-ip-recursive",
	"ssl-protocols",
	"ssl-prefer-server-ciphers",
	"ssl-ciphers",
	"ssl-dhparam-file",
	"error-log-level",
	"access-log",
	"access-log-off",
	"log-format",
	"log-format-escaping",
	"stream-log-format",
	"stream-log-format-escaping",
	"default-server-access-log-off",
	"default-server-return",
	"proxy-buffering",
	"proxy-buffers",
	"proxy-buffer-size",
	"proxy-max-temp-file-size",
	"main-snippets",
	"http-snippets",
	"location-snippets",
	"server-snippets",
	"worker-processes",
	"worker-cpu-affinity",
	"worker-shutdown-timeout",
	"worker-connections",
	"worker-rlimit-nofile",
	"keepalive",
	"max-fails",
	"upstream-zone-size",
	"fail-timeout",
	"main-template",
	"ingress-template",
	"virtualserver-template",
	"transportserver-template",
	"stream-snippets",
	"resolver-addresses",
	"resolver-ipv6",
	"resolver-valid",
	"resolver-timeout",
	"keepalive-timeout",
	"keepalive-requests",
	"variables-hash-bucket-size",
	"variables-hash-max-size",
	"opentracing-tracer",
	"opentracing-tracer-config",
	"opentracing",
	"app-protect-failure-mode-action",
	"app-protect-compressed-requests-action",
	"app-protect-cookie-seed",
	"app-protect-cpu-thresholds",
	"app-protect-physical-memory-util-thresholds",
	"app-protect-reconnect-period-seconds",
	"app-protect-dos-log-format",
	"app-protect-dos-log-format-escaping",
	"app-protect-dos-arb-fqdn",
	"zone-sync",
	"zone-sync-port",
	"zone-sync-resolver-addresses",
	"zone-sync-resolver-valid",
	"zone-sync-resolver-ipv6",
}

var mgmtConfigMapFilteredKeys = []string{
	"license-token-secret-name",
	"ssl-verify",
	"resolver-addresses",
	"resolver-ipv6",
	"resolver-valid",
	"enforce-initial-report",
	"usage-report-endpoint",
	"usage-report-interval",
	"ssl-trusted-certificate-secret-name",
	"ssl-certificate-secret-name",
	"usage-report-proxy-host",
}

// NodeCount returns the total number of nodes in the cluster.
// It returns an error if the underlying k8s API client errors.
func (c *Collector) NodeCount(ctx context.Context) (int, error) {
	return clusterInfo.GetNodeCount(ctx, c.Config.K8sClientReader)
}

// ReplicaCount returns a number of running NIC replicas.
func (c *Collector) ReplicaCount(ctx context.Context) (int, error) {
	pod, err := c.Config.K8sClientReader.CoreV1().Pods(c.Config.PodNSName.Namespace).Get(ctx, c.Config.PodNSName.Name, metaV1.GetOptions{})
	if err != nil {
		return 0, err
	}
	podRef := pod.GetOwnerReferences()
	if len(podRef) != 1 {
		return 0, fmt.Errorf("expected pod owner reference to be 1, got %d", len(podRef))
	}

	switch podRef[0].Kind {
	case "ReplicaSet":
		rs, err := c.Config.K8sClientReader.AppsV1().ReplicaSets(c.Config.PodNSName.Namespace).Get(ctx, podRef[0].Name, metaV1.GetOptions{})
		if err != nil {
			return 0, err
		}
		return int(*rs.Spec.Replicas), nil
	case "DaemonSet":
		ds, err := c.Config.K8sClientReader.AppsV1().DaemonSets(c.Config.PodNSName.Namespace).Get(ctx, podRef[0].Name, metaV1.GetOptions{})
		if err != nil {
			return 0, err
		}
		return int(ds.Status.CurrentNumberScheduled), nil
	default:
		return 0, fmt.Errorf("expected pod owner reference to be ReplicaSet or DeamonSet, got %s", podRef[0].Kind)
	}
}

// ClusterID returns the UID of the kube-system namespace representing cluster id.
// It returns an error if the underlying k8s API client errors.
func (c *Collector) ClusterID(ctx context.Context) (string, error) {
	return clusterInfo.GetClusterID(ctx, c.Config.K8sClientReader)
}

// ClusterVersion returns a string representing the K8s version.
// It returns an error if the underlying k8s API client errors.
func (c *Collector) ClusterVersion() (string, error) {
	sv, err := c.Config.K8sClientReader.Discovery().ServerVersion()
	if err != nil {
		return "", err
	}
	return sv.String(), nil
}

// Platform returns a string representing platform name.
func (c *Collector) Platform(ctx context.Context) (string, error) {
	nodes, err := c.Config.K8sClientReader.CoreV1().Nodes().List(ctx, metaV1.ListOptions{})
	if err != nil {
		return "", err
	}
	if len(nodes.Items) == 0 {
		return "", errors.New("no nodes in the cluster, cannot determine platform name")
	}
	return lookupPlatform(nodes.Items[0].Spec.ProviderID), nil
}

// InstallationID returns generated NIC InstallationID.
func (c *Collector) InstallationID(ctx context.Context) (_ string, err error) {
	return clusterInfo.GetInstallationID(ctx, c.Config.K8sClientReader, c.Config.PodNSName)
}

// Secrets returns the number of secrets watched by NIC.
func (c *Collector) Secrets() (int, error) {
	if c.Config.SecretStore == nil {
		return 0, errors.New("nil secret store")
	}
	return len(c.Config.SecretStore.GetSecretReferenceMap()), nil
}

// RegularIngressCount returns number of Minion Ingresses in the namespaces watched by NIC.
func (c *Collector) RegularIngressCount() int {
	ingressCount := c.Config.Configurator.GetIngressCounts()
	return ingressCount["regular"]
}

// MasterIngressCount returns number of Minion Ingresses in the namespaces watched by NIC.
func (c *Collector) MasterIngressCount() int {
	ingressCount := c.Config.Configurator.GetIngressCounts()
	return ingressCount["master"]
}

// MinionIngressCount returns number of Minion Ingresses in the namespaces watched by NIC.
func (c *Collector) MinionIngressCount() int {
	ingressCount := c.Config.Configurator.GetIngressCounts()
	return ingressCount["minion"]
}

// IngressAnnotations returns a list of all the unique annotations found in Ingresses.
func (c *Collector) IngressAnnotations() []string {
	if c.Config.Configurator == nil {
		return nil
	}
	annotations := c.Config.Configurator.GetIngressAnnotations()
	return annotations
}

// IngressClassCount returns number of Ingress Classes.
func (c *Collector) IngressClassCount(ctx context.Context) (int, error) {
	ic, err := c.Config.K8sClientReader.NetworkingV1().IngressClasses().List(ctx, metaV1.ListOptions{})
	if err != nil {
		return 0, err
	}
	return len(ic.Items), nil
}

// PolicyCount returns the count in each Policy
func (c *Collector) PolicyCount() map[string]int {
	policyCounters := make(map[string]int)
	if !c.Config.CustomResourcesEnabled {
		return policyCounters
	}
	if c.Config.Policies == nil {
		return policyCounters
	}
	policies := c.Config.Policies()
	if len(policies) == 0 {
		return policyCounters
	}

	for _, policy := range policies {
		spec := policy.Spec

		switch {
		case spec.AccessControl != nil:
			policyCounters["AccessControl"]++
		case spec.RateLimit != nil:
			// RateLimit is a special case, as it can be defined in multiple ways
			// depending on the condition used.
			// If the condition is JWT, we count it as RateLimitJWT,
			// if the condition is Variables, we count it as RateLimitVariables,
			// otherwise we count it as RateLimit.
			procecessRateLimitCounters(spec.RateLimit, policyCounters)
		case spec.JWTAuth != nil:
			policyCounters["JWTAuth"]++
		case spec.BasicAuth != nil:
			policyCounters["BasicAuth"]++
		case spec.IngressMTLS != nil:
			policyCounters["IngressMTLS"]++
		case spec.EgressMTLS != nil:
			policyCounters["EgressMTLS"]++
		case spec.OIDC != nil:
			policyCounters["OIDC"]++
		case spec.WAF != nil:
			policyCounters["WAF"]++
		case spec.APIKey != nil:
			policyCounters["APIKey"]++
		case spec.Cache != nil:
			policyCounters["Cache"]++
		}
	}
	return policyCounters
}

func procecessRateLimitCounters(rl *v1.RateLimit, pc map[string]int) {
	if rl.Condition == nil {
		pc["RateLimit"]++
	} else {
		// Check if the condition is JWT or Variables
		// and increment the appropriate counter.
		// If neither, increment the RateLimit counter.
		if rl.Condition.JWT != nil {
			pc["RateLimitJWT"]++
		}
		if rl.Condition.Variables != nil {
			pc["RateLimitVariables"]++
		}
	}
}

// AppProtectVersion returns the AppProtect Version
func (c *Collector) AppProtectVersion() string {
	return c.Config.AppProtectVersion
}

// IsPlusEnabled returns true or false depending on if NGINX is Plus or OSS
func (c *Collector) IsPlusEnabled() bool {
	return c.Config.IsPlus
}

// InstallationFlags returns the list of all set flags
func (c *Collector) InstallationFlags() []string {
	return c.Config.InstallationFlags
}

// ServiceCounts returns a map of service names and their counts in the Kubernetes cluster.
func (c *Collector) ServiceCounts() (map[string]int, error) {
	serviceCounts := make(map[string]int)

	services, err := c.Config.K8sClientReader.CoreV1().Services("").List(context.Background(), metaV1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, service := range services.Items {
		serviceCounts[string(service.Spec.Type)]++
	}

	return serviceCounts, nil
}

// BuildOS returns a string which is the base operating system image tha NIC is running in.
func (c *Collector) BuildOS() string {
	return c.Config.BuildOS
}

// ConfigMapKeys gets the main ConfigMap keys from the configMapKeys function that accesses the K8s API and returns keys that are filtered and used by NIC.
func (c *Collector) ConfigMapKeys(ctx context.Context) ([]string, error) {
	return c.configMapKeys(ctx,
		c.Config.MainConfigMapName,
		configMapFilteredKeys,
	)
}

// MGMTConfigMapKeys gets the MGMT ConfigMap keys from the configMapKeys function that accesses the K8s API and returns keys that are filtered and used by NIC.
func (c *Collector) MGMTConfigMapKeys(ctx context.Context) ([]string, error) {
	return c.configMapKeys(ctx,
		c.Config.MGMTConfigMapName,
		mgmtConfigMapFilteredKeys,
	)
}

// / configMapKeys is a helper function that retrieves the keys from the ConfigMap
// and filters them based on the provided filteredConfigMapKeys.
func (c *Collector) configMapKeys(
	ctx context.Context,
	configMapName string,
	filteredConfigMapKeys []string,
) ([]string, error) {
	parts := strings.Split(configMapName, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid config map name: %s", configMapName)
	}
	namespace, name := parts[0], parts[1]

	configMap, err := c.Config.K8sClientReader.CoreV1().ConfigMaps(namespace).Get(ctx, name, metaV1.GetOptions{})
	if err != nil {
		return nil, err
	}

	filteredKeys := make(map[string]struct{}, len(filteredConfigMapKeys))
	for _, key := range filteredConfigMapKeys {
		filteredKeys[key] = struct{}{}
	}

	var keys []string
	for k := range configMap.Data {
		if _, ok := filteredKeys[k]; ok {
			keys = append(keys, k)
		}
	}

	return keys, nil
}

// lookupPlatform takes a string representing a K8s PlatformID
// retrieved from a cluster node and returns a string
// representing the platform name.
func lookupPlatform(providerID string) string {
	provider := strings.TrimSpace(providerID)
	if provider == "" {
		return "other"
	}

	provider = strings.ToLower(providerID)

	p := strings.Split(provider, ":")
	if len(p) == 0 {
		return "other"
	}
	if p[0] == "" {
		return "other"
	}
	return p[0]
}

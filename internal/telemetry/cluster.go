package telemetry

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	clusterInfo "github.com/nginx/kubernetes-ingress/internal/common_cluster_info"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
			policyCounters["RateLimit"]++
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
		}
	}
	return policyCounters
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

// ConfigMapKeys gets the main ConfigMap Keys from K8s API and returns the keys and an error
func (c *Collector) ConfigMapKeys(ctx context.Context) ([]string, error) {
	if c.Config.MainConfigMapName == "" {
		return nil, fmt.Errorf("config map name is required")
	}

	parts := strings.Split(c.Config.MainConfigMapName, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid config map name: %s", c.Config.MainConfigMapName)
	}
	namespace, name := parts[0], parts[1]

	configMap, err := c.Config.K8sClientReader.CoreV1().ConfigMaps(namespace).Get(ctx, name, metaV1.GetOptions{})
	if err != nil {
		return nil, err
	}

	var keys []string
	for k := range configMap.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys, nil
}

// MGMTConfigMapKeys gets the mgmtConfigMap Keys from K8s API and returns the keys and an error
func (c *Collector) MGMTConfigMapKeys(ctx context.Context) ([]string, error) {
	if c.Config.MGMTConfigMapName == "" {
		return nil, fmt.Errorf("mgmtConfigMapName is not set")
	}

	parts := strings.Split(c.Config.MGMTConfigMapName, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid config map name: %s", c.Config.MGMTConfigMapName)
	}
	namespace, name := parts[0], parts[1]

	configMap, err := c.Config.K8sClientReader.CoreV1().ConfigMaps(namespace).Get(ctx, name, metaV1.GetOptions{})
	if err != nil {
		return nil, err
	}

	var keys []string
	for k := range configMap.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

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

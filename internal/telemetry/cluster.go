package telemetry

import (
	"context"
	"errors"
	"fmt"
	"strings"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NodeCount returns the total number of nodes in the cluster.
// It returns an error if the underlying k8s API client errors.
func (c *Collector) NodeCount(ctx context.Context) (int, error) {
	nodes, err := c.Config.K8sClientReader.CoreV1().Nodes().List(ctx, metaV1.ListOptions{})
	if err != nil {
		return 0, err
	}
	return len(nodes.Items), nil
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
	if podRef[0].Kind != "ReplicaSet" {
		return 0, fmt.Errorf("expected pod owner reference to be ReplicaSet, got %s", pod.OwnerReferences[0].Kind)
	}
	rs, err := c.Config.K8sClientReader.AppsV1().ReplicaSets(c.Config.PodNSName.Namespace).Get(ctx, podRef[0].Name, metaV1.GetOptions{})
	if err != nil {
		return 0, err
	}
	return int(*rs.Spec.Replicas), nil
}

// ClusterID returns the UID of the kube-system namespace representing cluster id.
// It returns an error if the underlying k8s API client errors.
func (c *Collector) ClusterID(ctx context.Context) (string, error) {
	cluster, err := c.Config.K8sClientReader.CoreV1().Namespaces().Get(ctx, "kube-system", metaV1.GetOptions{})
	if err != nil {
		return "", err
	}
	return string(cluster.UID), nil
}

// ClusterVersion returns a string respresenting the K8s version.
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

package commonclusterinfo

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// This file contains functions for data used in both product telemetry and license reporting

// GetNodeCount returns the number of nodes in the cluster
func GetNodeCount(ctx context.Context, client kubernetes.Interface) (int, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	return len(nodes.Items), nil
}

// GetClusterID returns the UID of the kube-system namespace representing cluster id.
// It returns an error if the underlying k8s API client errors.
func GetClusterID(ctx context.Context, client kubernetes.Interface) (string, error) {
	cluster, err := client.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return string(cluster.UID), nil
}

// GetInstallationID returns the Installation ID of the cluster
func GetInstallationID(ctx context.Context, client kubernetes.Interface, podNSName types.NamespacedName) (_ string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("error generating InstallationID: %w", err)
		}
	}()

	pod, err := client.CoreV1().Pods(podNSName.Namespace).Get(ctx, podNSName.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	podOwner := pod.GetOwnerReferences()
	if len(podOwner) != 1 {
		return "", fmt.Errorf("expected pod owner reference to be 1, got %d", len(podOwner))
	}

	switch podOwner[0].Kind {
	case "ReplicaSet":
		rs, err := client.AppsV1().ReplicaSets(podNSName.Namespace).Get(ctx, podOwner[0].Name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		rsOwner := rs.GetOwnerReferences() // rsOwner holds information about replica's owner - Deployment object
		if len(rsOwner) != 1 {
			return "", fmt.Errorf("expected replicaset owner reference to be 1, got %d", len(rsOwner))
		}
		return string(rsOwner[0].UID), nil
	case "DaemonSet":
		return string(podOwner[0].UID), nil
	default:
		return "", fmt.Errorf("expected pod owner reference to be ReplicaSet or DeamonSet, got %s", podOwner[0].Kind)
	}
}

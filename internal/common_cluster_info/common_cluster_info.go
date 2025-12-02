package commonclusterinfo

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// This file contains functions for data used in product telemetry, metadata and license reporting

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
		return string(podOwner[0].UID), nil
	}
}

// GetInstallationName returns the name of the Deployment
func GetInstallationName(ctx context.Context, client kubernetes.Interface, podNSName types.NamespacedName) (string, error) {
	pod, err := client.CoreV1().Pods(podNSName.Namespace).Get(ctx, podNSName.Name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	owners := pod.GetOwnerReferences()
	owner := owners[0]
	switch owner.Kind {
	case "ReplicaSet":
		replicaSet, err := client.AppsV1().ReplicaSets(podNSName.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		for _, replicaSetOwner := range replicaSet.GetOwnerReferences() {
			if replicaSetOwner.Kind == "Deployment" {
				return replicaSetOwner.Name, nil
			}
		}
		return "", fmt.Errorf("replicaset %s has no owner", replicaSet.Name)
	case "DaemonSet":
		return owner.Name, nil
	default:
		return owner.Name, nil
	}
}

package telemetry_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/nginx/kubernetes-ingress/internal/telemetry"
	appsV1 "k8s.io/api/apps/v1"
	apiCoreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func TestNodeCountInAClusterWithThreeNodes(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, node1, node2, node3)

	got, err := c.NodeCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := 3
	if want != got {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestNodeCountInAClusterWithOneNode(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, node1)
	got, err := c.NodeCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := 1
	if want != got {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestClusterIDRetrievesK8sClusterUID(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, node1, kubeNS)

	got, err := c.ClusterID(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := telemetryNICData.ClusterID
	if want != got {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestClusterIDErrorsOnNotExistingService(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, node1)
	_, err := c.ClusterID(context.Background())
	if err == nil {
		t.Error("want error, got nil")
	}
}

func TestK8sVersionRetrievesClusterVersion(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, node1)
	got, err := c.ClusterVersion()
	if err != nil {
		t.Fatal(err)
	}

	want := telemetryNICData.ClusterVersion
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestAWSPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeAWS)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "aws"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestAzurePlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeAzure)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "azure"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestGCPPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeGCP)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "gce"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestKindPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeKind)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "kind"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestVSpherePlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeVSphere)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "vsphere"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestK3SPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeK3S)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "k3s"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestIBMCloudPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeIBMCloud)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "ibmcloud"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestIBMPowerPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeIBMPowerVS)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "ibmpowervs"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestCloudStackPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeCloudStack)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "cloudstack"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestOpenStackPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeOpenStack)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "openstack"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestDigitalOceanPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeDigitalOcean)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "digitalocean"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestEquinixMetallPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeEquinixMetal)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "equinixmetal"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestAlibabaPlatformDeterminesOwnName(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeAlibaba)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "alicloud"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestPlatformLookupOnMissingPlatformIDField(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, node1)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "other"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestPlatformLookupOnMalformedPlatformIDField(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeMalformedPlatformID)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "//4232e3c7-d83c-d72b-758c-71d07a3d9310"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestPlatformLookupOnMalformedBlankPlatformIDField(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeMalformedBlankPlatformID)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "other"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestPlatformLookupOnMalformedEmptyPlatformIDField(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeMalformedEmptyPlatformID)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "other"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestPlatformLookupOnMalformedPartialPlatformIDField(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, nodeMalformedPartialPlatformID)
	got, err := c.Platform(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := "other"
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestReplicaCountReturnsNumberOfNICReplicas(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, node1, pod1, replica)

	got, err := c.ReplicaCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := 1
	if want != got {
		t.Errorf("want %d, got %d", want, got)
	}
}

func TestReplicaCountReturnsNumberOfNICDaemonSets(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, node1, pod2, daemon)
	got, err := c.ReplicaCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := 1
	if want != got {
		t.Errorf("want %d, got %d", want, got)
	}
}

func TestInstallationIDGeneratesHashOnReplicaSet(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, kubeNS, node1, pod1, replica)
	got, err := c.InstallationID(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := installationIDReplicaSet
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestInstallationIDGeneratesHashOnDaemonSet(t *testing.T) {
	t.Parallel()

	c := newTestCollectorForClusterWithNodes(t, kubeNS, node1, pod2, daemon)
	got, err := c.InstallationID(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := installationIDDaemonSet
	if want != got {
		t.Errorf("want %s, got %s", want, got)
	}
}

func TestInstallationIDFailsOnMissingReplicaSet(t *testing.T) {
	t.Parallel()

	// Pod1 is configured to have owner reference ReplicaSet.
	c := newTestCollectorForClusterWithNodes(t, kubeNS, node1, pod1)
	_, err := c.InstallationID(context.Background())
	if err == nil {
		t.Fatal("want error on missing replicaset got nil")
	}
}

func TestInstallationIDFailsOnMissingDaemonSet(t *testing.T) {
	t.Parallel()

	// Pod2 is configured to have owner reference DaemonSet.
	c := newTestCollectorForClusterWithNodes(t, kubeNS, node1, pod1)
	_, err := c.InstallationID(context.Background())
	if err == nil {
		t.Fatal("want error on missing daemonset got nil")
	}
}

func TestGetInstallationFlags(t *testing.T) {
	t.Parallel()

	c, err := telemetry.NewCollector(
		telemetry.CollectorConfig{
			InstallationFlags: []string{
				"-nginx-plus=true",
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	got := c.InstallationFlags()
	want := []string{"-nginx-plus=true"}
	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestGetServices(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		config telemetry.CollectorConfig
		want   map[string]int
	}{
		{
			name: "OneClusterIP",
			config: telemetry.CollectorConfig{
				K8sClientReader: newTestClientset(defaultNS, kubeNS, clusterIPService),
			},
			want: map[string]int{
				"ClusterIP": 1,
			},
		},
		{
			name: "MultipleClusterIPs",
			config: telemetry.CollectorConfig{
				K8sClientReader: newTestClientset(defaultNS, kubeNS, clusterIPService, clusterIPService2),
			},
			want: map[string]int{
				"ClusterIP": 2,
			},
		},
		{
			name: "MultipleExternalNamesAndNodePort",
			config: telemetry.CollectorConfig{
				K8sClientReader: newTestClientset(defaultNS, kubeNS, externalNameService, externalNameService2, nodePortService),
			},
			want: map[string]int{
				"ExternalName": 2,
				"NodePort":     1,
			},
		},
		{
			name: "MultipleServices",
			config: telemetry.CollectorConfig{
				K8sClientReader: newTestClientset(defaultNS, kubeNS, externalNameService, externalNameService2, nodePortService, nodePortService2, clusterIPService2, clusterIPService, loadBalancerService),
			},
			want: map[string]int{
				"ClusterIP":    2,
				"ExternalName": 2,
				"NodePort":     2,
				"LoadBalancer": 1,
			},
		},
		{
			name: "noServices",
			config: telemetry.CollectorConfig{
				K8sClientReader: newTestClientset(defaultNS, kubeNS),
			},
			want: map[string]int{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := telemetry.NewCollector(tc.config)
			if err != nil {
				t.Fatal(err)
			}

			got, err := c.ServiceCounts()
			if err != nil {
				t.Fatal(err)
			}

			if !cmp.Equal(tc.want, got) {
				t.Error(cmp.Diff(tc.want, got))
			}
		})
	}
}

// newTestCollectorForClusterWithNodes returns a telemetry collector configured
// to simulate collecting data on a cluser with provided nodes.
func newTestCollectorForClusterWithNodes(t *testing.T, nodes ...runtime.Object) *telemetry.Collector {
	t.Helper()

	c, err := telemetry.NewCollector(
		telemetry.CollectorConfig{},
	)
	if err != nil {
		t.Fatal(err)
	}
	c.Config.K8sClientReader = newTestClientset(nodes...)
	c.Config.PodNSName = types.NamespacedName{
		Namespace: "nginx-ingress",
		Name:      "nginx-ingress",
	}
	return c
}

// Test InstallationIDs are generated from test data structs:
// ClusterID, Pod and ReplicaSet/DaemonSet
var (
	installationIDReplicaSet = "239766ff-5a78-4a1e-8736-7faad1f2e122"
	installationIDDaemonSet  = "319766ff-5c78-4a9a-8736-7faad1f2e234"
)

// Pod and ReplicaSet for testing NIC replica sets.
var (
	pod1 = &apiCoreV1.Pod{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "nginx-ingress",
			Namespace: "nginx-ingress",
			OwnerReferences: []metaV1.OwnerReference{
				{
					Kind: "ReplicaSet",
					Name: "nginx-ingress",
					UID:  types.UID(installationIDReplicaSet),
				},
			},
			Labels: map[string]string{
				"app":                    "nginx-ingress",
				"app.kubernetes.io/name": "nginx-ingress",
			},
		},
		Spec: apiCoreV1.PodSpec{
			Containers: []apiCoreV1.Container{
				{
					Name:            "nginx-ingress",
					Image:           "nginx-ingress",
					ImagePullPolicy: "Always",
					Env: []apiCoreV1.EnvVar{
						{
							Name:  "POD_NAMESPACE",
							Value: "nginx-ingress",
						},
						{
							Name:  "POD_NAME",
							Value: "nginx-ingress",
						},
					},
				},
			},
		},
	}

	replicaNum int32 = 1
	replica          = &appsV1.ReplicaSet{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "ReplicaSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "nginx-ingress",
			Namespace: "nginx-ingress",
			Labels: map[string]string{
				"app":                    "nginx-ingress",
				"app.kubernetes.io/name": "nginx-ingress",
			},
			OwnerReferences: []metaV1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "nginx-ingress",
					UID:  types.UID(installationIDReplicaSet),
				},
			},
		},

		Spec: appsV1.ReplicaSetSpec{
			Replicas: &replicaNum,
		},
		Status: appsV1.ReplicaSetStatus{
			Replicas:          replicaNum,
			ReadyReplicas:     replicaNum,
			AvailableReplicas: replicaNum,
		},
	}

	pod2 = &apiCoreV1.Pod{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "nginx-ingress",
			Namespace: "nginx-ingress",
			OwnerReferences: []metaV1.OwnerReference{
				{
					Kind: "DaemonSet",
					Name: "nginx-ingress",
					UID:  types.UID(installationIDDaemonSet),
				},
			},
			Labels: map[string]string{
				"app":                    "nginx-ingress",
				"app.kubernetes.io/name": "nginx-ingress",
			},
		},
		Spec: apiCoreV1.PodSpec{
			Containers: []apiCoreV1.Container{
				{
					Name:            "nginx-ingress",
					Image:           "nginx-ingress",
					ImagePullPolicy: "Always",
					Env: []apiCoreV1.EnvVar{
						{
							Name:  "POD_NAMESPACE",
							Value: "nginx-ingress",
						},
						{
							Name:  "POD_NAME",
							Value: "nginx-ingress",
						},
					},
				},
			},
		},
	}

	daemonNum int32 = 1
	daemon          = &appsV1.DaemonSet{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "nginx-ingress",
			Namespace: "nginx-ingress",
			UID:       types.UID(installationIDDaemonSet),
			Labels:    map[string]string{"app": "nginx-ingress"},
		},
		Spec: appsV1.DaemonSetSpec{},
		Status: appsV1.DaemonSetStatus{
			CurrentNumberScheduled: daemonNum,
			NumberReady:            daemonNum,
			NumberAvailable:        daemonNum,
		},
	}
)

// Nodes for testing NIC namespaces.
var (
	node1 = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "test-node-1",
			Namespace: "nginx-ingress",
		},
		Spec: apiCoreV1.NodeSpec{},
	}

	node2 = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "test-node-2",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{},
	}

	node3 = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "test-node-3",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{},
	}

	kubeNS = &apiCoreV1.Namespace{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name: "kube-system",
			UID:  "329766ff-5d78-4c9e-8736-7faad1f2e937",
		},
		Spec: apiCoreV1.NamespaceSpec{},
	}

	defaultNS = &apiCoreV1.Namespace{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name: "default",
			UID:  "329766ff-5d78-4c9e-8736-7fesd1f2e937",
		},
		Spec: apiCoreV1.NamespaceSpec{},
	}
)

// Cloud providers' nodes for testing ProviderID lookups.
var (
	nodeAWS = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "aws:///eu-central-1a/i-088b4f07708408cc0",
		},
	}

	nodeAzure = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "azure:///subscriptions/ba96ef31-4a42-40f5-8740-03f7e3c439eb/resourceGroups/mc_hibrid-weu_be3rr5ovr8ulf_westeurope/providers/Microsoft.Compute/virtualMachines/aks-pool1-27255451-0",
		},
	}

	nodeGCP = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "gce://gcp-banzaidevgcp-nprd-38306/europe-north1-a/gke-vzf3z1vvleco9-pool1-7e48d363-8qz1",
		},
	}

	nodeKind = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "kind://docker/local/local-control-plane",
		},
	}

	nodeVSphere = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "vsphere://4232e3c7-d83c-d72b-758c-71d07a3d9310",
		},
	}

	nodeK3S = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "k3s://ip-1.2.3.4",
		},
	}

	nodeIBMCloud = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "ibmcloud://4232e3c7-d83c-d72b-758c-71d07a3d9310",
		},
	}

	nodeIBMPowerVS = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "ibmpowervs://4232e3c7-d83c-d72b-758c-71d07a3d9310",
		},
	}

	nodeCloudStack = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "cloudstack://4232e3c7-d83c-d72b-758c-71d07a3d9310",
		},
	}

	nodeOpenStack = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "openstack://4232e3c7-d83c-d72b-758c-71d07a3d9310",
		},
	}

	nodeDigitalOcean = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "digitalocean://4232e3c7-d83c-d72b-758c-71d07a3d9310",
		},
	}

	nodeEquinixMetal = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "equinixmetal://4232e3c7-d83c-d72b-758c-71d07a3d9310",
		},
	}

	nodeAlibaba = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "alicloud://4232e3c7-d83c-d72b-758c-71d07a3d9310",
		},
	}
)

// Nodes with missing or malformed PorviderID.
var (
	nodeMalformedPlatformID = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "//4232e3c7-d83c-d72b-758c-71d07a3d9310",
		},
	}

	nodeMalformedPartialPlatformID = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "://4232e3c7-d83c-d72b-758c-71d07a3d9310",
		},
	}

	nodeMalformedEmptyPlatformID = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: "",
		},
	}

	nodeMalformedBlankPlatformID = &apiCoreV1.Node{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Node",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "node",
			Namespace: "default",
		},
		Spec: apiCoreV1.NodeSpec{
			ProviderID: " ",
		},
	}
)

// Secrets for testing.
var (
	secret1 = &apiCoreV1.Secret{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "tls-secret-1",
			Namespace: "default",
		},
		Type: apiCoreV1.SecretTypeTLS,
		Data: map[string][]byte{},
	}

	secret2 = &apiCoreV1.Secret{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "tls-secret-2",
			Namespace: "default",
		},
		Type: apiCoreV1.SecretTypeTLS,
		Data: map[string][]byte{},
	}
)

// Services for testing
var (
	clusterIPService = &apiCoreV1.Service{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "coffee-svc",
			Namespace: "default",
		},
		Spec: apiCoreV1.ServiceSpec{
			Type: "ClusterIP",
		},
		Status: apiCoreV1.ServiceStatus{},
	}
	clusterIPService2 = &apiCoreV1.Service{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "coffee-svc2",
			Namespace: "default",
		},
		Spec: apiCoreV1.ServiceSpec{
			Type: "ClusterIP",
		},
		Status: apiCoreV1.ServiceStatus{},
	}
	nodePortService = &apiCoreV1.Service{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "tea-svc",
			Namespace: "default",
		},
		Spec: apiCoreV1.ServiceSpec{
			Type: "NodePort",
		},
		Status: apiCoreV1.ServiceStatus{},
	}
	nodePortService2 = &apiCoreV1.Service{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "tea-svc2",
			Namespace: "default",
		},
		Spec: apiCoreV1.ServiceSpec{
			Type: "NodePort",
		},
		Status: apiCoreV1.ServiceStatus{},
	}
	externalNameService = &apiCoreV1.Service{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "external-svc",
			Namespace: "default",
		},
		Spec: apiCoreV1.ServiceSpec{
			Type: "ExternalName",
		},
		Status: apiCoreV1.ServiceStatus{},
	}
	externalNameService2 = &apiCoreV1.Service{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "external-svc2",
			Namespace: "default",
		},
		Spec: apiCoreV1.ServiceSpec{
			Type: "ExternalName",
		},
		Status: apiCoreV1.ServiceStatus{},
	}
	loadBalancerService = &apiCoreV1.Service{
		TypeMeta: metaV1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "default-svc",
			Namespace: "default",
		},
		Spec: apiCoreV1.ServiceSpec{
			Type: "LoadBalancer",
		},
		Status: apiCoreV1.ServiceStatus{},
	}
)

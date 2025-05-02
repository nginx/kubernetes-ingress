import pytest
from suite.utils.resources_utils import get_reload_count, scale_deployment, wait_until_all_pods_are_ready

from tests.suite.utils.custom_assertions import assert_pods_scaled_to_count


@pytest.mark.vs
@pytest.mark.vs_use_cluster_ip
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-enable-prometheus-metrics",
                ],
            },
            {"example": "virtual-server-use-cluster-ip", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVSUseClusterIP:
    @pytest.mark.flaky(max_runs=3)
    def test_use_cluster_ip_reloads(
        self, kube_apis, ingress_controller_endpoint, crd_ingress_controller, virtual_server_setup
    ):
        wait_until_all_pods_are_ready(kube_apis.v1, virtual_server_setup.namespace)
        print("Step 1: get initial reload count")
        initial_reload_count = get_reload_count(virtual_server_setup.metrics_url)

        print("Step 2: scale the deployment down")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", virtual_server_setup.namespace, 1)
        assert_pods_scaled_to_count(kube_apis.apps_v1_api, kube_apis.v1, "backend1", virtual_server_setup.namespace, 1)

        print("Step 3: scale the deployment up")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", virtual_server_setup.namespace, 4)
        assert_pods_scaled_to_count(kube_apis.apps_v1_api, kube_apis.v1, "backend1", virtual_server_setup.namespace, 4)

        print("Step 4: get reload count after scaling")
        reload_count_after_scaling = get_reload_count(virtual_server_setup.metrics_url)

        assert reload_count_after_scaling == initial_reload_count, "Expected: no new reloads"

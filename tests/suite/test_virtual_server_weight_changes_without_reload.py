import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_assertions import wait_and_assert_status_code
from suite.utils.resources_utils import ensure_response_from_backend, get_reload_count, wait_before_test
from suite.utils.vs_vsr_resources_utils import patch_virtual_server_from_yaml


@pytest.mark.vs
@pytest.mark.smoke
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup, expect_reload",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-enable-prometheus-metrics",
                    "-weight-changes-dynamic-reload=true",
                ],
            },
            {"example": "virtual-server-weight-changes-dynamic-reload", "app_type": "split"},
            False,
        ),
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-enable-prometheus-metrics",
                    "-weight-changes-dynamic-reload=false",
                ],
            },
            {
                "example": "virtual-server-weight-changes-dynamic-reload",
                "app_type": "split",
            },
            True,
        ),
    ],
    indirect=["crd_ingress_controller", "virtual_server_setup"],
    ids=[
        "WithoutReload",
        "WithReload",
    ],
)
class TestWeightChangesWithReloadCondition:
    def test_weight_changes_reload_behavior(
        self, kube_apis, crd_ingress_controller, virtual_server_setup, expect_reload
    ):
        initial_weights_config = (
            f"{TEST_DATA}/virtual-server-weight-changes-dynamic-reload/standard/virtual-server.yaml"
        )
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            initial_weights_config,
            virtual_server_setup.namespace,
        )
        swap_weights_config = (
            f"{TEST_DATA}/virtual-server-weight-changes-dynamic-reload/virtual-server-weight-swap.yaml"
        )

        print("Step 1: Get a response from the backend.")
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        resp = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        assert "backend1-v1" in resp.text

        print("Step 2: Record the initial number of reloads.")
        count_before = get_reload_count(virtual_server_setup.metrics_url)
        print(f"Reload count before: {count_before}")

        print("Step 3: Apply a configuration that swaps the weights (0 100) to (100 0).")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, swap_weights_config, virtual_server_setup.namespace
        )

        print("Wait after applying config")
        wait_before_test(5)

        print("Step 4: Verify hitting the other backend.")
        ensure_response_from_backend(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        resp = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        assert "backend1-v2" in resp.text

        print("Step 5: Verify reload behavior based on the weight-changes-dynamic-reload flag.")
        count_after = get_reload_count(virtual_server_setup.metrics_url)
        print(f"Reload count after: {count_after}")

        if expect_reload:
            assert (
                count_before < count_after
            ), "The reload count should increase when weights are swapped and weight-changes-dynamic-reload=false."
        else:
            assert (
                count_before == count_after
            ), "The reload count should not change when weights are swapped and weight-changes-dynamic-reload=true."

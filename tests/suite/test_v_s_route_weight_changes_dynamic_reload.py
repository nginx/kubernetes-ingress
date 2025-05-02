import pytest
import requests
from settings import TEST_DATA
from suite.fixtures.custom_resource_fixtures import VirtualServerRoute
from suite.utils.resources_utils import (
    create_example_app,
    create_namespace_with_name_from_yaml,
    delete_namespace,
    ensure_response_from_backend,
    get_reload_count,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_host_from_yaml, get_paths_from_vsr_yaml, get_route_namespace_from_vs_yaml

from tests.suite.utils.custom_assertions import wait_and_assert_status_code
from tests.suite.utils.vs_vsr_resources_utils import (
    create_v_s_route_from_yaml,
    create_virtual_server_from_yaml,
    patch_v_s_route_from_yaml,
)


class VSRWeightChangesDynamicReloadSetup:
    """
    Encapsulate weight changes without reload details.

    Attributes:
        namespace (str):
        vs_host (str):
        vs_name (str):
        route (VirtualServerRoute):
        backends_url (str): backend url
    """

    def __init__(self, namespace, vs_host, vs_name, route: VirtualServerRoute, backends_url, metrics_url):
        self.namespace = namespace
        self.vs_host = vs_host
        self.vs_name = vs_name
        self.route = route
        self.backends_url = backends_url
        self.metrics_url = metrics_url


@pytest.fixture(scope="class")
def vsr_weight_changes_dynamic_reload_setup(
    request, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint
) -> VSRWeightChangesDynamicReloadSetup:
    """
    Prepare an example app for weight changes without reload VSR.

    Single namespace with VS+VSR and weight changes without reload app.

    :param request: internal pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint:
    :param ingress_controller_prerequisites:
    :return:
    """

    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
    vs_routes_ns = get_route_namespace_from_vs_yaml(
        f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml"
    )
    ns_1 = create_namespace_with_name_from_yaml(kube_apis.v1, vs_routes_ns[0], f"{TEST_DATA}/common/ns.yaml")
    print("------------------------- Deploy Virtual Server -----------------------------------")
    vs_name = create_virtual_server_from_yaml(
        kube_apis.custom_objects, f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml", ns_1
    )
    vs_host = get_first_host_from_yaml(f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml")

    print("------------------------- Deploy Virtual Server Route -----------------------------------")
    vsr_name = create_v_s_route_from_yaml(
        kube_apis.custom_objects, f"{TEST_DATA}/{request.param['example']}/virtual-server-route-initial.yaml", ns_1
    )
    vsr_paths = get_paths_from_vsr_yaml(f"{TEST_DATA}/{request.param['example']}/virtual-server-route-initial.yaml")
    route = VirtualServerRoute(ns_1, vsr_name, vsr_paths)
    backends_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}{vsr_paths[0]}"

    print("---------------------- Deploy weight changes without reload vsr app ----------------------------")
    create_example_app(kube_apis, "weight-changes-dynamic-reload-vsr", ns_1)
    wait_until_all_pods_are_ready(kube_apis.v1, ns_1)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete test namespace")
            delete_namespace(kube_apis.v1, ns_1)

    request.addfinalizer(fin)

    return VSRWeightChangesDynamicReloadSetup(ns_1, vs_host, vs_name, route, backends_url, metrics_url)


@pytest.mark.vsr
@pytest.mark.vsr_splits
@pytest.mark.smoke
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller,vsr_weight_changes_dynamic_reload_setup, expect_reload",
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
            {"example": "virtual-server-route-weight-changes-dynamic-reload"},
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
            {"example": "virtual-server-route-weight-changes-dynamic-reload"},
            True,
        ),
    ],
    indirect=["crd_ingress_controller", "vsr_weight_changes_dynamic_reload_setup"],
    ids=["WithoutReload", "WithReload"],
)
class TestVSRWeightChangesWithReloadCondition:

    def test_vsr_weight_changes_reload_behavior(
        self, kube_apis, crd_ingress_controller, vsr_weight_changes_dynamic_reload_setup, expect_reload
    ):
        swap_weights_config = (
            f"{TEST_DATA}/virtual-server-route-weight-changes-dynamic-reload/virtual-server-route-swap.yaml"
        )

        print("Step 1: Get a response from the backend.")
        wait_and_assert_status_code(
            200, vsr_weight_changes_dynamic_reload_setup.backends_url, vsr_weight_changes_dynamic_reload_setup.vs_host
        )
        resp = requests.get(
            vsr_weight_changes_dynamic_reload_setup.backends_url,
            headers={"host": vsr_weight_changes_dynamic_reload_setup.vs_host},
        )
        assert "backend1" in resp.text

        print("Step 2: Record the initial number of reloads.")
        count_before = get_reload_count(vsr_weight_changes_dynamic_reload_setup.metrics_url)
        print(f"Reload count before: {count_before}")

        print("Step 3: Apply a configuration that swaps the weights (0 100) to (100 0).")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            vsr_weight_changes_dynamic_reload_setup.route.name,
            swap_weights_config,
            vsr_weight_changes_dynamic_reload_setup.route.namespace,
        )

        wait_before_test(5)

        print("Step 4: Verify hitting the other backend.")
        ensure_response_from_backend(
            vsr_weight_changes_dynamic_reload_setup.backends_url, vsr_weight_changes_dynamic_reload_setup.vs_host
        )
        wait_and_assert_status_code(
            200, vsr_weight_changes_dynamic_reload_setup.backends_url, vsr_weight_changes_dynamic_reload_setup.vs_host
        )
        resp = requests.get(
            vsr_weight_changes_dynamic_reload_setup.backends_url,
            headers={"host": vsr_weight_changes_dynamic_reload_setup.vs_host},
        )
        assert "backend2" in resp.text

        print("Step 5: Verify reload behavior based on the weight-changes-dynamic-reload flag.")
        count_after = get_reload_count(vsr_weight_changes_dynamic_reload_setup.metrics_url)
        print(f"Reload count after: {count_after}")
        if expect_reload:
            assert (
                count_before < count_after
            ), "The reload count should increase when weights are swapped and weight-changes-dynamic-reload=false."
        else:
            assert (
                count_before == count_after
            ), "The reload count should not change when weights are swapped and weight-changes-dynamic-reload=true."

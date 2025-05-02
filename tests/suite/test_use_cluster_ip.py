import pytest
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    get_reload_count,
    scale_deployment,
    wait_before_test,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

from tests.suite.utils.custom_assertions import assert_pods_scaled_to_count


class UseClusterIPSetup:
    def __init__(self, ingress_host, metrics_url):
        self.ingress_host = ingress_host
        self.metrics_url = metrics_url


@pytest.fixture(scope="class")
def use_cluster_ip_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    ingress_controller,
    test_namespace,
) -> UseClusterIPSetup:
    print("------------------------- Deploy use-cluster-ip setup -----------------------------------")

    test_data_path = f"{TEST_DATA}/use-cluster-ip/ingress"
    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"

    ingress_path = f"{test_data_path}/{request.param}/use-cluster-ip-ingress.yaml"
    create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_path)
    if request.param == "mergeable":
        create_ingress_from_yaml(
            kube_apis.networking_v1, test_namespace, f"{test_data_path}/{request.param}/minion-ingress.yaml"
        )
    create_example_app(kube_apis, "simple", test_namespace)

    wait_before_test(1)

    ingress_host = get_first_ingress_host_from_yaml(ingress_path)

    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port, ingress_controller_endpoint.port_ssl
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up use-cluster-ip setup")
            delete_items_from_yaml(kube_apis, ingress_path, test_namespace)
            delete_common_app(kube_apis, "simple", test_namespace)
            if request.param == "mergeable":
                delete_items_from_yaml(
                    kube_apis,
                    f"{test_data_path}/{request.param}/minion-ingress.yaml",
                    test_namespace,
                )

    request.addfinalizer(fin)

    return UseClusterIPSetup(
        ingress_host,
        metrics_url,
    )


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller, use_cluster_ip_setup",
    [
        pytest.param({"extra_args": ["-enable-prometheus-metrics"]}, "standard"),
        pytest.param({"extra_args": ["-enable-prometheus-metrics"]}, "mergeable"),
    ],
    indirect=True,
)
class TestIngressUseClusterIPReloads:
    def test_ingress_use_cluster_ip_reloads(
        self, kube_apis, ingress_controller_endpoint, test_namespace, use_cluster_ip_setup
    ):
        print("Step 1: get initial reload count")
        initial_reload_count = get_reload_count(use_cluster_ip_setup.metrics_url)

        print("Step 2: scale the deployment down")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", test_namespace, 1)
        assert_pods_scaled_to_count(kube_apis.apps_v1_api, kube_apis.v1, "backend1", test_namespace, 1)

        print("Step 3: scale the deployment up")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", test_namespace, 4)
        assert_pods_scaled_to_count(kube_apis.apps_v1_api, kube_apis.v1, "backend1", test_namespace, 4)

        print("Step 4: get reload count after scaling")
        reload_count_after_scaling = get_reload_count(use_cluster_ip_setup.metrics_url)

        assert reload_count_after_scaling == initial_reload_count, "Expected: no new reloads"

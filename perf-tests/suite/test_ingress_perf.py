import json

import pytest
import requests
from common import collect_prom_reload_metrics, run_perf
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_secret,
    ensure_connection,
    ensure_connection_to_public_endpoint,
    generate_e2e_run_id,
    get_e2e_run_selector,
    get_resource_metrics,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

reload = []


class Setup:
    """
    Encapsulate the Smoke Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
    """

    def __init__(self, req_url):
        self.req_url = req_url


@pytest.fixture(scope="class")
def setup(request, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint, test_namespace) -> Setup:
    print("------------------------- Deploy prerequisites -----------------------------------")
    e2e_run_id = generate_e2e_run_id()
    secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, f"{TEST_DATA}/smoke/smoke-secret.yaml")

    create_example_app(kube_apis, "simple", test_namespace, e2e_run_id=e2e_run_id)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace, get_e2e_run_selector(e2e_run_id))
    req_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )

    def fin():
        print("Clean up simple app")
        print("Collect resource usage metrics")
        pod_metrics = get_resource_metrics(kube_apis.custom_objects, "pods", ingress_controller_prerequisites.namespace)
        with open("ingress_pod_metrics.json", "w+") as f:
            json.dump(pod_metrics, f, ensure_ascii=False, indent=4)
        node_metrics = get_resource_metrics(
            kube_apis.custom_objects, "nodes", ingress_controller_prerequisites.namespace
        )
        with open("ingress_node_metrics.json", "w+") as f:
            json.dump(node_metrics, f, ensure_ascii=False, indent=4)

        delete_common_app(kube_apis, "simple", test_namespace)
        delete_secret(kube_apis.v1, secret_name, test_namespace)
        with open("reload_ing.json", "w+") as f:
            json.dump(reload, f, ensure_ascii=False, indent=4)

    request.addfinalizer(fin)
    return Setup(req_url)


@pytest.fixture
def setup_users(request):
    return request.config.getoption("--users")


@pytest.fixture
def setup_rate(request):
    return request.config.getoption("--hatch-rate")


@pytest.fixture
def setup_time(request):
    return request.config.getoption("--time")


@pytest.mark.perf
@pytest.mark.parametrize(
    "ingress_controller",
    [
        {
            "extra_args": [
                f"-enable-prometheus-metrics",
            ]
        }
    ],
    indirect=["ingress_controller"],
)
class TestIngressPerf:
    def test_perf(
        self,
        kube_apis,
        ingress_controller_endpoint,
        test_namespace,
        ingress_controller,
        setup,
        setup_users,
        setup_rate,
        setup_time,
    ):
        create_items_from_yaml(kube_apis, f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml", test_namespace)
        ingress_host = get_first_ingress_host_from_yaml(f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml")
        wait_before_test()
        ensure_connection(setup.req_url, 200, {"host": ingress_host})
        resp = requests.get(setup.req_url, headers={"host": ingress_host}, verify=False)
        assert resp.status_code == 200
        collect_prom_reload_metrics(
            reload,
            "Ingress resource",
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.metrics_port,
        )
        run_perf(setup.req_url, setup_users, setup_rate, setup_time, "ing")
        delete_items_from_yaml(kube_apis, f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml", test_namespace)

import os
import tempfile

import pytest
import yaml
from settings import TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.custom_assertions import wait_and_assert_status_code
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_secret,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    get_last_reload_time,
    get_pods_amount,
    get_reload_count,
    get_test_file_name,
    scale_deployment,
    wait_before_test,
    wait_until_all_pods_are_ready,
    write_to_json,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

paths = ["backend1", "backend2"]
reload_times = {}


class SmokeSetup:
    """
    Encapsulate the Smoke Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        ingress_host (str):
    """

    def __init__(self, public_endpoint: PublicEndpoint, ingress_host):
        self.public_endpoint = public_endpoint
        self.ingress_host = ingress_host


@pytest.fixture(scope="class", params=["standard", "mergeable", "implementation-specific-pathtype"])
def smoke_setup(request, kube_apis, ingress_controller_endpoint, ingress_controller, test_namespace) -> SmokeSetup:
    print("------------------------- Deploy Smoke Example -----------------------------------")
    secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, f"{TEST_DATA}/smoke/smoke-secret.yaml")
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/smoke/{request.param}/smoke-ingress.yaml", test_namespace)
    ingress_host = get_first_ingress_host_from_yaml(f"{TEST_DATA}/smoke/{request.param}/smoke-ingress.yaml")
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up the Smoke Application:")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(kube_apis, f"{TEST_DATA}/smoke/{request.param}/smoke-ingress.yaml", test_namespace)
            delete_secret(kube_apis.v1, secret_name, test_namespace)
            write_to_json(f"reload-{get_test_file_name(request.node.fspath)}.json", reload_times)

    request.addfinalizer(fin)

    return SmokeSetup(ingress_controller_endpoint, ingress_host)


@pytest.mark.smoke
@pytest.mark.ingresses
@pytest.mark.ingresses_smoke
class TestSmoke:
    @pytest.mark.parametrize(
        "ingress_controller",
        [
            pytest.param({"extra_args": ["-enable-prometheus-metrics"]}, id="one-additional-cli-args"),
            pytest.param(
                {"extra_args": ["-nginx-debug", "-health-status=true", "-enable-prometheus-metrics"]},
                id="some-additional-cli-args",
            ),
        ],
        indirect=True,
    )
    @pytest.mark.parametrize("path", paths)
    def test_response_code_200_and_server_name(self, request, ingress_controller, smoke_setup, path):
        req_url = f"https://{smoke_setup.public_endpoint.public_ip}:{smoke_setup.public_endpoint.port_ssl}/{path}"
        metrics_url = (
            f"http://{smoke_setup.public_endpoint.public_ip}:{smoke_setup.public_endpoint.metrics_port}/metrics"
        )
        ensure_response_from_backend(req_url, smoke_setup.ingress_host)
        reload_ms = get_last_reload_time(metrics_url, "nginx")
        print(f"last reload duration: {reload_ms} ms")
        reload_times[f"{request.node.name}"] = f"last reload duration: {reload_ms} ms"
        wait_and_assert_status_code(200, req_url, smoke_setup.ingress_host, verify=False)

    @pytest.mark.parametrize(
        "ingress_controller",
        [
            pytest.param({"extra_args": ["-enable-prometheus-metrics"]}, id="one-additional-cli-args"),
        ],
        indirect=True,
    )
    def test_reload_count_after_start(self, kube_apis, smoke_setup, ingress_controller_prerequisites):
        ns = ingress_controller_prerequisites.namespace

        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ns, 0)
        while get_pods_amount(kube_apis.v1, ns) != 0:
            print(f"Number of replicas not 0, retrying...")
            wait_before_test()
        num = scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ns, 1)
        assert num is None

        metrics_url = (
            f"http://{smoke_setup.public_endpoint.public_ip}:{smoke_setup.public_endpoint.metrics_port}/metrics"
        )
        count = get_reload_count(metrics_url)

        assert count == 1

    @pytest.mark.parametrize(
        "ingress_controller",
        [
            pytest.param({"extra_args": ["-enable-prometheus-metrics"]}),
        ],
        indirect=True,
    )
    def test_batch_create_reload_count(self, kube_apis, smoke_setup, ingress_controller_prerequisites, test_namespace):
        metrics_url = (
            f"http://{smoke_setup.public_endpoint.public_ip}:{smoke_setup.public_endpoint.metrics_port}/metrics"
        )
        count_before = get_reload_count(metrics_url)
        num_res = 10
        manifest = f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml"
        with open(manifest) as f:
            doc = yaml.safe_load(f)
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".yml", delete=False) as temp:
                for i in range(1, num_res + 1):
                    doc["metadata"]["name"] = f"smoke-ingress-{i}"
                    doc["spec"]["rules"][0]["host"] = f"smoke-{i}.example.com"
                    temp.write(yaml.safe_dump(doc) + "---\n")
        create_items_from_yaml(kube_apis, temp.name, test_namespace)

        wait_before_test(5)

        count_after = get_reload_count(metrics_url)
        new_reloads = count_after - count_before

        print(f"Counted {new_reloads} reloads for {num_res} new config objects")

        delete_items_from_yaml(kube_apis, temp.name, test_namespace)
        os.remove(temp.name)

        assert new_reloads <= (int(num_res / 2) + 1)

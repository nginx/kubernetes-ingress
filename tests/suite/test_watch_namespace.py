from unittest import mock

import pytest
import requests
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_namespace_with_name_from_yaml,
    delete_namespace,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    generate_e2e_run_id,
    get_e2e_run_selector,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml


class BackendSetup:
    """
    Encapsulate the example details.

    Attributes:
        req_url (str):
        ingress_hosts (dict):
    """

    def __init__(self, req_url, ingress_hosts):
        self.req_url = req_url
        self.ingress_hosts = ingress_hosts


@pytest.fixture(scope="class")
def backend_setup(request, kube_apis, ingress_controller_endpoint) -> BackendSetup:
    """
    Create 2 namespaces and deploy simple applications in them.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :return: BackendSetup
    """
    e2e_run_id = generate_e2e_run_id()
    watched_namespace = create_namespace_with_name_from_yaml(kube_apis.v1, f"watched-ns", f"{TEST_DATA}/common/ns.yaml")
    foreign_namespace = create_namespace_with_name_from_yaml(kube_apis.v1, f"foreign-ns", f"{TEST_DATA}/common/ns.yaml")
    watched_namespace2 = create_namespace_with_name_from_yaml(
        kube_apis.v1, f"watched-ns2", f"{TEST_DATA}/common/ns.yaml"
    )

    ingress_hosts = {}
    for ns in [watched_namespace, foreign_namespace, watched_namespace2]:
        print(f"------------------------- Deploy the backend in {ns} -----------------------------------")
        create_example_app(kube_apis, "simple", ns, e2e_run_id=e2e_run_id)
        src_ing_yaml = f"{TEST_DATA}/watch-namespace/{ns}-ingress.yaml"
        create_items_from_yaml(kube_apis, src_ing_yaml, ns)
        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)
        ingress_hosts[f"{ns}-ingress"] = ingress_host
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"
        wait_until_all_pods_are_ready(kube_apis.v1, ns, get_e2e_run_selector(e2e_run_id))
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            delete_namespace(kube_apis.v1, watched_namespace)
            delete_namespace(kube_apis.v1, foreign_namespace)
            delete_namespace(kube_apis.v1, watched_namespace2)

    request.addfinalizer(fin)

    return BackendSetup(req_url, ingress_hosts)


@pytest.mark.ingresses
@pytest.mark.watch_namespace
@pytest.mark.parametrize(
    "ingress_controller, expected_responses",
    [
        pytest.param(
            {"extra_args": ["-watch-namespace=watched-ns"]}, {"watched-ns-ingress": 200, "foreign-ns-ingress": 404}
        )
    ],
    indirect=["ingress_controller"],
)
class TestWatchNamespace:
    def test_response_codes(self, ingress_controller, backend_setup, expected_responses):
        for ing in ["watched-ns-ingress", "foreign-ns-ingress"]:
            ensure_response_from_backend(backend_setup.req_url, backend_setup.ingress_hosts[ing])
            resp = requests.get(backend_setup.req_url, headers={"host": backend_setup.ingress_hosts[ing]})
            assert (
                resp.status_code == expected_responses[ing]
            ), f"Expected: {expected_responses[ing]} response code for {backend_setup.ingress_hosts[ing]}"


@pytest.mark.ingresses
@pytest.mark.watch_namespace
@pytest.mark.parametrize(
    "ingress_controller, expected_responses",
    [
        pytest.param(
            {"extra_args": ["-watch-namespace=watched-ns,watched-ns2"]},
            {"watched-ns-ingress": 200, "watched-ns2-ingress": 200, "foreign-ns-ingress": 404},
        )
    ],
    indirect=["ingress_controller"],
)
class TestWatchMultipleNamespaces:
    def test_response_codes(self, ingress_controller, backend_setup, expected_responses):
        for ing in ["watched-ns-ingress", "watched-ns2-ingress", "foreign-ns-ingress"]:
            ensure_response_from_backend(backend_setup.req_url, backend_setup.ingress_hosts[ing])
            resp = mock.Mock()
            resp.status_code = "None"
            retry = 0
            while resp.status_code != expected_responses[ing] and retry < 3:
                resp = requests.get(backend_setup.req_url, headers={"host": backend_setup.ingress_hosts[ing]})
                retry = retry + 1
                wait_before_test()
            assert (
                resp.status_code == expected_responses[ing]
            ), f"Expected: {expected_responses[ing]} response code for {backend_setup.ingress_hosts[ing]}"

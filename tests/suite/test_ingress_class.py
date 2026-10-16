import pytest
import requests
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
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


ingresses_under_test = ["custom-class", "nginx-class", "no-class"]


@pytest.fixture(scope="class")
def backend_setup(request, kube_apis, ingress_controller_endpoint, test_namespace) -> BackendSetup:
    """
    Deploy simple application and all the Ingress resources under test in one namespace.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :param test_namespace:
    :return: BackendSetup
    """
    print("------------------------- Deploy the backend -----------------------------------")
    e2e_run_id = generate_e2e_run_id()
    create_example_app(kube_apis, "simple", test_namespace, e2e_run_id=e2e_run_id)
    req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace, get_e2e_run_selector(e2e_run_id))
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )
    print("------------------------- Deploy ingresses under test -----------------------------------")
    ingress_hosts = {}
    for item in ingresses_under_test:
        src_ing_yaml = f"{TEST_DATA}/ingress-class/{item}-ingress.yaml"
        create_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
        ingress_hosts[item] = get_first_ingress_host_from_yaml(src_ing_yaml)
    wait_before_test(2)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            delete_common_app(kube_apis, "simple", test_namespace)
            for item in ingresses_under_test:
                src_ing_yaml = f"{TEST_DATA}/ingress-class/{item}-ingress.yaml"
                delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)

    request.addfinalizer(fin)

    return BackendSetup(req_url, ingress_hosts)


@pytest.mark.ingresses
class TestIngressClassArgs:
    @pytest.mark.parametrize(
        "ingress_controller, expected_responses",
        [
            pytest.param(
                {"extra_args": ["-ingress-class=custom"]},
                {"custom-class": 200, "nginx-class": 404, "no-class": 404},
                id="custom-ingress-class",
            ),
            pytest.param(
                {"extra_args": None},
                {"custom-class": 404, "nginx-class": 200, "no-class": 404},
                id="no-args-set",
            ),
        ],
        indirect=["ingress_controller"],
    )
    def test_response_codes_117_plus(
        self,
        ingress_controller,
        backend_setup,
        expected_responses,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
    ):
        """
        Checks for ingressClass behaviour
        """
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

        for item in ingresses_under_test:
            ensure_response_from_backend(backend_setup.req_url, backend_setup.ingress_hosts[item])
            resp = requests.get(backend_setup.req_url, headers={"host": backend_setup.ingress_hosts[item]})
            assert (
                resp.status_code == expected_responses[item]
            ), f"Expected: {expected_responses[item]} response code for {backend_setup.ingress_hosts[item]}"

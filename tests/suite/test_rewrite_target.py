import pytest
import requests
from settings import TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml, get_name_from_yaml


class RewriteTargetSetup:
    """Encapsulate Rewrite Target example details."""

    def __init__(
        self,
        public_endpoint: PublicEndpoint,
        ingress_src_file,
        ingress_name,
        ingress_host,
        namespace,
        request_url,
    ):
        self.public_endpoint = public_endpoint
        self.ingress_name = ingress_name
        self.namespace = namespace
        self.ingress_host = ingress_host
        self.ingress_src_file = ingress_src_file
        self.request_url = request_url


@pytest.fixture(scope="function")
def rewrite_target_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    ingress_controller,
    test_namespace,
) -> RewriteTargetSetup:
    print("------------------------- Deploy Ingress with rewrite-target annotations -----------------------------------")
    src = f"{TEST_DATA}/rewrite-target/{request.param}.yaml"
    create_items_from_yaml(kube_apis, src, test_namespace)
    ingress_name = get_name_from_yaml(src)
    ingress_host = get_first_ingress_host_from_yaml(src)
    request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port, ingress_controller_endpoint.port_ssl
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(kube_apis, src, test_namespace)

    request.addfinalizer(fin)

    return RewriteTargetSetup(
        ingress_controller_endpoint,
        src,
        ingress_name,
        ingress_host,
        test_namespace,
        request_url,
    )


@pytest.mark.annotations
class TestRewriteTarget:
    @pytest.mark.parametrize("rewrite_target_setup", ["rewrite-static"], indirect=True)
    def test_static_rewrite_target(self, rewrite_target_setup):
        """
        Test static rewrite target functionality.
        Request to /app should be rewritten to /backend.
        """
        request_url = f"http://{rewrite_target_setup.public_endpoint.public_ip}:{rewrite_target_setup.public_endpoint.port}/app"
        resp = requests.get(
            request_url,
            headers={"host": rewrite_target_setup.ingress_host},
        )
        
        assert resp.status_code == 200
        assert "URI: /backend" in resp.text

    @pytest.mark.parametrize("rewrite_target_setup", ["rewrite-regex"], indirect=True)
    def test_regex_rewrite_target(self, rewrite_target_setup):
        """
        Test regex rewrite target functionality with capture groups.
        Request to /v1/users/123 should be rewritten to /api/users/123.
        """
        request_url = f"http://{rewrite_target_setup.public_endpoint.public_ip}:{rewrite_target_setup.public_endpoint.port}/v1/users/123"
        resp = requests.get(
            request_url,
            headers={"host": rewrite_target_setup.ingress_host},
        )
        
        assert resp.status_code == 200
        assert "URI: /api/users/123" in resp.text
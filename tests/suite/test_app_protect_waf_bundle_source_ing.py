import pytest
from settings import TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.ap_resources_utils import (
    assert_waf_blocked,
    send_malicious_request_with_retry,
)
from suite.utils.bundle_source_utils import (
    BundleServerSetup,
    create_waf_bundle_source_policy,
    setup_bundle_server,
    teardown_bundle_server,
)
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

INGRESS_SRC = f"{TEST_DATA}/ap-waf-v5/ingress-policy.yaml"
POLICY_NAME = "waf-policy"


class BundleSourceIngressSetup:
    """Holds setup state for bundle source Ingress tests."""

    def __init__(self, public_endpoint: PublicEndpoint, ingress_host: str):
        self.public_endpoint = public_endpoint
        self.ingress_host = ingress_host


@pytest.fixture(scope="class")
def bundle_server(kube_apis, test_namespace) -> BundleServerSetup:
    """Deploy an HTTPS bundle server serving WAF bundles."""
    server = setup_bundle_server(kube_apis, test_namespace)
    yield server
    teardown_bundle_server(kube_apis, test_namespace)


@pytest.fixture(scope="function")
def ingress_setup(kube_apis, ingress_controller_endpoint, test_namespace):
    """Deploy a backend app and Ingress that references the WAF policy."""
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    create_items_from_yaml(kube_apis, INGRESS_SRC, test_namespace)

    ingress_host = get_first_ingress_host_from_yaml(INGRESS_SRC)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )
    wait_before_test()

    yield BundleSourceIngressSetup(ingress_controller_endpoint, ingress_host)

    delete_items_from_yaml(kube_apis, INGRESS_SRC, test_namespace)
    delete_common_app(kube_apis, "simple", test_namespace)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect_waf_v5
@pytest.mark.appprotect_waf_bundle_source
@pytest.mark.parametrize(
    "crd_ingress_controller_with_waf_v5",
    [
        {
            "type": "complete",
            "extra_args": [
                "-enable-custom-resources",
                "-enable-leader-election=false",
                "-enable-app-protect",
            ],
        }
    ],
    indirect=True,
)
class TestWAFBundleSourceInsecureIngress:
    def test_bundle_source_block_ingress(
        self,
        kube_apis,
        crd_ingress_controller_with_waf_v5,
        test_namespace,
        ingress_setup,
        bundle_server,
    ):
        pol_name = create_waf_bundle_source_policy(
            kube_apis.custom_objects,
            test_namespace,
            POLICY_NAME,
            bundle_server.insecure_url,
            insecure_skip_verify=True,
        )
        wait_before_test(10)

        request_url = (
            f"http://{ingress_setup.public_endpoint.public_ip}:" f"{ingress_setup.public_endpoint.port}/backend1"
        )
        response = send_malicious_request_with_retry(request_url, ingress_setup.ingress_host)

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

        assert_waf_blocked(response)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect_waf_v5
@pytest.mark.appprotect_waf_bundle_source
@pytest.mark.parametrize(
    "crd_ingress_controller_with_waf_v5",
    [
        {
            "type": "complete",
            "extra_args": [
                "-enable-custom-resources",
                "-enable-leader-election=false",
                "-enable-app-protect",
            ],
        }
    ],
    indirect=True,
)
class TestWAFBundleSourceMTLSIngress:
    def test_bundle_source_mtls_block_ingress(
        self,
        kube_apis,
        crd_ingress_controller_with_waf_v5,
        test_namespace,
        ingress_setup,
        bundle_server,
    ):
        pol_name = create_waf_bundle_source_policy(
            kube_apis.custom_objects,
            test_namespace,
            POLICY_NAME,
            bundle_server.mtls_url,
            insecure_skip_verify=True,
            secret=bundle_server.client_secret,
        )
        wait_before_test(10)

        request_url = (
            f"http://{ingress_setup.public_endpoint.public_ip}:" f"{ingress_setup.public_endpoint.port}/backend1"
        )
        response = send_malicious_request_with_retry(request_url, ingress_setup.ingress_host)

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

        assert_waf_blocked(response)

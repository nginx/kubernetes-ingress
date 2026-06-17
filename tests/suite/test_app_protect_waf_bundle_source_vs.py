import pytest
import requests
from settings import TEST_DATA
from suite.utils.bundle_source_utils import (
    BundleServerSetup,
    create_waf_bundle_source_policy,
    patch_waf_bundle_source_policy,
    setup_bundle_server,
    teardown_bundle_server,
)
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
    patch_virtual_server_from_yaml,
)

WAF_SPEC_VS = f"{TEST_DATA}/ap-waf-v5/virtual-server-waf-spec.yaml"
WAF_ROUTE_VS = f"{TEST_DATA}/ap-waf-v5/virtual-server-waf-route.yaml"
STD_VS = f"{TEST_DATA}/ap-waf-v5/standard/virtual-server.yaml"

POLICY_NAME = "waf-policy"
INVALID_BUNDLE_URL = "https://does-not-exist.invalid/bundles/waf.tgz"


def send_malicious_request_with_retry(url, host, retries=10):
    """Send a request with an embedded XSS payload, retrying until WAF blocks it."""
    response = requests.get(url + "</script>", headers={"host": host})
    count = 0
    while count < retries and "Request Rejected" not in response.text:
        wait_before_test(2)
        response = requests.get(url + "</script>", headers={"host": host})
        count += 1
    return response


def assert_waf_blocked(response):
    """Assert that the response was rejected by App Protect WAF."""
    assert response.status_code == 200
    assert "The requested URL was rejected. Please consult with your administrator." in response.text


def restore_default_vs(kube_apis, virtual_server_setup):
    """Restore the VirtualServer to its default state without WAF policy."""
    delete_virtual_server(
        kube_apis.custom_objects,
        virtual_server_setup.vs_name,
        virtual_server_setup.namespace,
    )
    create_virtual_server_from_yaml(
        kube_apis.custom_objects,
        STD_VS,
        virtual_server_setup.namespace,
    )
    wait_before_test()


@pytest.fixture(scope="class")
def bundle_server(kube_apis, test_namespace) -> BundleServerSetup:
    """Deploy an HTTPS bundle server serving WAF bundles with TLS + mTLS endpoints."""
    server = setup_bundle_server(kube_apis, test_namespace)
    yield server
    teardown_bundle_server(kube_apis, test_namespace)


IC_PARAMS = {
    "type": "complete",
    "extra_args": ["-enable-app-protect"],
}
VS_PARAMS = {
    "example": "ap-waf-v5",
    "app_type": "simple",
}


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect_waf_v5
@pytest.mark.appprotect_waf_bundle_source
@pytest.mark.parametrize(
    "crd_ingress_controller_with_waf_v5, virtual_server_setup",
    [(IC_PARAMS, VS_PARAMS)],
    indirect=True,
)
class TestWAFBundleSourceInsecureVS:
    @pytest.mark.parametrize(
        "vs_src",
        [WAF_SPEC_VS, WAF_ROUTE_VS],
        ids=["spec-level", "route-level"],
    )
    def test_bundle_source_insecure_block_vs(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_waf_v5,
        virtual_server_setup,
        test_namespace,
        bundle_server,
        vs_src,
    ):
        pol_name = create_waf_bundle_source_policy(
            kube_apis.custom_objects,
            test_namespace,
            POLICY_NAME,
            bundle_server.insecure_url,
            insecure_skip_verify=True,
        )
        wait_before_test()

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        response = send_malicious_request_with_retry(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
        )

        restore_default_vs(kube_apis, virtual_server_setup)
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

        assert_waf_blocked(response)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect_waf_v5
@pytest.mark.appprotect_waf_bundle_source
@pytest.mark.parametrize(
    "crd_ingress_controller_with_waf_v5, virtual_server_setup",
    [(IC_PARAMS, VS_PARAMS)],
    indirect=True,
)
class TestWAFBundleSourceMTLSVS:
    def test_bundle_source_mtls_block_vs(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_waf_v5,
        virtual_server_setup,
        test_namespace,
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
        wait_before_test()

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            WAF_SPEC_VS,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        response = send_malicious_request_with_retry(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
        )

        restore_default_vs(kube_apis, virtual_server_setup)
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

        assert_waf_blocked(response)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect_waf_v5
@pytest.mark.appprotect_waf_bundle_source
@pytest.mark.parametrize(
    "crd_ingress_controller_with_waf_v5, virtual_server_setup",
    [(IC_PARAMS, VS_PARAMS)],
    indirect=True,
)
class TestWAFBundleSourceFailureVS:
    def test_bundle_source_invalid_url(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_waf_v5,
        virtual_server_setup,
        test_namespace,
    ):
        pol_name = create_waf_bundle_source_policy(
            kube_apis.custom_objects,
            test_namespace,
            POLICY_NAME,
            INVALID_BUNDLE_URL,
            insecure_skip_verify=True,
        )

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            WAF_SPEC_VS,
            virtual_server_setup.namespace,
        )

        # Wait for the controller to attempt the fetch and update policy status.
        wait_before_test(5)

        policy_info = read_custom_resource(
            kube_apis.custom_objects,
            test_namespace,
            "policies",
            POLICY_NAME,
        )

        # The controller sets Warning + BundleFetchFailed when the initial fetch fails.
        assert "status" in policy_info, f"Policy has no status: {policy_info}"
        assert policy_info["status"]["state"] == "Warning", f"Expected Warning state, got: {policy_info['status']}"

        # WAF is inactive so a malicious request should NOT be blocked with
        # the rejection page. The VS may return a 500 or the backend's response
        # depending on how the NGINX config was generated.
        response = requests.get(
            virtual_server_setup.backend_1_url + "</script>",
            headers={"host": virtual_server_setup.vs_host},
        )
        assert "The requested URL was rejected" not in response.text

        restore_default_vs(kube_apis, virtual_server_setup)
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

    def test_bundle_source_recovery(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_waf_v5,
        virtual_server_setup,
        test_namespace,
        bundle_server,
    ):
        # Step 1: Create policy with unreachable URL.
        pol_name = create_waf_bundle_source_policy(
            kube_apis.custom_objects,
            test_namespace,
            POLICY_NAME,
            INVALID_BUNDLE_URL,
            insecure_skip_verify=True,
        )

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            WAF_SPEC_VS,
            virtual_server_setup.namespace,
        )
        wait_before_test(5)

        # Confirm Warning status.
        policy_info = read_custom_resource(
            kube_apis.custom_objects,
            test_namespace,
            "policies",
            POLICY_NAME,
        )
        assert policy_info.get("status", {}).get("state") == "Warning"

        # Step 2: Patch policy to a valid bundle URL.
        patch_waf_bundle_source_policy(
            kube_apis.custom_objects,
            test_namespace,
            POLICY_NAME,
            bundle_server.insecure_url,
            insecure_skip_verify=True,
        )

        # Step 3: Wait for WAF to become active and verify blocking.
        response = send_malicious_request_with_retry(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            retries=15,
        )

        restore_default_vs(kube_apis, virtual_server_setup)
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

        assert_waf_blocked(response)

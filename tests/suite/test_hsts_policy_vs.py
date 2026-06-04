import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import create_secret_from_yaml, delete_secret, wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    delete_and_create_vs_from_yaml,
    patch_virtual_server_from_yaml,
    read_vs,
)

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
tls_sec_src = f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"

hsts_pol_src = f"{TEST_DATA}/hsts/policies/hsts-policy.yaml"
hsts_pol_subdomains_src = f"{TEST_DATA}/hsts/policies/hsts-policy-subdomains.yaml"
hsts_pol_behind_proxy_src = f"{TEST_DATA}/hsts/policies/hsts-policy-behind-proxy.yaml"

hsts_vs_spec_src = f"{TEST_DATA}/hsts/spec/virtual-server-hsts-spec.yaml"
hsts_vs_spec_subdomains_src = f"{TEST_DATA}/hsts/spec/virtual-server-hsts-subdomains-spec.yaml"
hsts_vs_spec_behind_proxy_src = f"{TEST_DATA}/hsts/spec/virtual-server-hsts-behind-proxy-spec.yaml"


def setup_policy(kube_apis, test_namespace, policy_src, tls_secret_src):
    """Create HSTS policy and TLS secret, return their names for teardown."""
    tls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, tls_secret_src)
    pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_src, test_namespace)
    wait_before_test()
    return tls_secret_name, pol_name


def teardown_policy(kube_apis, test_namespace, tls_secret_name, pol_name):
    delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
    delete_secret(kube_apis.v1, tls_secret_name, test_namespace)


@pytest.mark.policies
@pytest.mark.policies_hsts
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-enable-leader-election=false",
                ],
            },
            {
                "example": "virtual-server",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestHSTSPolicyVS:
    """Tests for the HSTS policy on VirtualServer resources."""

    def test_hsts_header_present_on_https(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """HTTPS request to a VS with HSTS policy receives the Strict-Transport-Security header."""
        tls_secret_name, pol_name = setup_policy(kube_apis, test_namespace, hsts_pol_src, tls_sec_src)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            hsts_vs_spec_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp = requests.get(
            virtual_server_setup.backend_1_url_ssl,
            headers={"host": virtual_server_setup.vs_host},
            allow_redirects=False,
            verify=False,
        )
        print(f"Response headers: {resp.headers}")

        vs_res = read_vs(kube_apis.custom_objects, test_namespace, virtual_server_setup.vs_name)
        teardown_policy(kube_apis, test_namespace, tls_secret_name, pol_name)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, test_namespace
        )

        assert resp.status_code == 200
        assert "Strict-Transport-Security" in resp.headers
        assert "max-age=2592000" in resp.headers["Strict-Transport-Security"]
        assert vs_res["status"]["state"] == "Valid"

    def test_hsts_header_absent_on_http(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """HTTP request to a VS with HSTS policy does not receive the Strict-Transport-Security header."""
        tls_secret_name, pol_name = setup_policy(kube_apis, test_namespace, hsts_pol_src, tls_sec_src)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            hsts_vs_spec_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
            allow_redirects=False,
        )
        print(f"Response headers: {resp.headers}")

        teardown_policy(kube_apis, test_namespace, tls_secret_name, pol_name)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, test_namespace
        )

        assert "Strict-Transport-Security" not in resp.headers

    def test_hsts_include_subdomains(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """HSTS header includes the includeSubDomains directive when configured."""
        tls_secret_name, pol_name = setup_policy(kube_apis, test_namespace, hsts_pol_subdomains_src, tls_sec_src)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            hsts_vs_spec_subdomains_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp = requests.get(
            virtual_server_setup.backend_1_url_ssl,
            headers={"host": virtual_server_setup.vs_host},
            allow_redirects=False,
            verify=False,
        )
        print(f"Response headers: {resp.headers}")

        teardown_policy(kube_apis, test_namespace, tls_secret_name, pol_name)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, test_namespace
        )

        assert "Strict-Transport-Security" in resp.headers
        assert "includeSubDomains" in resp.headers["Strict-Transport-Security"]

    def test_hsts_behind_proxy(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """With behindProxy enabled, the HSTS header is controlled by X-Forwarded-Proto."""
        tls_secret_name, pol_name = setup_policy(kube_apis, test_namespace, hsts_pol_behind_proxy_src, tls_sec_src)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            hsts_vs_spec_behind_proxy_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp_xfp_https = requests.get(
            virtual_server_setup.backend_1_url_ssl,
            headers={
                "host": virtual_server_setup.vs_host,
                "X-Forwarded-Proto": "https",
            },
            allow_redirects=False,
            verify=False,
        )
        resp_xfp_http = requests.get(
            virtual_server_setup.backend_1_url_ssl,
            headers={
                "host": virtual_server_setup.vs_host,
                "X-Forwarded-Proto": "http",
            },
            allow_redirects=False,
            verify=False,
        )
        print(f"XFP https headers: {resp_xfp_https.headers}")
        print(f"XFP http headers: {resp_xfp_http.headers}")

        teardown_policy(kube_apis, test_namespace, tls_secret_name, pol_name)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, test_namespace
        )

        assert "Strict-Transport-Security" in resp_xfp_https.headers
        assert "Strict-Transport-Security" not in resp_xfp_http.headers

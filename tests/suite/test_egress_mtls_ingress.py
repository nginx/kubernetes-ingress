import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import apply_and_wait_for_valid_policy, create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_secret,
    ensure_connection_to_public_endpoint,
    get_reload_count,
    wait_before_test,
    wait_for_reload,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml, get_name_from_yaml

trusted_cert_secret_src = f"{TEST_DATA}/egress-mtls/secret/egress-mtls-secret.yaml"
tls_secret_src = f"{TEST_DATA}/egress-mtls/secret/tls-secret.yaml"

valid_policy_src = f"{TEST_DATA}/egress-mtls/policies/egress-mtls.yaml"
invalid_policy_src = f"{TEST_DATA}/egress-mtls/policies/egress-mtls-invalid.yaml"

valid_ingress_variants = [
    pytest.param("standard", id="standard"),
    pytest.param("mergeable-master", id="mergeable-master"),
    pytest.param("mergeable-minion", id="mergeable-minion"),
]

invalid_ingress_variants = [
    pytest.param("standard-invalid", id="standard-invalid"),
    pytest.param("mergeable-master-invalid", id="mergeable-master-invalid"),
    pytest.param("mergeable-minion-invalid", id="mergeable-minion-invalid"),
]


class IngressSetup:
    """Capture the data needed to exercise an Ingress example variant."""

    def __init__(self, ingress_src_file, ingress_name, ingress_host, namespace, request_url, metrics_url):
        self.ingress_src_file = ingress_src_file
        self.ingress_name = ingress_name
        self.ingress_host = ingress_host
        self.namespace = namespace
        self.request_url = request_url
        self.metrics_url = metrics_url


def setup_policy(kube_apis, test_namespace, policy_src):
    """Create the trusted CA and client TLS secrets, then apply a valid egress mTLS policy."""

    print("------------- Create egress mTLS secrets --------------")
    trusted_cert_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, trusted_cert_secret_src)
    tls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, tls_secret_src)

    print("------------- Create egress mTLS policy --------------")
    apply_and_wait_for_valid_policy(kube_apis, test_namespace, policy_src)
    policy_name = get_name_from_yaml(policy_src)

    return trusted_cert_secret_name, tls_secret_name, policy_name


def setup_invalid_policy(kube_apis, test_namespace, policy_src):
    """Create the trusted CA and client TLS secrets, then apply an intentionally invalid egress mTLS policy."""

    print("------------- Create egress mTLS secrets --------------")
    trusted_cert_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, trusted_cert_secret_src)
    tls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, tls_secret_src)

    print("------------- Create invalid egress mTLS policy --------------")
    policy_name = create_policy_from_yaml(kube_apis.custom_objects, policy_src, test_namespace)
    wait_before_test(2)

    return trusted_cert_secret_name, tls_secret_name, policy_name


def teardown_policy(kube_apis, test_namespace, policy_name, tls_secret_name, mtls_secret_name):
    """Remove the policy and both secrets created for a test case."""

    print("------------- Delete policy and related secrets --------------")
    delete_policy(kube_apis.custom_objects, policy_name, test_namespace)
    delete_secret(kube_apis.v1, tls_secret_name, test_namespace)
    delete_secret(kube_apis.v1, mtls_secret_name, test_namespace)


def deploy_ingress(kube_apis, ingress_controller_endpoint, test_namespace, ingress_variant):
    """Deploy a specific ingress variant and wait for NGINX to reload it."""

    src = f"{TEST_DATA}/egress-mtls/ingress/{ingress_variant}/egress-mtls-ingress.yaml"
    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
    count_before = get_reload_count(metrics_url)

    print(f"------------- Create ingress from {src} --------------")
    create_items_from_yaml(kube_apis, src, test_namespace)

    print("------------- Wait for reload after ingress apply --------------")
    wait_for_reload(metrics_url, count_before)

    ingress_name = get_name_from_yaml(src)
    ingress_host = get_first_ingress_host_from_yaml(src)
    request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

    return IngressSetup(src, ingress_name, ingress_host, test_namespace, request_url, metrics_url)


@pytest.fixture(scope="function")
def backend_setup(request, kube_apis, test_namespace):
    """Deploy the secure backend once per test case and clean it up afterwards."""

    print("------------- Deploy secure backend app --------------")
    create_example_app(kube_apis, "secure-ca", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("------------- Delete secure backend app --------------")
            delete_common_app(kube_apis, "secure-ca", test_namespace)

    request.addfinalizer(fin)


@pytest.mark.policies
@pytest.mark.policies_mtls
@pytest.mark.annotations
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        {
            "type": "complete",
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-leader-election=false",
                f"-enable-prometheus-metrics",
            ],
        },
    ],
    indirect=True,
)
class TestEgressMTLSPoliciesIngress:
    @pytest.mark.parametrize("ingress_variant", valid_ingress_variants)
    @pytest.mark.smoke
    def test_valid_egress_mtls_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        backend_setup,
        ingress_controller_endpoint,
        test_namespace,
        ingress_variant,
    ):
        """Validate valid egress mTLS policies for standard ingress and both mergeable annotation placements."""

        policy_name = tls_secret_name = mtls_secret_name = None
        ingress_setup = None

        try:
            mtls_secret_name, tls_secret_name, policy_name = setup_policy(kube_apis, test_namespace, valid_policy_src)
            ingress_setup = deploy_ingress(kube_apis, ingress_controller_endpoint, test_namespace, ingress_variant)

            ensure_connection_to_public_endpoint(
                ingress_controller_endpoint.public_ip,
                ingress_controller_endpoint.port,
                ingress_controller_endpoint.port_ssl,
            )
            # Exercise the active ingress variant through the public endpoint.
            resp = requests.get(ingress_setup.request_url, headers={"host": ingress_setup.ingress_host})

            # Valid egress mTLS policies should allow requests to reach the secure backend.
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
            assert "hello from pod secure-app" in resp.text, f"Unexpected response body: {resp.text}"
        finally:
            if ingress_setup is not None:
                delete_items_from_yaml(kube_apis, ingress_setup.ingress_src_file, test_namespace)
            if policy_name is not None:
                teardown_policy(kube_apis, test_namespace, policy_name, tls_secret_name, mtls_secret_name)

    @pytest.mark.parametrize("ingress_variant", invalid_ingress_variants)
    def test_invalid_egress_mtls_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        backend_setup,
        ingress_controller_endpoint,
        test_namespace,
        ingress_variant,
    ):
        """Validate invalid egress mTLS policies fail closed for standard ingress and both mergeable annotation placements."""

        policy_name = tls_secret_name = mtls_secret_name = None
        ingress_setup = None

        try:
            mtls_secret_name, tls_secret_name, policy_name = setup_invalid_policy(
                kube_apis, test_namespace, invalid_policy_src
            )
            ingress_setup = deploy_ingress(kube_apis, ingress_controller_endpoint, test_namespace, ingress_variant)

            ensure_connection_to_public_endpoint(
                ingress_controller_endpoint.public_ip,
                ingress_controller_endpoint.port,
                ingress_controller_endpoint.port_ssl,
            )
            # Exercise the active ingress variant and read the rejected Policy status.
            resp = requests.get(ingress_setup.request_url, headers={"host": ingress_setup.ingress_host})
            policy_info = read_custom_resource(
                kube_apis.custom_objects, test_namespace, "policies", "egress-mtls-policy"
            )

            # Invalid egress mTLS policies should fail closed and surface a rejected Policy status.
            assert resp.status_code == 500, f"Expected 500, got {resp.status_code}"
            assert (
                policy_info["status"]["reason"] == "Rejected"
            ), f"Unexpected policy status: {policy_info.get('status', {})}"
            assert (
                policy_info["status"]["state"] == "Invalid"
            ), f"Unexpected policy status: {policy_info.get('status', {})}"
        finally:
            if ingress_setup is not None:
                delete_items_from_yaml(kube_apis, ingress_setup.ingress_src_file, test_namespace)
            if policy_name is not None:
                teardown_policy(kube_apis, test_namespace, policy_name, tls_secret_name, mtls_secret_name)

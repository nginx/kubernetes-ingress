import pytest
import requests
from settings import TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.policy_resources_utils import apply_and_wait_for_valid_policy, delete_policy
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


class AppProtectWAFv5PolicyIngressSetup:
    def __init__(self, public_endpoint: PublicEndpoint, ingress_host: str):
        self.public_endpoint = public_endpoint
        self.ingress_host = ingress_host


ingress_src = f"{TEST_DATA}/ap-waf-v5/ingress-policy.yaml"
mergable_ing_src = f"{TEST_DATA}/ap-waf-v5/mergeable-ingress-policy.yaml"
policy_src = f"{TEST_DATA}/ap-waf-v5/policies/waf.yaml"


def assert_waf_rejected(response):
    assert response.status_code == 200
    assert "Request Rejected" in response.text
    assert "The requested URL was rejected. Please consult with your administrator." in response.text


def send_malicious_request_with_retry(url, host):
    response = requests.get(url + "</script>", headers={"host": host})
    retries = 0
    while retries < 5 and "Request Rejected" not in response.text:
        wait_before_test(1)
        response = requests.get(url + "</script>", headers={"host": host})
        retries += 1
    return response


def create_ingress_setup(kube_apis, ingress_controller_endpoint, test_namespace, ingress_src):
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    create_items_from_yaml(kube_apis, ingress_src, test_namespace)

    ingress_host = get_first_ingress_host_from_yaml(ingress_src)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )
    wait_before_test()

    return AppProtectWAFv5PolicyIngressSetup(ingress_controller_endpoint, ingress_host)


def cleanup_ingress_setup(kube_apis, ingress_src, test_namespace):
    delete_items_from_yaml(kube_apis, ingress_src, test_namespace)
    delete_common_app(kube_apis, "simple", test_namespace)


@pytest.fixture(scope="function")
def ingress_setup(kube_apis, ingress_controller_endpoint, test_namespace):
    setup = create_ingress_setup(kube_apis, ingress_controller_endpoint, test_namespace, ingress_src)
    yield setup
    cleanup_ingress_setup(kube_apis, ingress_src, test_namespace)


@pytest.fixture(scope="function")
def mergeable_ingress_setup(kube_apis, ingress_controller_endpoint, test_namespace):
    setup = create_ingress_setup(kube_apis, ingress_controller_endpoint, test_namespace, mergable_ing_src)
    yield setup
    cleanup_ingress_setup(kube_apis, mergable_ing_src, test_namespace)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect_waf_v5
@pytest.mark.appprotect_waf_policies_ing_v5
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
class TestAppProtectWAFv5PolicyIngress:
    def test_waf_policy_v5_on_ingress(
        self,
        kube_apis,
        crd_ingress_controller_with_waf_v5,
        test_namespace,
        ingress_setup,
    ):
        apply_and_wait_for_valid_policy(kube_apis, test_namespace, policy_src)

        request_url = f"http://{ingress_setup.public_endpoint.public_ip}:{ingress_setup.public_endpoint.port}/backend1"
        response = send_malicious_request_with_retry(request_url, ingress_setup.ingress_host)

        delete_policy(kube_apis.custom_objects, "waf-policy", test_namespace)
        assert_waf_rejected(response)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect_waf_v5
@pytest.mark.appprotect_waf_policies_ing_v5
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
class TestAppProtectWAFv5PolicyMergeableIngress:
    def test_waf_policy_v5_on_mergeable_ingress(
        self,
        kube_apis,
        crd_ingress_controller_with_waf_v5,
        test_namespace,
        mergeable_ingress_setup,
    ):
        apply_and_wait_for_valid_policy(kube_apis, test_namespace, policy_src)

        request_url = (
            f"http://{mergeable_ingress_setup.public_endpoint.public_ip}:"
            f"{mergeable_ingress_setup.public_endpoint.port}/backend1"
        )
        response = send_malicious_request_with_retry(request_url, mergeable_ingress_setup.ingress_host)

        delete_policy(kube_apis.custom_objects, "waf-policy", test_namespace)
        assert_waf_rejected(response)

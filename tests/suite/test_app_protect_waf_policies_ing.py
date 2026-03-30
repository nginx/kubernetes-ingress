import pytest
import requests
from settings import TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.ap_resources_utils import (
    create_ap_logconf_from_yaml,
    create_ap_policy_from_yaml,
    create_ap_usersig_from_yaml,
    create_ap_waf_policy_from_yaml,
    delete_ap_logconf,
    delete_ap_policy,
    delete_ap_usersig,
)
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml


class AppProtectWAFPolicyIngressSetup:
    def __init__(self, public_endpoint: PublicEndpoint, ingress_host: str):
        self.public_endpoint = public_endpoint
        self.ingress_host = ingress_host


ingress_src = f"{TEST_DATA}/ap-waf/ingress-policy.yaml"
mergeable_ing_src = f"{TEST_DATA}/ap-waf/mergeable-ingress-policy.yaml"
policy_src = f"{TEST_DATA}/ap-waf/policies/waf-dataguard.yaml"


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

    return AppProtectWAFPolicyIngressSetup(ingress_controller_endpoint, ingress_host)


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
    setup = create_ingress_setup(kube_apis, ingress_controller_endpoint, test_namespace, mergeable_ing_src)
    yield setup
    cleanup_ingress_setup(kube_apis, mergeable_ing_src, test_namespace)


@pytest.fixture(scope="function")
def appprotect_v4_resources(request, kube_apis, test_namespace):
    logconf_src = f"{TEST_DATA}/ap-waf/logconf.yaml"
    usersig_src = f"{TEST_DATA}/ap-waf/ap-ic-uds.yaml"
    appolicy_src = f"{TEST_DATA}/ap-waf/dataguard-alarm-uds.yaml"

    log_name = create_ap_logconf_from_yaml(kube_apis.custom_objects, logconf_src, test_namespace)
    usersig_name = create_ap_usersig_from_yaml(kube_apis.custom_objects, usersig_src, test_namespace)
    appolicy_name = create_ap_policy_from_yaml(kube_apis.custom_objects, appolicy_src, test_namespace)

    wait_before_test()

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            delete_ap_policy(kube_apis.custom_objects, appolicy_name, test_namespace)
            delete_ap_usersig(kube_apis.custom_objects, usersig_name, test_namespace)
            delete_ap_logconf(kube_apis.custom_objects, log_name, test_namespace)

    request.addfinalizer(fin)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect
@pytest.mark.appprotect_waf_policies_ing
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
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
class TestAppProtectWAFPolicyIngress:
    def test_waf_policy_v4_on_ingress(
        self,
        kube_apis,
        crd_ingress_controller_with_ap,
        test_namespace,
        appprotect_v4_resources,
        ingress_setup,
    ):
        create_ap_waf_policy_from_yaml(
            kube_apis.custom_objects,
            policy_src,
            test_namespace,
            test_namespace,
            True,
            True,
            "dataguard-alarm-uds",
            "logconf",
            "syslog:server=127.0.0.1:514",
        )

        request_url = f"http://{ingress_setup.public_endpoint.public_ip}:{ingress_setup.public_endpoint.port}/backend1"
        ensure_response_from_backend(request_url, ingress_setup.ingress_host, check404=True)
        response = send_malicious_request_with_retry(request_url, ingress_setup.ingress_host)

        delete_policy(kube_apis.custom_objects, "waf-policy", test_namespace)
        assert_waf_rejected(response)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect
@pytest.mark.appprotect_waf_policies_ing
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
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
class TestAppProtectWAFPolicyMergeableIngress:
    def test_waf_policy_v4_on_mergeable_ingress(
        self,
        kube_apis,
        crd_ingress_controller_with_ap,
        test_namespace,
        appprotect_v4_resources,
        mergeable_ingress_setup,
    ):
        create_ap_waf_policy_from_yaml(
            kube_apis.custom_objects,
            policy_src,
            test_namespace,
            test_namespace,
            True,
            True,
            "dataguard-alarm-uds",
            "logconf",
            "syslog:server=127.0.0.1:514",
        )

        request_url = (
            f"http://{mergeable_ingress_setup.public_endpoint.public_ip}:"
            f"{mergeable_ingress_setup.public_endpoint.port}/backend1"
        )
        ensure_response_from_backend(request_url, mergeable_ingress_setup.ingress_host, check404=True)
        response = send_malicious_request_with_retry(request_url, mergeable_ingress_setup.ingress_host)

        delete_policy(kube_apis.custom_objects, "waf-policy", test_namespace)
        assert_waf_rejected(response)

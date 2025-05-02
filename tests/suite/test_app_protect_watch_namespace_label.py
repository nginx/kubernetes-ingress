import time

import pytest
import requests
from settings import TEST_DATA
from suite.utils.ap_resources_utils import (
    create_ap_logconf_from_yaml,
    create_ap_policy_from_yaml,
    delete_ap_logconf,
    delete_ap_policy,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress_with_ap_annotations,
    create_items_from_yaml,
    create_namespace_with_name_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_namespace,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    patch_namespace_with_label,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

# This test shows that a policy outside of the namespace test_namespace is not picked up by IC.

valid_resp_body = "Server name:"
invalid_resp_body = "The requested URL was rejected. Please consult with your administrator."
reload_times = {}


class BackendSetup:
    """
    Encapsulate the example details.

    Attributes:
        req_url (str):
        ingress_host (str):
    """

    def __init__(self, req_url, req_url_2, metrics_url, ingress_host, test_namespace, policy_namespace):
        self.req_url = req_url
        self.req_url_2 = req_url_2
        self.metrics_url = metrics_url
        self.ingress_host = ingress_host
        self.test_namespace = test_namespace
        self.policy_namespace = policy_namespace


@pytest.fixture(scope="class")
def backend_setup(request, kube_apis, ingress_controller_endpoint) -> BackendSetup:
    """
    Deploy a simple application and AppProtect manifests.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :param test_namespace:
    :return: BackendSetup
    """
    timestamp = round(time.time() * 1000)
    test_namespace = f"test-namespace-{str(timestamp)}"
    policy_namespace = f"policy-test-namespace-{str(timestamp)}"
    policy = "file-block"

    create_namespace_with_name_from_yaml(kube_apis.v1, test_namespace, f"{TEST_DATA}/common/ns.yaml")
    print("------------------------- Deploy backend application -------------------------")

    create_example_app(kube_apis, "simple", test_namespace)
    req_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"
    req_url_2 = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend2"
    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )

    print("------------------------- Deploy Secret -----------------------------")
    src_sec_yaml = f"{TEST_DATA}/appprotect/appprotect-secret.yaml"
    create_items_from_yaml(kube_apis, src_sec_yaml, test_namespace)

    print("------------------------- Deploy logconf -----------------------------")
    src_log_yaml = f"{TEST_DATA}/appprotect/logconf.yaml"
    log_name = create_ap_logconf_from_yaml(kube_apis.custom_objects, src_log_yaml, test_namespace)

    print(f"------------------------- Deploy namespace: {policy_namespace} ---------------------------")
    create_namespace_with_name_from_yaml(kube_apis.v1, policy_namespace, f"{TEST_DATA}/common/ns.yaml")

    print(f"------------------------- Deploy appolicy: {policy} ---------------------------")
    src_pol_yaml = f"{TEST_DATA}/appprotect/{policy}.yaml"
    pol_name = create_ap_policy_from_yaml(kube_apis.custom_objects, src_pol_yaml, policy_namespace)

    print("------------------------- Deploy ingress -----------------------------")
    ingress_host = {}
    src_ing_yaml = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"
    create_ingress_with_ap_annotations(
        kube_apis, src_ing_yaml, test_namespace, f"{policy_namespace}/{policy}", "True", "True", "127.0.0.1:514"
    )
    ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)
    wait_before_test()

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            src_ing_yaml = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"
            delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
            delete_ap_policy(kube_apis.custom_objects, pol_name, policy_namespace)
            delete_namespace(kube_apis.v1, policy_namespace)
            delete_ap_logconf(kube_apis.custom_objects, log_name, test_namespace)
            delete_common_app(kube_apis, "simple", test_namespace)
            src_sec_yaml = f"{TEST_DATA}/appprotect/appprotect-secret.yaml"
            delete_items_from_yaml(kube_apis, src_sec_yaml, test_namespace)
            delete_namespace(kube_apis.v1, test_namespace)

    request.addfinalizer(fin)

    return BackendSetup(req_url, req_url_2, metrics_url, ingress_host, test_namespace, policy_namespace)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect
@pytest.mark.appprotect_watch
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
    [
        {
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-app-protect",
                f"-enable-prometheus-metrics",
                f"-watch-namespace-label=app=watch",
                f"-log-level=debug",
            ]
        }
    ],
    indirect=True,
)
class TestAppProtectWatchNamespaceLabelEnabled:
    def test_responses(self, request, kube_apis, crd_ingress_controller_with_ap, backend_setup):
        """
        Test file-block AppProtect policy with -watch-namespace-label
        """
        patch_namespace_with_label(
            kube_apis.v1, backend_setup.test_namespace, "watch", f"{TEST_DATA}/common/ns-patch.yaml"
        )
        wait_before_test()
        print("------------- Run test for AP policy: file-block not enforced --------------")
        # The policy namespace does not have the watched label, show the policy is not enforced
        print(f"Request URL: {backend_setup.req_url} and Host: {backend_setup.ingress_host}")

        ensure_response_from_backend(backend_setup.req_url, backend_setup.ingress_host, check404=True)

        print("----------------------- Send request ----------------------")
        resp = requests.get(
            f"{backend_setup.req_url}/test.bat", headers={"host": backend_setup.ingress_host}, verify=False
        )

        print(resp.text)

        assert valid_resp_body in resp.text
        assert resp.status_code == 200

        # Add the label to the policy namespace, show the policy is now enforced
        patch_namespace_with_label(
            kube_apis.v1, backend_setup.policy_namespace, "watch", f"{TEST_DATA}/common/ns-patch.yaml"
        )
        wait_before_test(15)
        print("------------- Run test for AP policy: file-block is enforced now --------------")
        print(f"Request URL: {backend_setup.req_url} and Host: {backend_setup.ingress_host}")

        ensure_response_from_backend(backend_setup.req_url, backend_setup.ingress_host, check404=True)

        print("----------------------- Send request ----------------------")
        resp = requests.get(
            f"{backend_setup.req_url}/test.bat", headers={"host": backend_setup.ingress_host}, verify=False
        )
        retry = 0
        while invalid_resp_body not in resp.text and retry <= 60:
            resp = requests.get(
                f"{backend_setup.req_url}/test.bat", headers={"host": backend_setup.ingress_host}, verify=False
            )
            retry += 1
            wait_before_test(1)
            print(f"Policy not yet enforced, retrying... #{retry}")

        assert invalid_resp_body in resp.text
        assert resp.status_code == 200

        # Remove the label again fro the policy namespace, show the policy is not enforced again
        patch_namespace_with_label(
            kube_apis.v1, backend_setup.policy_namespace, "nowatch", f"{TEST_DATA}/common/ns-patch.yaml"
        )
        wait_before_test(15)
        print("------------- Run test for AP policy: file-block not enforced again --------------")
        print(f"Request URL: {backend_setup.req_url} and Host: {backend_setup.ingress_host}")

        ensure_response_from_backend(backend_setup.req_url, backend_setup.ingress_host, check404=True)

        print("----------------------- Send request ----------------------")
        resp = requests.get(
            f"{backend_setup.req_url}/test.bat", headers={"host": backend_setup.ingress_host}, verify=False
        )
        retry = 0
        while valid_resp_body not in resp.text and retry <= 60:
            resp = requests.get(
                f"{backend_setup.req_url}/test.bat", headers={"host": backend_setup.ingress_host}, verify=False
            )
            retry += 1
            wait_before_test(1)
            print(f"Policy not yet removed, retrying... #{retry}")

        assert valid_resp_body in resp.text
        assert resp.status_code == 200

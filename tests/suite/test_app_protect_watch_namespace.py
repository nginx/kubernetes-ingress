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
    generate_e2e_run_id,
    get_e2e_run_selector,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

# This test shows that a policy outside of the namespace test_namespace is not picked up by IC.

timestamp = round(time.time() * 1000)
test_namespace = f"test-namespace-{str(timestamp)}"
policy_namespace = f"policy-test-namespace-{str(timestamp)}"
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

    def __init__(self, req_url, req_url_2, metrics_url, ingress_host):
        self.req_url = req_url
        self.req_url_2 = req_url_2
        self.metrics_url = metrics_url
        self.ingress_host = ingress_host


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
    policy = "file-block"
    e2e_run_id = generate_e2e_run_id()

    create_namespace_with_name_from_yaml(kube_apis.v1, test_namespace, f"{TEST_DATA}/common/ns.yaml")
    print("------------------------- Deploy backend application -------------------------")

    create_example_app(kube_apis, "simple", test_namespace, e2e_run_id=e2e_run_id)
    req_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"
    req_url_2 = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend2"
    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace, get_e2e_run_selector(e2e_run_id))
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

    return BackendSetup(req_url, req_url_2, metrics_url, ingress_host)


# the first case does not set "-watch-namespace" so the policy is configured on the ingress.
# This causes the traffic to be blocked


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect
@pytest.mark.appprotect_watch
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
    [{"extra_args": [f"-enable-custom-resources", f"-enable-app-protect", f"-enable-prometheus-metrics"]}],
    indirect=True,
)
class TestAppProtectWatchNamespaceDisabled:
    def test_responses(self, request, kube_apis, crd_ingress_controller_with_ap, backend_setup):
        """
        Test file_block AppProtect policy without -watch-namespace
        """
        print("------------- Run test for AP policy: file-block --------------")
        print(f"Request URL: {backend_setup.req_url} and Host: {backend_setup.ingress_host}")

        ensure_response_from_backend(backend_setup.req_url, backend_setup.ingress_host, check404=True)

        print("----------------------- Send request ----------------------")
        resp = requests.get(
            f"{backend_setup.req_url}/test.bat", headers={"host": backend_setup.ingress_host}, verify=False
        )

        print(resp.text)

        assert invalid_resp_body in resp.text
        assert resp.status_code == 200


# In this test case the "-watch-namespace" param is set so the policy in policy_namespace
# Is not configured on the ingress -> NAP uses the default policy which will not block the same request.


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
                f"-watch-namespace={test_namespace}",
            ]
        }
    ],
    indirect=True,
)
class TestAppProtectWatchNamespaceEnabled:
    def test_responses(self, request, kube_apis, crd_ingress_controller_with_ap, backend_setup, test_namespace):
        """
        Test file-block AppProtect policy with -watch-namespace
        """
        print("------------- Run test for AP policy: file-block --------------")
        print(f"Request URL: {backend_setup.req_url} and Host: {backend_setup.ingress_host}")

        ensure_response_from_backend(backend_setup.req_url, backend_setup.ingress_host, check404=True)

        print("----------------------- Send request ----------------------")
        resp = requests.get(
            f"{backend_setup.req_url}/test.bat", headers={"host": backend_setup.ingress_host}, verify=False
        )

        print(resp.text)

        assert valid_resp_body in resp.text
        assert resp.status_code == 200

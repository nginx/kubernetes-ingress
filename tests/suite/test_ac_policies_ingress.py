import pytest
import requests
from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import apply_and_wait_for_valid_policy, create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    get_first_pod_name,
    get_reload_count,
    get_test_file_name,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_for_reload,
    wait_until_all_pods_are_ready,
    write_to_json,
)
from suite.utils.yaml_utils import (
    get_first_ingress_host_from_yaml,
    get_name_from_yaml,
)

std_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"
test_cm_src = f"{TEST_DATA}/access-control/configmap/nginx-config.yaml"

deny_pol_src = f"{TEST_DATA}/access-control/policies/access-control-policy-deny.yaml"
allow_pol_src = f"{TEST_DATA}/access-control/policies/access-control-policy-allow.yaml"
invalid_pol_src = f"{TEST_DATA}/access-control/policies/access-control-policy-invalid.yaml"

reload_times = {}


class IngressSetup:
    """Encapsulate Ingress example details.

    Attributes:
        public_endpoint: PublicEndpoint
        ingress_src_file:
        ingress_name:
        ingress_pod_name:
        ingress_host:
        namespace: example namespace
    """

    def __init__(
        self,
        public_endpoint: PublicEndpoint,
        ingress_src_file,
        ingress_name,
        ingress_host,
        ingress_pod_name,
        namespace,
        request_url,
    ):
        self.public_endpoint = public_endpoint
        self.ingress_name = ingress_name
        self.ingress_pod_name = ingress_pod_name
        self.namespace = namespace
        self.ingress_host = ingress_host
        self.ingress_src_file = ingress_src_file
        self.request_url = request_url
        self.metrics_url = f"http://{public_endpoint.public_ip}:{public_endpoint.metrics_port}/metrics"


@pytest.fixture(scope="function")
def policy_setup(request, kube_apis, test_namespace) -> None:
    """
    Create policy from yaml file.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param test_namespace: example namespace
    """
    pol_path = request.param

    print(f"------------- Create policy --------------")
    pol_name = apply_and_wait_for_valid_policy(kube_apis, test_namespace, pol_path)
    if not pol_name:
        pytest.skip(f"Failed to create policy from {pol_path}")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print(f"------------- Delete policy --------------")
            delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

    request.addfinalizer(fin)


@pytest.fixture(scope="function")
def invalid_policy_setup(request, kube_apis, test_namespace) -> None:
    """
    Create an invalid policy from yaml file.
    Does not wait for Valid state since the policy is expected to be rejected.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param test_namespace: example namespace
    """
    pol_path = request.param

    print(f"------------- Create invalid policy --------------")
    pol_name = create_policy_from_yaml(kube_apis.custom_objects, pol_path, test_namespace)
    wait_before_test(2)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print(f"------------- Delete invalid policy --------------")
            delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

    request.addfinalizer(fin)


@pytest.fixture(scope="function")
def ingress_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    test_namespace,
) -> IngressSetup:
    print("------------------------- Deploy backend app first -----------------------------------")
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    print("------------------------- Deploy Ingress with AccessControl policy -----------------------------------")
    src = f"{TEST_DATA}/access-control/ingress/{request.param}/annotations-ac-ingress.yaml"
    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
    count_before = get_reload_count(metrics_url)
    create_items_from_yaml(kube_apis, src, test_namespace)
    ingress_name = get_name_from_yaml(src)
    ingress_host = get_first_ingress_host_from_yaml(src)
    request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

    print("------------------------- Wait for reload after ingress apply -----------------------------------")
    wait_for_reload(metrics_url, count_before)

    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port, ingress_controller_endpoint.port_ssl
    )
    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(kube_apis, src, test_namespace)

    request.addfinalizer(fin)

    return IngressSetup(
        ingress_controller_endpoint,
        src,
        ingress_name,
        ingress_host,
        ic_pod_name,
        test_namespace,
        request_url,
    )


@pytest.fixture(scope="class")
def config_setup(request, kube_apis, ingress_controller_prerequisites) -> None:
    """
    Replace configmap to add "set-real-ip-from"
    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_prerequisites: IC pre-requisites
    """
    print(f"------------- Replace ConfigMap --------------")
    replace_configmap_from_yaml(
        kube_apis.v1,
        ingress_controller_prerequisites.config_map["metadata"]["name"],
        ingress_controller_prerequisites.namespace,
        test_cm_src,
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print(f"------------- Restore ConfigMap --------------")
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                std_cm_src,
            )
            write_to_json(f"reload-{get_test_file_name(request.node.fspath)}.json", reload_times)

    request.addfinalizer(fin)


@pytest.mark.policies
@pytest.mark.policies_ac
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
class TestAccessControlPoliciesIngress:

    @pytest.mark.parametrize("ingress_setup", ["standard", "mergeable", "minion-deny"], indirect=True)
    @pytest.mark.parametrize("policy_setup", [deny_pol_src], indirect=True)
    @pytest.mark.smoke
    def test_deny_policy(
        self,
        request,
        kube_apis,
        crd_ingress_controller,
        config_setup,
        policy_setup,
        ingress_setup,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test if ip (10.0.0.1) block-listing is working:
        - denied IP  -> 403
        - other IP   -> 200
        """
        print(f"\nUse IP listed in deny block: 10.0.0.1")
        resp1 = requests.get(
            ingress_setup.request_url,
            headers={"host": ingress_setup.ingress_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp1.status_code}\n{resp1.text}")

        print(f"\nUse IP not listed in deny block: 10.0.0.2")
        resp2 = requests.get(
            ingress_setup.request_url,
            headers={"host": ingress_setup.ingress_host, "X-Real-IP": "10.0.0.2"},
        )
        print(f"Response: {resp2.status_code}\n{resp2.text}")

        assert resp1.status_code == 403, f"Expected 403 for denied IP, got {resp1.status_code}"
        assert resp2.status_code == 200, f"Expected 200 for non-denied IP, got {resp2.status_code}"

    @pytest.mark.parametrize("ingress_setup", ["standard-allow", "mergeable-allow", "minion-allow"], indirect=True)
    @pytest.mark.parametrize("policy_setup", [allow_pol_src], indirect=True)
    @pytest.mark.smoke
    def test_allow_policy(
        self,
        request,
        kube_apis,
        crd_ingress_controller,
        config_setup,
        policy_setup,
        ingress_setup,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test if ip (10.0.0.1) allow-listing is working:
        - allowed IP -> 200
        - other IP   -> 403
        """
        print(f"\nUse IP listed in allow block: 10.0.0.1")
        resp1 = requests.get(
            ingress_setup.request_url,
            headers={"host": ingress_setup.ingress_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp1.status_code}\n{resp1.text}")

        print(f"\nUse IP not listed in allow block: 10.0.0.2")
        resp2 = requests.get(
            ingress_setup.request_url,
            headers={"host": ingress_setup.ingress_host, "X-Real-IP": "10.0.0.2"},
        )
        print(f"Response: {resp2.status_code}\n{resp2.text}")

        assert resp1.status_code == 200, f"Expected 200 for allowed IP, got {resp1.status_code}"
        assert resp2.status_code == 403, f"Expected 403 for non-allowed IP, got {resp2.status_code}"

    @pytest.mark.parametrize(
        "ingress_setup", ["standard-invalid", "mergeable-invalid", "minion-invalid"], indirect=True
    )
    @pytest.mark.parametrize("invalid_policy_setup", [invalid_pol_src], indirect=True)
    def test_invalid_policy(
        self,
        request,
        kube_apis,
        crd_ingress_controller,
        config_setup,
        invalid_policy_setup,
        ingress_setup,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test if invalid policy is applied then response is not affected (200) and policy status is Rejected/Invalid.
        """
        print(f"\nSend request with invalid policy applied")
        resp = requests.get(
            ingress_setup.request_url,
            headers={"host": ingress_setup.ingress_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")

        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", "invalid-policy")
        print(f"Policy status: {policy_info.get('status', {})}")

        assert resp.status_code == 200, f"Expected 200 for invalid policy, got {resp.status_code}"
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "Rejected"
            and policy_info["status"]["state"] == "Invalid"
        ), f"Expected policy to be Rejected/Invalid, got {policy_info.get('status', {})}"

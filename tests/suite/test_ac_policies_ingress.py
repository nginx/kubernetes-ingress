import pytest
import requests
from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy, apply_and_wait_for_valid_policy
from suite.utils.resources_utils import (
    ensure_response_from_backend,
    get_last_reload_time,
    get_test_file_name,
    replace_configmap_from_yaml,
    wait_before_test,
    write_to_json,
    create_items_from_yaml,
    create_example_app,
    wait_until_all_pods_are_ready,
    ensure_connection_to_public_endpoint,
    get_first_pod_name,
    delete_common_app,
    delete_items_from_yaml,
    get_ingress_nginx_template_conf
)
from suite.utils.yaml_utils import (
    get_name_from_yaml,
    get_first_ingress_host_from_yaml,
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


@pytest.fixture(scope="class")
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

@pytest.fixture(scope="class")
def ingress_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    test_namespace,
) -> IngressSetup:
    print("------------------------- Deploy Ingress with AccessControl policy -----------------------------------")
    src = f"{TEST_DATA}/access-control/ingress/{request.param}/annotations-ac-ingress.yaml"
    create_items_from_yaml(kube_apis, src, test_namespace)
    ingress_name = get_name_from_yaml(src)
    ingress_host = get_first_ingress_host_from_yaml(src)
    request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

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
@pytest.mark.parametrize("crd_ingress_controller, ingress_setup", 
[
    (
        {
            "type": "complete",
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-leader-election=false",
            ],
        },
        "standard",
    ),
    (
        {
            "type": "complete",
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-leader-election=false",
            ],
        },
        "mergeable",
    )
], 
indirect=True
)
class TestAccessControlPoliciesIngress:
    def restore_default_ingress(self, kube_apis, virtual_server_setup) -> None:
        """
        Restore VirtualServer without policy spec
        """
        # delete_virtual_server(kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace)
        # create_virtual_server_from_yaml(kube_apis.custom_objects, std_vs_src, virtual_server_setup.namespace)
        wait_before_test()

    #  (self, kube_apis, annotations_setup, ingress_controller_prerequisites, test_namespace)
    @pytest.mark.parametrize("policy_setup", [deny_pol_src], indirect=True)
    @pytest.mark.smoke
    def test_deny_policy(
        self,
        request,
        kube_apis,
        crd_ingress_controller,
        policy_setup,
        ingress_setup,
        ingress_controller_prerequisites,
        test_namespace,
        config_setup,
    ):
        """
        Test if ip (10.0.0.1) block-listing is working: default(no policy) -> deny
        """
        for i in range(60):
            print(f"Wait, attempt {i+1}")
            wait_before_test(1)

        resp = requests.get(
            ingress_setup.request_url,
            headers={"host": ingress_setup.ingress_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"URL: {ingress_setup.request_url}")
        print(f"Host header: {ingress_setup.ingress_host}")
        print(f"Response: {resp.status_code}\n{resp.text}")
        print(f"Timestamp: {resp.headers.get('Date')}")

        get_ingress_nginx_template_conf(
            kube_apis.v1,
            ingress_setup.namespace,
            ingress_setup.ingress_name,
            ingress_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert resp.status_code == 403

        # policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        # print(f"\nUse IP listed in deny block: 10.0.0.1")
        # resp1 = requests.get(
        #     virtual_server_setup.backend_1_url,
        #     headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        # )
        # print(f"Response: {resp1.status_code}\n{resp1.text}")
        # print(f"\nUse IP not listed in deny block: 10.0.0.2")
        # resp2 = requests.get(
        #     virtual_server_setup.backend_1_url,
        #     headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.2"},
        # )
        # print(f"Response: {resp2.status_code}\n{resp2.text}")

        # reload_ms = get_last_reload_time(virtual_server_setup.metrics_url, "nginx")
        # print(f"last reload duration: {reload_ms} ms")
        # reload_times[f"{request.node.name}"] = f"last reload duration: {reload_ms} ms"

        # delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        # self.restore_default_vs(kube_apis, virtual_server_setup)

        # assert (
        #     policy_info["status"]
        #     and policy_info["status"]["reason"] == "AddedOrUpdated"
        #     and policy_info["status"]["state"] == "Valid"
        # )

        # assert (
        #     resp1.status_code == 403
        #     and "403 Forbidden" in resp1.text
        #     and resp2.status_code == 200
        #     and "Server address:" in resp2.text
        # )

    # @pytest.mark.parametrize("src", [allow_vs_src, allow_vs_src_route])
    # @pytest.mark.smoke
    # def test_allow_policy(
    #     self,
    #     kube_apis,
    #     crd_ingress_controller,
    #     virtual_server_setup,
    #     test_namespace,
    #     config_setup,
    #     src,
    # ):
    #     """
    #     Test if ip (10.0.0.1) allow-listing is working: default(no policy) -> allow
    #     """
    #     ensure_response_from_backend(
    #         virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
    #     )
    #     resp = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
    #     )
    #     print(f"Response: {resp.status_code}\n{resp.text}")
    #     assert resp.status_code == 200

    #     print(f"Create allow policy")
    #     pol_name = create_policy_from_yaml(kube_apis.custom_objects, allow_pol_src, test_namespace)
    #     patch_virtual_server_from_yaml(
    #         kube_apis.custom_objects,
    #         virtual_server_setup.vs_name,
    #         src,
    #         virtual_server_setup.namespace,
    #     )
    #     wait_before_test()

    #     policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
    #     print(f"\nUse IP listed in allow block: 10.0.0.1")
    #     resp1 = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
    #     )
    #     print(f"\nUse IP listed not in allow block: 10.0.0.2")
    #     print(f"Response: {resp1.status_code}\n{resp1.text}")
    #     resp2 = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.2"},
    #     )
    #     print(f"Response: {resp2.status_code}\n{resp2.text}")

    #     delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
    #     self.restore_default_vs(kube_apis, virtual_server_setup)

    #     assert (
    #         policy_info["status"]
    #         and policy_info["status"]["reason"] == "AddedOrUpdated"
    #         and policy_info["status"]["state"] == "Valid"
    #     )

    #     assert (
    #         resp1.status_code == 200
    #         and "Server address:" in resp1.text
    #         and resp2.status_code == 403
    #         and "403 Forbidden" in resp2.text
    #     )

    # @pytest.mark.parametrize("src", [override_vs_src, override_vs_src_route])
    # def test_override_policy(
    #     self,
    #     kube_apis,
    #     crd_ingress_controller,
    #     virtual_server_setup,
    #     test_namespace,
    #     config_setup,
    #     src,
    # ):
    #     """
    #     Test if ip allow-listing overrides block-listing: default(no policy) -> deny and allow
    #     """
    #     ensure_response_from_backend(
    #         virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
    #     )
    #     resp = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
    #     )
    #     print(f"Response: {resp.status_code}\n{resp.text}")
    #     assert resp.status_code == 200

    #     print(f"Create deny policy")
    #     deny_pol_name = create_policy_from_yaml(kube_apis.custom_objects, deny_pol_src, test_namespace)
    #     print(f"Create allow policy")
    #     allow_pol_name = create_policy_from_yaml(kube_apis.custom_objects, allow_pol_src, test_namespace)
    #     patch_virtual_server_from_yaml(
    #         kube_apis.custom_objects,
    #         virtual_server_setup.vs_name,
    #         src,
    #         virtual_server_setup.namespace,
    #     )
    #     wait_before_test()

    #     print(f"Use IP listed in both deny and allow policies: 10.0.0.1")
    #     resp = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
    #     )
    #     print(f"Response: {resp.status_code}\n{resp.text}")

    #     delete_policy(kube_apis.custom_objects, deny_pol_name, test_namespace)
    #     delete_policy(kube_apis.custom_objects, allow_pol_name, test_namespace)
    #     self.restore_default_vs(kube_apis, virtual_server_setup)

    #     assert resp.status_code == 200 and "Server address:" in resp.text

    # @pytest.mark.parametrize("src", [invalid_vs_src, invalid_vs_src_route])
    # def test_invalid_policy(
    #     self,
    #     kube_apis,
    #     crd_ingress_controller,
    #     virtual_server_setup,
    #     test_namespace,
    #     config_setup,
    #     src,
    # ):
    #     """
    #     Test if invalid policy is applied then response is 500
    #     """
    #     ensure_response_from_backend(
    #         virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
    #     )
    #     resp = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
    #     )
    #     print(f"Response: {resp.status_code}\n{resp.text}")
    #     assert resp.status_code == 200

    #     print(f"Create invalid policy")
    #     invalid_pol_name = create_policy_from_yaml(kube_apis.custom_objects, invalid_pol_src, test_namespace)
    #     patch_virtual_server_from_yaml(
    #         kube_apis.custom_objects,
    #         virtual_server_setup.vs_name,
    #         src,
    #         virtual_server_setup.namespace,
    #     )

    #     wait_before_test()
    #     resp = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
    #     )
    #     print(f"Response: {resp.status_code}\n{resp.text}")

    #     vs_info = read_custom_resource(
    #         kube_apis.custom_objects,
    #         virtual_server_setup.namespace,
    #         "virtualservers",
    #         virtual_server_setup.vs_name,
    #     )
    #     policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", invalid_pol_name)
    #     delete_policy(kube_apis.custom_objects, invalid_pol_name, test_namespace)
    #     self.restore_default_vs(kube_apis, virtual_server_setup)

    #     assert resp.status_code == 500 and "500 Internal Server Error" in resp.text
    #     assert (
    #         policy_info["status"]
    #         and policy_info["status"]["reason"] == "Rejected"
    #         and policy_info["status"]["state"] == "Invalid"
    #     )
    #     assert vs_info["status"]["state"] == "Warning" and vs_info["status"]["reason"] == "AddedOrUpdatedWithWarning"

    # @pytest.mark.parametrize("src", [deny_vs_src, deny_vs_src_route])
    # def test_deleted_policy(
    #     self,
    #     kube_apis,
    #     crd_ingress_controller,
    #     virtual_server_setup,
    #     test_namespace,
    #     config_setup,
    #     src,
    # ):
    #     """
    #     Test if valid policy is deleted then response is 500
    #     """
    #     ensure_response_from_backend(
    #         virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
    #     )
    #     resp = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
    #     )
    #     print(f"Response: {resp.status_code}\n{resp.text}")
    #     assert resp.status_code == 200

    #     print(f"Create deny policy")
    #     pol_name = create_policy_from_yaml(kube_apis.custom_objects, deny_pol_src, test_namespace)
    #     patch_virtual_server_from_yaml(
    #         kube_apis.custom_objects,
    #         virtual_server_setup.vs_name,
    #         src,
    #         virtual_server_setup.namespace,
    #     )

    #     wait_before_test()
    #     vs_info = read_custom_resource(
    #         kube_apis.custom_objects,
    #         virtual_server_setup.namespace,
    #         "virtualservers",
    #         virtual_server_setup.vs_name,
    #     )
    #     assert vs_info["status"]["state"] == "Valid"
    #     delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

    #     wait_before_test()
    #     resp = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
    #     )
    #     print(f"Response: {resp.status_code}\n{resp.text}")

    #     vs_info = read_custom_resource(
    #         kube_apis.custom_objects,
    #         virtual_server_setup.namespace,
    #         "virtualservers",
    #         virtual_server_setup.vs_name,
    #     )
    #     self.restore_default_vs(kube_apis, virtual_server_setup)

    #     assert resp.status_code == 500 and "500 Internal Server Error" in resp.text
    #     assert vs_info["status"]["state"] == "Warning" and vs_info["status"]["reason"] == "AddedOrUpdatedWithWarning"

    # def test_route_override_spec(
    #     self,
    #     kube_apis,
    #     crd_ingress_controller,
    #     virtual_server_setup,
    #     test_namespace,
    #     config_setup,
    # ):
    #     """
    #     Test allow policy specified under routes overrides block in spec
    #     """
    #     ensure_response_from_backend(
    #         virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
    #     )
    #     resp = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
    #     )
    #     print(f"Response: {resp.status_code}\n{resp.text}")
    #     assert resp.status_code == 200

    #     print(f"Create deny policy")
    #     deny_pol_name = create_policy_from_yaml(kube_apis.custom_objects, deny_pol_src, test_namespace)
    #     print(f"Create allow policy")
    #     allow_pol_name = create_policy_from_yaml(kube_apis.custom_objects, allow_pol_src, test_namespace)

    #     patch_virtual_server_from_yaml(
    #         kube_apis.custom_objects,
    #         virtual_server_setup.vs_name,
    #         override_vs_spec_route_src,
    #         virtual_server_setup.namespace,
    #     )
    #     wait_before_test()

    #     print(f"Use IP listed in both deny and allow policies: 10.0.0.1")
    #     resp = requests.get(
    #         virtual_server_setup.backend_1_url,
    #         headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
    #     )
    #     print(f"Response: {resp.status_code}\n{resp.text}")

    #     self.restore_default_vs(kube_apis, virtual_server_setup)
    #     delete_policy(kube_apis.custom_objects, deny_pol_name, test_namespace)
    #     delete_policy(kube_apis.custom_objects, allow_pol_name, test_namespace)

    #     assert resp.status_code == 200 and "Server address:" in resp.text

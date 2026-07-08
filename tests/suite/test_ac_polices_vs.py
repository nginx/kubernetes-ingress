import pytest
import requests
from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import (
    ensure_response_from_backend,
    get_last_reload_time,
    get_test_file_name,
    replace_configmap_from_yaml,
    wait_before_test,
    write_to_json,
)
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
    patch_virtual_server_from_yaml,
)

std_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"
test_cm_src = f"{TEST_DATA}/access-control/configmap/nginx-config.yaml"
std_vs_src = f"{TEST_DATA}/access-control/standard/virtual-server.yaml"
deny_pol_src = f"{TEST_DATA}/access-control/policies/access-control-policy-deny.yaml"
deny_vs_src = f"{TEST_DATA}/access-control/spec/virtual-server-deny.yaml"
allow_pol_src = f"{TEST_DATA}/access-control/policies/access-control-policy-allow.yaml"
allow_vs_src = f"{TEST_DATA}/access-control/spec/virtual-server-allow.yaml"
override_vs_src = f"{TEST_DATA}/access-control/spec/virtual-server-override.yaml"
invalid_pol_src = f"{TEST_DATA}/access-control/policies/access-control-policy-invalid.yaml"
invalid_vs_src = f"{TEST_DATA}/access-control/spec/virtual-server-invalid.yaml"
allow_vs_src_route = f"{TEST_DATA}/access-control/route-subroute/virtual-server-allow-route.yaml"
deny_vs_src_route = f"{TEST_DATA}/access-control/route-subroute/virtual-server-deny-route.yaml"
invalid_vs_src_route = f"{TEST_DATA}/access-control/route-subroute/virtual-server-invalid-route.yaml"
override_vs_src_route = f"{TEST_DATA}/access-control/route-subroute/virtual-server-override-route.yaml"
override_vs_spec_route_src = f"{TEST_DATA}/access-control/route-subroute/virtual-server-override-spec-route.yaml"
reload_times = {}


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
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                    f"-enable-prometheus-metrics",
                ],
            },
            {
                "example": "access-control",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestAccessControlPoliciesVs:
    def restore_default_vs(self, kube_apis, virtual_server_setup) -> None:
        """
        Restore VirtualServer without policy spec
        """
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace)
        create_virtual_server_from_yaml(kube_apis.custom_objects, std_vs_src, virtual_server_setup.namespace)
        wait_before_test()

    @pytest.mark.parametrize("src", [deny_vs_src, deny_vs_src_route])
    @pytest.mark.smoke
    def test_deny_policy(
        self,
        request,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        config_setup,
        src,
    ):
        """
        Test if ip (10.0.0.1) block-listing is working: default(no policy) -> deny
        """
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
        )
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        assert resp.status_code == 200

        print(f"Create deny policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, deny_pol_src, test_namespace)
        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        print(f"\nUse IP listed in deny block: 10.0.0.1")
        resp1 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp1.status_code}\n{resp1.text}")
        print(f"\nUse IP not listed in deny block: 10.0.0.2")
        resp2 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.2"},
        )
        print(f"Response: {resp2.status_code}\n{resp2.text}")

        reload_ms = get_last_reload_time(virtual_server_setup.metrics_url, "nginx")
        print(f"last reload duration: {reload_ms} ms")
        reload_times[f"{request.node.name}"] = f"last reload duration: {reload_ms} ms"

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )

        assert (
            resp1.status_code == 403
            and "403 Forbidden" in resp1.text
            and resp2.status_code == 200
            and "Server address:" in resp2.text
        )

    @pytest.mark.parametrize("src", [allow_vs_src, allow_vs_src_route])
    @pytest.mark.smoke
    def test_allow_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        config_setup,
        src,
    ):
        """
        Test if ip (10.0.0.1) allow-listing is working: default(no policy) -> allow
        """
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
        )
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        assert resp.status_code == 200

        print(f"Create allow policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, allow_pol_src, test_namespace)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        print(f"\nUse IP listed in allow block: 10.0.0.1")
        resp1 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"\nUse IP listed not in allow block: 10.0.0.2")
        print(f"Response: {resp1.status_code}\n{resp1.text}")
        resp2 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.2"},
        )
        print(f"Response: {resp2.status_code}\n{resp2.text}")

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )

        assert (
            resp1.status_code == 200
            and "Server address:" in resp1.text
            and resp2.status_code == 403
            and "403 Forbidden" in resp2.text
        )

    @pytest.mark.parametrize("src", [override_vs_src, override_vs_src_route])
    def test_override_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        config_setup,
        src,
    ):
        """
        Test if ip allow-listing overrides block-listing: default(no policy) -> deny and allow
        """
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
        )
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        assert resp.status_code == 200

        print(f"Create deny policy")
        deny_pol_name = create_policy_from_yaml(kube_apis.custom_objects, deny_pol_src, test_namespace)
        print(f"Create allow policy")
        allow_pol_name = create_policy_from_yaml(kube_apis.custom_objects, allow_pol_src, test_namespace)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        print(f"Use IP listed in both deny and allow policies: 10.0.0.1")
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")

        delete_policy(kube_apis.custom_objects, deny_pol_name, test_namespace)
        delete_policy(kube_apis.custom_objects, allow_pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

        assert resp.status_code == 200 and "Server address:" in resp.text

    @pytest.mark.parametrize("src", [invalid_vs_src, invalid_vs_src_route])
    def test_invalid_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        config_setup,
        src,
    ):
        """
        Test if invalid policy is applied then response is 500
        """
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
        )
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        assert resp.status_code == 200

        print(f"Create invalid policy")
        invalid_pol_name = create_policy_from_yaml(kube_apis.custom_objects, invalid_pol_src, test_namespace)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )

        wait_before_test()
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")

        vs_info = read_custom_resource(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            "virtualservers",
            virtual_server_setup.vs_name,
        )
        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", invalid_pol_name)
        delete_policy(kube_apis.custom_objects, invalid_pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

        assert resp.status_code == 500 and "500 Internal Server Error" in resp.text
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "Rejected"
            and policy_info["status"]["state"] == "Invalid"
        )
        assert vs_info["status"]["state"] == "Warning" and vs_info["status"]["reason"] == "AddedOrUpdatedWithWarning"

    @pytest.mark.parametrize("src", [deny_vs_src, deny_vs_src_route])
    def test_deleted_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        config_setup,
        src,
    ):
        """
        Test if valid policy is deleted then response is 500
        """
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
        )
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        assert resp.status_code == 200

        print(f"Create deny policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, deny_pol_src, test_namespace)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )

        wait_before_test()
        vs_info = read_custom_resource(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            "virtualservers",
            virtual_server_setup.vs_name,
        )
        assert vs_info["status"]["state"] == "Valid"
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

        wait_before_test()
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")

        vs_info = read_custom_resource(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            "virtualservers",
            virtual_server_setup.vs_name,
        )
        self.restore_default_vs(kube_apis, virtual_server_setup)

        assert resp.status_code == 500 and "500 Internal Server Error" in resp.text
        assert vs_info["status"]["state"] == "Warning" and vs_info["status"]["reason"] == "AddedOrUpdatedWithWarning"

    def test_route_override_spec(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        config_setup,
    ):
        """
        Test allow policy specified under routes overrides block in spec
        """
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"X-Real-IP": "10.0.0.1"}
        )
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        assert resp.status_code == 200

        print(f"Create deny policy")
        deny_pol_name = create_policy_from_yaml(kube_apis.custom_objects, deny_pol_src, test_namespace)
        print(f"Create allow policy")
        allow_pol_name = create_policy_from_yaml(kube_apis.custom_objects, allow_pol_src, test_namespace)

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            override_vs_spec_route_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        print(f"Use IP listed in both deny and allow policies: 10.0.0.1")
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")

        self.restore_default_vs(kube_apis, virtual_server_setup)
        delete_policy(kube_apis.custom_objects, deny_pol_name, test_namespace)
        delete_policy(kube_apis.custom_objects, allow_pol_name, test_namespace)

        assert resp.status_code == 200 and "Server address:" in resp.text

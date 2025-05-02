import pytest
import requests
from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import ensure_response_from_backend, replace_configmap_from_yaml, wait_before_test
from suite.utils.vs_vsr_resources_utils import patch_v_s_route_from_yaml, patch_virtual_server_from_yaml

std_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"
test_cm_src = f"{TEST_DATA}/access-control/configmap/nginx-config.yaml"
std_vs_src = f"{TEST_DATA}/virtual-server-route/standard/virtual-server.yaml"
deny_pol_src = f"{TEST_DATA}/access-control/policies/access-control-policy-deny.yaml"
allow_pol_src = f"{TEST_DATA}/access-control/policies/access-control-policy-allow.yaml"
invalid_pol_src = f"{TEST_DATA}/access-control/policies/access-control-policy-invalid.yaml"
deny_vsr_src = f"{TEST_DATA}/access-control/route-subroute/virtual-server-route-deny-subroute.yaml"
allow_vsr_src = f"{TEST_DATA}/access-control/route-subroute/virtual-server-route-allow-subroute.yaml"
override_vsr_src = f"{TEST_DATA}/access-control/route-subroute/virtual-server-route-override-subroute.yaml"
invalid_vsr_src = f"{TEST_DATA}/access-control/route-subroute/virtual-server-route-invalid-subroute.yaml"
vs_spec_vsr_override_src = f"{TEST_DATA}/access-control/route-subroute/virtual-server-vsr-spec-override.yaml"
vs_route_vsr_override_src = f"{TEST_DATA}/access-control/route-subroute/virtual-server-vsr-route-override.yaml"


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

    request.addfinalizer(fin)


@pytest.mark.policies
@pytest.mark.policies_ac
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [f"-enable-custom-resources", f"-enable-leader-election=false"],
            },
            {"example": "virtual-server-route"},
        )
    ],
    indirect=True,
)
class TestAccessControlPoliciesVsr:
    def restore_default_vsr(self, kube_apis, v_s_route_setup) -> None:
        """
        Function to revert vsr deployments to valid state
        """
        patch_src_m = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            patch_src_m,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

    @pytest.mark.flaky(max_runs=3)
    def test_deny_policy_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        test_namespace,
        config_setup,
        v_s_route_setup,
    ):
        """
        Test if ip (10.0.0.1) block-listing is working (policy specified in vsr subroute): default(no policy) -> deny
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers={"X-Real-IP": "10.0.0.1"},
            check404=True,
        )
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        assert resp.status_code == 200

        print(f"Create deny policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, deny_pol_src, v_s_route_setup.route_m.namespace)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            deny_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers={"X-Real-IP": "10.0.0.1"},
            check404=True,
        )
        policy_info = read_custom_resource(
            kube_apis.custom_objects, v_s_route_setup.route_m.namespace, "policies", pol_name
        )

        print(f"\nUse IP listed in deny block: 10.0.0.1")
        resp1 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp1.status_code}\n{resp1.text}")
        print(f"\nUse IP not listed in deny block: 10.0.0.2")
        resp2 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.2"},
        )
        print(f"Response: {resp2.status_code}\n{resp2.text}")

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
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

    def test_allow_policy_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        test_namespace,
        config_setup,
        v_s_route_setup,
    ):
        """
        Test if ip (10.0.0.1) block-listing is working (policy specified in vsr subroute): default(no policy) -> deny
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        assert resp.status_code == 200

        print(f"Create allow policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, allow_pol_src, v_s_route_setup.route_m.namespace)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            allow_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        policy_info = read_custom_resource(
            kube_apis.custom_objects, v_s_route_setup.route_m.namespace, "policies", pol_name
        )

        print(f"\nUse IP listed in deny block: 10.0.0.1")
        resp1 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp1.status_code}\n{resp1.text}")
        print(f"\nUse IP not listed in deny block: 10.0.0.2")
        resp2 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.2"},
        )
        print(f"Response: {resp2.status_code}\n{resp2.text}")

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert (
            resp2.status_code == 403
            and "403 Forbidden" in resp2.text
            and resp1.status_code == 200
            and "Server address:" in resp1.text
        )

    def test_override_policy_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        test_namespace,
        config_setup,
        v_s_route_setup,
    ):
        """
        Test if ip (10.0.0.1) allow-listing overrides block-listing (policy specified in vsr subroute)
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        assert resp.status_code == 200

        print(f"Create deny policy")
        deny_pol_name = create_policy_from_yaml(
            kube_apis.custom_objects, deny_pol_src, v_s_route_setup.route_m.namespace
        )
        print(f"Create allow policy")
        allow_pol_name = create_policy_from_yaml(
            kube_apis.custom_objects, allow_pol_src, v_s_route_setup.route_m.namespace
        )
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            override_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        print(f"\nUse IP listed in deny block: 10.0.0.1")
        resp1 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp1.status_code}\n{resp1.text}")
        print(f"\nUse IP not listed in deny block: 10.0.0.2")
        resp2 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.2"},
        )
        print(f"Response: {resp2.status_code}\n{resp2.text}")

        delete_policy(kube_apis.custom_objects, deny_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, allow_pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        assert (
            resp2.status_code == 403
            and "403 Forbidden" in resp2.text
            and resp1.status_code == 200
            and "Server address:" in resp1.text
        )

    def test_invalid_policy_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        test_namespace,
        config_setup,
        v_s_route_setup,
    ):
        """
        Test if applying invalid-policy results in 500.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        assert resp.status_code == 200

        print(f"Create invalid policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, invalid_pol_src, v_s_route_setup.route_m.namespace)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            invalid_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        policy_info = read_custom_resource(
            kube_apis.custom_objects, v_s_route_setup.route_m.namespace, "policies", pol_name
        )

        print(f"\nUse IP listed in deny block: 10.0.0.1")
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")
        vsr_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "Rejected"
            and policy_info["status"]["state"] == "Invalid"
        )
        assert resp.status_code == 500 and "500 Internal Server Error" in resp.text
        assert vsr_info["status"]["state"] == "Warning" and vsr_info["status"]["reason"] == "AddedOrUpdatedWithWarning"

    @pytest.mark.parametrize("src", [vs_spec_vsr_override_src, vs_route_vsr_override_src])
    def test_override_vs_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        test_namespace,
        config_setup,
        v_s_route_setup,
        src,
    ):
        """
        Test if vsr subroute policy overrides vs spec policy and vsr subroute policy overrides vs route policy
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"

        print(f"Create deny policy")
        deny_pol_name = create_policy_from_yaml(
            kube_apis.custom_objects, deny_pol_src, v_s_route_setup.route_m.namespace
        )
        print(f"Create allow policy")
        allow_pol_name = create_policy_from_yaml(
            kube_apis.custom_objects, allow_pol_src, v_s_route_setup.route_m.namespace
        )

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            allow_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        # patch vs with blocking policy
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, src, v_s_route_setup.namespace
        )
        wait_before_test()

        print(f"\nUse IP listed in deny block: 10.0.0.1")
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "X-Real-IP": "10.0.0.1"},
        )
        print(f"Response: {resp.status_code}\n{resp.text}")

        delete_policy(kube_apis.custom_objects, deny_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, allow_pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, std_vs_src, v_s_route_setup.namespace
        )
        wait_before_test()
        assert resp.status_code == 200 and "Server address:" in resp.text

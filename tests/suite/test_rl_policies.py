import time

import jwt
import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import get_pod_list, get_vs_nginx_template_conf, scale_deployment, wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
    patch_virtual_server_from_yaml,
)

std_vs_src = f"{TEST_DATA}/rate-limit/standard/virtual-server.yaml"
rl_pol_pri_src = f"{TEST_DATA}/rate-limit/policies/rate-limit-primary.yaml"
rl_pol_pri_sca_src = f"{TEST_DATA}/rate-limit/policies/rate-limit-primary-scaled.yaml"
rl_vs_pri_src = f"{TEST_DATA}/rate-limit/spec/virtual-server-primary.yaml"
rl_vs_pri_sca_src = f"{TEST_DATA}/rate-limit/spec/virtual-server-primary-scaled.yaml"
rl_pol_sec_src = f"{TEST_DATA}/rate-limit/policies/rate-limit-secondary.yaml"
rl_vs_sec_src = f"{TEST_DATA}/rate-limit/spec/virtual-server-secondary.yaml"
rl_pol_invalid = f"{TEST_DATA}/rate-limit/policies/rate-limit-invalid.yaml"
rl_vs_invalid = f"{TEST_DATA}/rate-limit/spec/virtual-server-invalid.yaml"
rl_vs_override_spec = f"{TEST_DATA}/rate-limit/spec/virtual-server-override.yaml"
rl_vs_override_route = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-override-route.yaml"
rl_vs_override_spec_route = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-override-spec-route.yaml"
rl_vs_jwt_claim_sub = f"{TEST_DATA}/rate-limit/spec/virtual-server-jwt-claim-sub.yaml"
rl_pol_jwt_claim_sub = f"{TEST_DATA}/rate-limit/policies/rate-limit-jwt-claim-sub.yaml"


@pytest.mark.policies
@pytest.mark.policies_rl
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                ],
            },
            {
                "example": "rate-limit",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestRateLimitingPolicies:
    def restore_default_vs(self, kube_apis, virtual_server_setup) -> None:
        """
        Restore VirtualServer without policy spec
        """
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace)
        create_virtual_server_from_yaml(kube_apis.custom_objects, std_vs_src, virtual_server_setup.namespace)
        wait_before_test()

    @pytest.mark.smoke
    @pytest.mark.parametrize("src", [rl_vs_pri_src])
    def test_rl_policy_1rs(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if rate-limiting policy is working with 1 rps
        """
        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_pri_src, test_namespace)
        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )

        wait_before_test()
        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        occur = []
        t_end = time.perf_counter() + 1
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
        )
        print(resp.status_code)
        assert resp.status_code == 200
        while time.perf_counter() < t_end:
            resp = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host},
            )
            occur.append(resp.status_code)
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert occur.count(200) <= 1

    @pytest.mark.parametrize("src", [rl_vs_sec_src])
    def test_rl_policy_5rs(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if rate-limiting policy is working with 5 rps
        """
        rate_sec = 5
        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_sec_src, test_namespace)
        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )

        wait_before_test()
        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        occur = []
        t_end = time.perf_counter() + 1
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
        )
        assert resp.status_code == 200
        while time.perf_counter() < t_end:
            resp = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host},
            )
            occur.append(resp.status_code)
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert rate_sec >= occur.count(200) >= (rate_sec - 2)

    @pytest.mark.parametrize("src", [rl_vs_invalid])
    def test_rl_policy_invalid(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test the status code is 500 if invalid policy is deployed
        """
        print(f"Create rl policy")
        invalid_pol_name = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_invalid, test_namespace)
        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )

        wait_before_test()
        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", invalid_pol_name)
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
        )
        print(resp.text)
        delete_policy(kube_apis.custom_objects, invalid_pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "Rejected"
            and policy_info["status"]["state"] == "Invalid"
        )
        assert resp.status_code == 500

    @pytest.mark.parametrize("src", [rl_vs_pri_src])
    def test_rl_policy_deleted(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test the status code if 500 is valid policy is removed
        """
        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_pri_src, test_namespace)
        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
        )
        assert resp.status_code == 200
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        wait_before_test()
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
        )
        self.restore_default_vs(kube_apis, virtual_server_setup)
        assert resp.status_code == 500

    @pytest.mark.parametrize("src", [rl_vs_override_spec, rl_vs_override_route])
    def test_rl_override(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        List multiple policies in vs and test if the one with less rps is used
        """
        print(f"Create rl policy")
        pol_name_pri = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_pri_src, test_namespace)
        pol_name_sec = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_sec_src, test_namespace)
        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        occur = []
        t_end = time.perf_counter() + 1
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
        )
        assert resp.status_code == 200
        while time.perf_counter() < t_end:
            resp = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host},
            )
            occur.append(resp.status_code)
        delete_policy(kube_apis.custom_objects, pol_name_pri, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_name_sec, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)
        assert occur.count(200) <= 1

    @pytest.mark.parametrize("src", [rl_vs_override_spec_route])
    def test_rl_override_spec_route(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        List policies in vs spec and route resp. and test if route overrides spec
        route:policy = secondary (5 rps)
        spec:policy = primary (1 rps)
        """
        rate_sec = 5
        print(f"Create rl policy")
        pol_name_pri = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_pri_src, test_namespace)
        pol_name_sec = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_sec_src, test_namespace)
        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        occur = []
        t_end = time.perf_counter() + 1
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
        )
        assert resp.status_code == 200
        while time.perf_counter() < t_end:
            resp = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host},
            )
            occur.append(resp.status_code)
        delete_policy(kube_apis.custom_objects, pol_name_pri, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_name_sec, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)
        assert rate_sec >= occur.count(200) >= (rate_sec - 2)

    @pytest.mark.parametrize("src", [rl_vs_pri_sca_src])
    def test_rl_policy_scaled(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if rate-limit scaling is being calculated correctly
        """
        ns = ingress_controller_prerequisites.namespace
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ns, 4)

        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_pri_sca_src, test_namespace)
        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        ic_pods = get_pod_list(kube_apis.v1, ns)
        for i in range(len(ic_pods)):
            conf = get_vs_nginx_template_conf(
                kube_apis.v1,
                virtual_server_setup.namespace,
                virtual_server_setup.vs_name,
                ic_pods[i].metadata.name,
                ingress_controller_prerequisites.namespace,
            )
            assert "rate=10r/s" in conf
        # restore replicas, policy and vs
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ns, 1)
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vs_jwt_claim_sub])
    def test_rl_policy_jwt_claim_sub(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if rate-limiting policy is working with 1 rps using $jwt_claim_sub as the rate limit key
        """
        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_jwt_claim_sub, test_namespace)
        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        jwt_token = jwt.encode(
            {"sub": "client1"},
            "nginx",
            algorithm="HS256",
        )
        occur = []
        t_end = time.perf_counter() + 1

        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {jwt_token}"},
        )
        print(resp.status_code)
        wait_before_test()
        assert resp.status_code == 200
        while time.perf_counter() < t_end:
            resp = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {jwt_token}"},
            )
            occur.append(resp.status_code)
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert occur.count(200) <= 1

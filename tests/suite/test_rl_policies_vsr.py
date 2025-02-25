import time

import jwt
import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import apply_and_assert_valid_policy, create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import get_pod_list, scale_deployment, wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    get_vs_nginx_template_conf,
    patch_v_s_route_from_yaml,
    patch_virtual_server_from_yaml,
)

std_vs_src = f"{TEST_DATA}/virtual-server-route/standard/virtual-server.yaml"
rl_pol_pri_src = f"{TEST_DATA}/rate-limit/policies/rate-limit-primary.yaml"
rl_pol_pri_sca_src = f"{TEST_DATA}/rate-limit/policies/rate-limit-primary-scaled.yaml"
rl_vsr_pri_src = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-pri-subroute.yaml"
rl_vsr_pri_sca_src = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-pri-subroute-scaled.yaml"
rl_pol_sec_src = f"{TEST_DATA}/rate-limit/policies/rate-limit-secondary.yaml"
rl_vsr_sec_src = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-sec-subroute.yaml"
rl_pol_invalid_src = f"{TEST_DATA}/rate-limit/policies/rate-limit-invalid.yaml"
rl_vsr_invalid_src = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-invalid-subroute.yaml"
rl_vsr_override_src = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-override-subroute.yaml"
rl_vsr_override_vs_spec_src = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-vsr-spec-override.yaml"
rl_vsr_override_vs_route_src = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-vsr-route-override.yaml"
rl_vsr_jwt_claim_sub_src = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-jwt-claim-sub.yaml"
rl_pol_jwt_claim_sub_src = f"{TEST_DATA}/rate-limit/policies/rate-limit-jwt-claim-sub.yaml"
rl_vsr_basic_premium_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-tiered-basic-premium-jwt-claim-sub.yaml"
)
rl_vsr_multiple_tiered_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-mutliple-tiered-jwt-claim-sub.yaml"
)
rl_pol_basic_no_default_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-basic-no-default-jwt-claim-sub.yaml"
)
rl_pol_premium_no_default_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-premium-no-default-jwt-claim-sub.yaml"
)
rl_pol_basic_with_default_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-basic-with-default-jwt-claim-sub.yaml"
)
rl_pol_bronze_with_default_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-bronze-with-default-jwt-claim-sub.yaml"
)
rl_pol_silver_no_default_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-silver-no-default-jwt-claim-sub.yaml"
)
rl_pol_gold_no_default_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-gold-no-default-jwt-claim-sub.yaml"
)


@pytest.mark.policies
@pytest.mark.policies_rl
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                ],
            },
            {"example": "virtual-server-route"},
        )
    ],
    indirect=True,
)
class TestRateLimitingPoliciesVsr:
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

    @pytest.mark.smoke
    @pytest.mark.parametrize("src", [rl_vsr_pri_src])
    def test_rl_policy_1rs_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test if rate-limiting policy is working with ~1 rps in vsr:subroute
        """

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_pri_src, v_s_route_setup.route_m.namespace)
        print(f"Patch vsr with policy: {src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            src,
            v_s_route_setup.route_m.namespace,
        )

        wait_before_test()
        policy_info = read_custom_resource(
            kube_apis.custom_objects, v_s_route_setup.route_m.namespace, "policies", pol_name
        )
        occur = []
        t_end = time.perf_counter() + 1
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
        )
        print(resp.status_code)
        assert resp.status_code == 200
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host},
            )
            occur.append(resp.status_code)
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert occur.count(200) <= 1

    @pytest.mark.parametrize("src", [rl_vsr_sec_src])
    def test_rl_policy_5rs_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test if rate-limiting policy is working with ~5 rps in vsr:subroute
        """
        rate_sec = 5
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_sec_src, v_s_route_setup.route_m.namespace)
        print(f"Patch vsr with policy: {src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            src,
            v_s_route_setup.route_m.namespace,
        )

        wait_before_test()
        policy_info = read_custom_resource(
            kube_apis.custom_objects, v_s_route_setup.route_m.namespace, "policies", pol_name
        )
        occur = []
        t_end = time.perf_counter() + 1
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
        )
        print(resp.status_code)
        assert resp.status_code == 200
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host},
            )
            occur.append(resp.status_code)
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert rate_sec >= occur.count(200) >= (rate_sec - 2)

    @pytest.mark.parametrize("src", [rl_vsr_override_src])
    def test_rl_policy_override_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test if rate-limiting policy with lower rps is used when multiple policies are listed in vsr:subroute
        And test if the order of policies in vsr:subroute has no effect
        """

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        print(f"Create rl policy: 1rps")
        pol_name_pri = create_policy_from_yaml(
            kube_apis.custom_objects, rl_pol_pri_src, v_s_route_setup.route_m.namespace
        )
        print(f"Create rl policy: 5rps")
        pol_name_sec = create_policy_from_yaml(
            kube_apis.custom_objects, rl_pol_sec_src, v_s_route_setup.route_m.namespace
        )
        print(f"Patch vsr with policy: {src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        occur = []
        t_end = time.perf_counter() + 1
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
        )
        print(resp.status_code)
        assert resp.status_code == 200
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host},
            )
            occur.append(resp.status_code)
        delete_policy(kube_apis.custom_objects, pol_name_pri, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, pol_name_sec, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        assert occur.count(200) <= 1

    @pytest.mark.parametrize("src", [rl_vsr_pri_src])
    def test_rl_policy_deleted_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test if deleting a policy results in 500
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, rl_pol_pri_src, v_s_route_setup.route_m.namespace)
        print(f"Patch vsr with policy: {src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
        )
        assert resp.status_code == 200
        print(resp.status_code)
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
        )
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        assert resp.status_code == 500

    @pytest.mark.parametrize("src", [rl_vsr_invalid_src])
    def test_rl_policy_invalid_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test if using an invalid policy in vsr:subroute results in 500
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        print(f"Create rl policy")
        invalid_pol_name = create_policy_from_yaml(
            kube_apis.custom_objects, rl_pol_invalid_src, v_s_route_setup.route_m.namespace
        )
        print(f"Patch vsr with policy: {src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            src,
            v_s_route_setup.route_m.namespace,
        )

        wait_before_test()
        policy_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "policies",
            invalid_pol_name,
        )
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
        )
        print(resp.status_code)
        delete_policy(kube_apis.custom_objects, invalid_pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "Rejected"
            and policy_info["status"]["state"] == "Invalid"
        )
        assert resp.status_code == 500

    @pytest.mark.parametrize("src", [rl_vsr_override_vs_spec_src, rl_vsr_override_vs_route_src])
    def test_override_vs_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        test_namespace,
        v_s_route_setup,
        src,
    ):
        """
        Test if vsr subroute policy overrides vs spec policy
        And vsr subroute policy overrides vs route policy
        """
        rate_sec = 5
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"

        # policy for virtualserver
        print(f"Create rl policy: 1rps")
        pol_name_vs = create_policy_from_yaml(
            kube_apis.custom_objects, rl_pol_pri_src, v_s_route_setup.route_m.namespace
        )
        # policy for virtualserverroute
        print(f"Create rl policy: 5rps")
        pol_name_vsr = create_policy_from_yaml(
            kube_apis.custom_objects, rl_pol_sec_src, v_s_route_setup.route_m.namespace
        )

        # patch vsr with 5rps policy
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            rl_vsr_sec_src,
            v_s_route_setup.route_m.namespace,
        )
        # patch vs with 1rps policy
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, src, v_s_route_setup.namespace
        )
        wait_before_test()
        occur = []
        t_end = time.perf_counter() + 1
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
        )
        print(resp.status_code)
        assert resp.status_code == 200
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host},
            )
            occur.append(resp.status_code)

        delete_policy(kube_apis.custom_objects, pol_name_vs, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, pol_name_vsr, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, std_vs_src, v_s_route_setup.namespace
        )
        assert rate_sec >= occur.count(200) >= (rate_sec - 2)

    @pytest.mark.parametrize("src", [rl_vsr_pri_sca_src])
    def test_rl_policy_scaled_vsr(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test if rate-limiting policy is working with ~1 rps in vsr:subroute
        """

        ns = ingress_controller_prerequisites.namespace
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ns, 4)

        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(
            kube_apis.custom_objects, rl_pol_pri_sca_src, v_s_route_setup.route_m.namespace
        )
        print(f"Patch vsr with policy: {src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            src,
            v_s_route_setup.route_m.namespace,
        )

        wait_before_test()
        policy_info = read_custom_resource(
            kube_apis.custom_objects, v_s_route_setup.route_m.namespace, "policies", pol_name
        )

        ic_pods = get_pod_list(kube_apis.v1, ns)
        for i in range(len(ic_pods)):
            conf = get_vs_nginx_template_conf(
                kube_apis.v1,
                v_s_route_setup.route_m.namespace,
                v_s_route_setup.vs_name,
                ic_pods[i].metadata.name,
                ingress_controller_prerequisites.namespace,
            )
            assert "rate=10r/s" in conf
        # restore replicas, policy and vsr
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ns, 1)
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )

    @pytest.mark.smoke
    @pytest.mark.parametrize("src", [rl_vsr_jwt_claim_sub_src])
    def test_rl_policy_jwt_claim_sub_vsr(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test if rate-limiting policy is working with 1 rps using $jwt_claim_sub as the rate limit key in vsr:subroute
        """

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        pol_name = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_jwt_claim_sub_src)

        print(f"Patch vsr with policy: {src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test(1)
        vsr_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        assert (
            vsr_info["status"]
            and vsr_info["status"]["reason"] == "AddedOrUpdated"
            and vsr_info["status"]["state"] == "Valid"
        )

        jwt_token = jwt.encode(
            {"sub": "client1"},
            "nginx",
            algorithm="HS256",
        )

        ##  Test Rate Limit 1r/s
        occur = []
        t_end = time.perf_counter() + 1
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {jwt_token}"},
        )

        print(resp.status_code)
        assert resp.status_code == 200
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {jwt_token}"},
            )
            occur.append(resp.status_code)
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)

        assert occur.count(200) <= 1

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vsr_basic_premium_jwt_claim_sub])
    def test_rl_policy_tiered_basic_premium_no_default_jwt_claim_sub_vsr(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test if basic rate-limiting policy is working with 1 rps using $jwt_claim_sub as the rate limit key,
        if premium rate-limiting policy is working with 5 rps using $jwt_claim_sub as the rate limit key &
        if the default is unlimited when no default policy is applied.
        Policies are applied at the VirtualServerRoute level
        """

        basic_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_basic_no_default_jwt_claim_sub
        )
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_premium_no_default_jwt_claim_sub
        )

        print(f"Patch vsr with policy: {src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test(1)
        vsr_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        assert (
            vsr_info["status"]
            and vsr_info["status"]["reason"] == "AddedOrUpdated"
            and vsr_info["status"]["state"] == "Valid"
        )

        basic_jwt_token = jwt.encode(
            {"user_details": {"level": "Basic"}, "sub": "client1"},
            "nginx",
            algorithm="HS256",
        )
        premium_jwt_token = jwt.encode(
            {"user_details": {"level": "Premium"}, "sub": "client2"},
            "nginx",
            algorithm="HS256",
        )

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"

        ##  Test Basic Rate Limit 1r/s
        basic_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
            )
            basic_occur.append(resp.status_code)
        assert basic_occur.count(200) == 1
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        premium_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
            )
            premium_occur.append(resp.status_code)
        assert premium_occur.count(200) >= 5 and premium_occur.count(200) <= 6  # allow 5 or 6 requests in the results
        wait_before_test(1)

        ##  Test Default Rate Limit unlimited
        default_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host},
            )
            default_occur.append(resp.status_code)
        assert default_occur.count(503) == 0

        delete_policy(kube_apis.custom_objects, basic_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vsr_basic_premium_jwt_claim_sub])
    def test_rl_policy_tiered_basic_premium_with_default_jwt_claim_sub_vsr(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test if basic rate-limiting policy is working with 1 rps using $jwt_claim_sub as the rate limit key,
        if premium rate-limiting policy is working with 5 rps using $jwt_claim_sub as the rate limit key &
        if the default basic rate limit of 1r/s is applied.
        Policies are applied at the VirtualServerRoute level
        """

        basic_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_basic_with_default_jwt_claim_sub
        )
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_premium_no_default_jwt_claim_sub
        )

        print(f"Patch vsr with policy: {src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test(1)
        vsr_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        assert (
            vsr_info["status"]
            and vsr_info["status"]["reason"] == "AddedOrUpdated"
            and vsr_info["status"]["state"] == "Valid"
        )

        basic_jwt_token = jwt.encode(
            {"user_details": {"level": "Basic"}, "sub": "client1"},
            "nginx",
            algorithm="HS256",
        )
        premium_jwt_token = jwt.encode(
            {"user_details": {"level": "Premium"}, "sub": "client2"},
            "nginx",
            algorithm="HS256",
        )

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"

        ##  Test Basic Rate Limit 1r/s
        basic_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
            )
            basic_occur.append(resp.status_code)
        assert basic_occur.count(200) == 1
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        premium_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
            )
            premium_occur.append(resp.status_code)
        assert premium_occur.count(200) >= 5 and premium_occur.count(200) <= 6  # allow 5 or 6 requests in the results
        wait_before_test(1)

        ##  Test Default Rate Limit 1r/s
        default_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host},
            )
            default_occur.append(resp.status_code)
        assert default_occur.count(200) == 1

        delete_policy(kube_apis.custom_objects, basic_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vsr_multiple_tiered_jwt_claim_sub])
    def test_rl_policy_multiple_tiered_jwt_claim_sub_vsr(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test applying a basic/premium tier to /backend1 &,
        applying a bronze/silver/gold tier to /backend3.
        Policies are applied at the VirtualServerRoute level
        """

        basic_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_basic_with_default_jwt_claim_sub
        )
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_premium_no_default_jwt_claim_sub
        )
        bronze_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_bronze_with_default_jwt_claim_sub
        )
        silver_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_silver_no_default_jwt_claim_sub
        )
        gold_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_gold_no_default_jwt_claim_sub
        )

        print(f"Patch vsr with policy: {src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test(1)
        vsr_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        assert (
            vsr_info["status"]
            and vsr_info["status"]["reason"] == "AddedOrUpdated"
            and vsr_info["status"]["state"] == "Valid"
        )

        basic_jwt_token = jwt.encode(
            {"user_details": {"level": "Basic"}, "sub": "client1"},
            "nginx",
            algorithm="HS256",
        )
        premium_jwt_token = jwt.encode(
            {"user_details": {"level": "Premium"}, "sub": "client2"},
            "nginx",
            algorithm="HS256",
        )
        bronze_jwt_token = jwt.encode(
            {"user_details": {"tier": "Bronze"}, "sub": "client1"},
            "nginx",
            algorithm="HS256",
        )
        silver_jwt_token = jwt.encode(
            {"user_details": {"tier": "Silver"}, "sub": "client2"},
            "nginx",
            algorithm="HS256",
        )
        gold_jwt_token = jwt.encode(
            {"user_details": {"tier": "Gold"}, "sub": "client3"},
            "nginx",
            algorithm="HS256",
        )

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"

        ##  Test Basic Rate Limit 1r/s
        basic_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
            )
            basic_occur.append(resp.status_code)
        assert basic_occur.count(200) == 1
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        premium_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
            )
            premium_occur.append(resp.status_code)
        assert premium_occur.count(200) >= 5 and premium_occur.count(200) <= 6  # allow 5 or 6 requests in the results
        wait_before_test(1)

        ##  Test Basic Default Rate Limit 1r/s
        basic_default_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host},
            )
            basic_default_occur.append(resp.status_code)
        assert basic_default_occur.count(200) == 1
        wait_before_test(1)

        ##  Test Bronze Rate Limit 5r/s
        bronze_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[1]}",
                headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {bronze_jwt_token}"},
            )
            bronze_occur.append(resp.status_code)
        assert bronze_occur.count(200) == 5
        wait_before_test(1)

        ##  Test Silver Rate Limit 10r/s
        silver_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[1]}",
                headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {silver_jwt_token}"},
            )
            silver_occur.append(resp.status_code)
        assert silver_occur.count(200) == 10
        wait_before_test(1)

        ##  Test Gold Rate Limit 15r/s
        gold_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[1]}",
                headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {gold_jwt_token}"},
            )
            gold_occur.append(resp.status_code)
        assert gold_occur.count(200) == 15
        wait_before_test(1)

        ##  Test Bronze Default Rate Limit 5r/s
        bronze_default_occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                f"{req_url}{v_s_route_setup.route_m.paths[1]}",
                headers={"host": v_s_route_setup.vs_host},
            )
            bronze_default_occur.append(resp.status_code)
        assert bronze_default_occur.count(200) == 5

        delete_policy(kube_apis.custom_objects, basic_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, bronze_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, silver_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, gold_pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)

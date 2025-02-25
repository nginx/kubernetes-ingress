import time

import jwt
import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import apply_and_assert_valid_policy, create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import get_pod_list, scale_deployment, wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    apply_and_assert_valid_vs,
    apply_and_assert_valid_vsr,
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

    def check_rate_limit(self, url, code, counter, headers={}):
        occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                url,
                headers=headers,
            )
            occur.append(resp.status_code)
        assert occur.count(code) == counter

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
        pol_name = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_pri_src)

        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
        )

        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host},
        )

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)

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
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        pol_name = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_sec_src)

        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
        )

        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host},
        )

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)

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
        pol_name_pri = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_pri_src)
        pol_name_sec = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_sec_src)

        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
        )

        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host},
        )

        delete_policy(kube_apis.custom_objects, pol_name_pri, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, pol_name_sec, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)

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
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"

        # policy for virtualserver
        pol_name_pri = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_pri_src)
        pol_name_sec = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_sec_src)

        # patch vsr with 5rps policy
        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            rl_vsr_sec_src,
        )

        # patch vs with 1rps policy
        apply_and_assert_valid_vs(
            kube_apis,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            src,
        )

        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host},
        )
        delete_policy(kube_apis.custom_objects, pol_name_pri, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, pol_name_sec, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, std_vs_src, v_s_route_setup.namespace
        )

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

        pol_name = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_pri_sca_src)

        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
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
        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
        )

        jwt_token = jwt.encode(
            {"sub": "client1"},
            "nginx",
            algorithm="HS256",
        )

        ##  Test Rate Limit 1r/s
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {jwt_token}"},
        )

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)

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

        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
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

        ##  Test Basic Rate Limit 1r/s+
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Default Rate Limit unlimited
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            503,
            0,
            headers={"host": v_s_route_setup.vs_host},
        )

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

        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
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
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Default Rate Limit 1r/s
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host},
        )

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

        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
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
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Basic Default Rate Limit 1r/s
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host},
        )
        wait_before_test(1)

        ##  Test Bronze Rate Limit 5r/s
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {bronze_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Silver Rate Limit 10r/s
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            10,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {silver_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Gold Rate Limit 15r/s
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            15,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {gold_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Bronze Default Rate Limit 5r/s
        self.check_rate_limit(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host},
        )

        delete_policy(kube_apis.custom_objects, basic_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, bronze_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, silver_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, gold_pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)

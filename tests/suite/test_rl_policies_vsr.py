import time

import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import apply_and_assert_valid_policy, delete_policy
from suite.utils.resources_utils import wait_before_test, wait_for_event
from suite.utils.vs_vsr_resources_utils import (
    apply_and_assert_warning_vsr,
    patch_v_s_route_from_yaml,
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
rl_vsr_override_tiered_basic_premium_vs_spec_src = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-vsr-tiered-basic-premium-spec-override.yaml"
)
rl_vsr_override_tiered_basic_premium_vs_route_src = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-vsr-tiered-basic-premium-route-override.yaml"
)
rl_vsr_jwt_claim_sub_src = f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-jwt-claim-sub.yaml"
rl_pol_jwt_claim_sub_src = f"{TEST_DATA}/rate-limit/policies/rate-limit-jwt-claim-sub.yaml"
rl_vsr_basic_premium_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-tiered-basic-premium-jwt-claim-sub.yaml"
)
rl_vsr_bronze_silver_gold_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-tiered-bronze-silver-gold-jwt-claim-sub.yaml"
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
rl_pol_premium_with_default_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-premium-with-default-jwt-claim-sub.yaml"
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

    def check_rate_limit_eq(self, url, code, counter, delay=0.01, headers={}):
        occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                url,
                headers=headers,
            )
            occur.append(resp.status_code)
            wait_before_test(delay)
        assert occur.count(code) in range(counter, counter + 2)

    def check_rate_limit_nearly_eq(self, url, code, counter, plus_minus=1, delay=0.01, headers={}):
        occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.get(
                url,
                headers=headers,
            )
            occur.append(resp.status_code)
            wait_before_test(delay)
        lower_range = counter
        if counter > 1:
            lower_range = counter - plus_minus
        upper_range = counter + plus_minus + 1  # add an extra 1 to account for range
        assert occur.count(code) in range(lower_range, upper_range)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vsr_basic_premium_jwt_claim_sub])
    def test_rl_duplicate_default_policy_tiered_basic_premium_with_default_jwt_claim_sub_vsr(
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
        Test if when both a basic and premium rate-limiting policy are the default for the tier,
        the VS goes into a Invalid state and emits a Warning Event.
        Policies are applied at the VirtualServer Route level
        """
        basic_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_basic_with_default_jwt_claim_sub
        )
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_premium_with_default_jwt_claim_sub
        )

        # Patch VirtualServerRoute
        apply_and_assert_warning_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
        )

        # Assert that the 'AddedOrUpdatedWithWarning' event is present
        assert (
            wait_for_event(
                kube_apis.v1,
                f"Tiered rate-limit Policies on [{v_s_route_setup.route_m.namespace}/{v_s_route_setup.route_m.name}] contain conflicting default values",
                v_s_route_setup.route_m.namespace,
                30,
            )
            is True
        )

        delete_policy(kube_apis.custom_objects, basic_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)

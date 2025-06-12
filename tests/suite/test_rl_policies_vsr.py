import time

import jwt
import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.nginx_api_utils import (
    check_synced_zone_exists,
    wait_for_zone_sync_enabled,
    wait_for_zone_sync_nodes_online,
)
from suite.utils.policy_resources_utils import (
    apply_and_assert_valid_policy,
    create_policy_from_yaml,
    delete_policy,
    read_policy,
)
from suite.utils.resources_utils import (
    create_secret_from_yaml,
    delete_secret,
    get_first_pod_name,
    get_pod_list,
    replace_configmap_from_yaml,
    scale_deployment,
    wait_before_test,
    wait_for_event,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    apply_and_assert_valid_vs,
    apply_and_assert_valid_vsr,
    apply_and_assert_warning_vsr,
    delete_and_create_v_s_route_from_yaml,
    delete_and_create_vs_from_yaml,
    get_vs_nginx_template_conf,
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
rl_vsr_override_tiered_jwt_basic_premium_vs_spec_src = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-vsr-tiered-jwt-basic-premium-spec-override.yaml"
)
rl_vsr_override_tiered_jwt_basic_premium_vs_route_src = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-vsr-tiered-jwt-basic-premium-route-override.yaml"
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
rl_basic_apikey_client1 = "client1basic"
rl_premium_apikey_client1 = "client1premium"
rl_bronze_apikey_client1 = "client1bronze"
rl_silver_apikey_client1 = "client1silver"
rl_gold_apikey_client1 = "client1gold"
rl_default_apikey_random = "random"
rl_sec_apikey = f"{TEST_DATA}/rate-limit/policies/api-key-secret.yaml"
rl_pol_apikey = f"{TEST_DATA}/rate-limit/policies/api-key-policy.yaml"
rl_pol_basic_with_default_apikey = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-basic-with-default-variables-apikey.yaml"
)
rl_pol_premium_no_default_apikey = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-premium-no-default-variables-apikey.yaml"
)
rl_pol_bronze_with_default_apikey = f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-bronze-with-default-apikey.yaml"
rl_pol_silver_no_default_apikey = f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-silver-no-default-apikey.yaml"
rl_pol_gold_no_default_apikey = f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-gold-no-default-apikey.yaml"
rl_vsr_override_tiered_apikey_basic_premium_vs_spec_src = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-vsr-tiered-apikey-basic-premium-spec-override.yaml"
)
rl_vsr_override_tiered_apikey_basic_premium_vs_route_src = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-vsr-tiered-apikey-basic-premium-route-override.yaml"
)
rl_vsr_bronze_silver_gold_apikey = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-tiered-bronze-silver-gold-apikey.yaml"
)
rl_vsr_multiple_tiered_variables_apikey = (
    f"{TEST_DATA}/rate-limit/route-subroute/virtual-server-route-mutliple-tiered-variables-apikey.yaml"
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
                    "-nginx-status-allow-cidrs=0.0.0.0/0,::/0",
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
        delete_and_create_v_s_route_from_yaml(
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

        self.check_rate_limit_nearly_eq(
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

        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host},
        )

        self.restore_default_vsr(kube_apis, v_s_route_setup)
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

        self.check_rate_limit_nearly_eq(
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
        delete_and_create_v_s_route_from_yaml(
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
        delete_and_create_v_s_route_from_yaml(
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

        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host},
        )
        delete_policy(kube_apis.custom_objects, pol_name_pri, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, pol_name_sec, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        delete_and_create_vs_from_yaml(
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
                print_log=False,
            )
            assert "rate=10r/s" in conf
        # restore replicas, policy and vsr
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ns, 1)
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vsr_sec_src])
    def test_rl_policy_5rs_with_zone_sync_vsr(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test pods are scaled to 3, ZoneSync is enabled & Policy zone is synced
        """
        replica_count = 3
        NGINX_API_VERSION = 9
        pol_name = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_sec_src)

        configmap_name = "nginx-config"

        print("Step 1: apply minimal zone_sync nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-minimal.yaml",
        )

        print("Step 2: apply the policy to the virtual server route")
        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
        )

        print(f"Step 3: scale deployments to {replica_count}")
        scale_deployment(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            "nginx-ingress",
            ingress_controller_prerequisites.namespace,
            replica_count,
        )

        wait_before_test()

        print("Step 4: check if pods are ready")
        wait_until_all_pods_are_ready(kube_apis.v1, ingress_controller_prerequisites.namespace)

        print("Step 5: check plus api for zone sync")
        api_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.api_port}"

        stream_url = f"{api_url}/api/{NGINX_API_VERSION}/stream"
        assert wait_for_zone_sync_enabled(stream_url)

        zone_sync_url = f"{stream_url}/zone_sync"
        assert wait_for_zone_sync_nodes_online(zone_sync_url, replica_count)

        print("Step 6: check plus api if zone is synced")
        assert check_synced_zone_exists(zone_sync_url, pol_name.replace("-", "_", -1))

        # revert changes
        scale_deployment(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            "nginx-ingress",
            ingress_controller_prerequisites.namespace,
            1,
        )
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vsr_pri_sca_src])
    def test_rl_policy_with_scale_and_zone_sync_vsr(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        src,
    ):
        """
        Test pods are scaled to 3, ZoneSync is enabled & Policy zone is synced
        """
        replica_count = 3
        NGINX_API_VERSION = 9
        pol_name = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_pri_sca_src)

        configmap_name = "nginx-config"

        print("Step 1: apply minimal zone_sync nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-minimal.yaml",
        )

        print("Step 2: apply the policy to the virtual server route")
        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
        )

        print(f"Step 3: scale deployments to {replica_count}")
        scale_deployment(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            "nginx-ingress",
            ingress_controller_prerequisites.namespace,
            replica_count,
        )

        wait_before_test()

        print("Step 4: check if pods are ready")
        wait_until_all_pods_are_ready(kube_apis.v1, ingress_controller_prerequisites.namespace)

        print("Step 5: check plus api for zone sync")
        api_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.api_port}"

        stream_url = f"{api_url}/api/{NGINX_API_VERSION}/stream"
        assert wait_for_zone_sync_enabled(stream_url)

        zone_sync_url = f"{stream_url}/zone_sync"
        assert wait_for_zone_sync_nodes_online(zone_sync_url, replica_count)

        print("Step 6: check plus api if zone is synced")
        assert check_synced_zone_exists(zone_sync_url, pol_name.replace("-", "_", -1))

        print("Step 7: check sync in config")
        pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        vsr_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            pod_name,
            ingress_controller_prerequisites.namespace,
        )

        policy = read_policy(kube_apis.custom_objects, v_s_route_setup.route_m.namespace, pol_name)
        expected_conf_line = f"limit_req_zone {policy["spec"]["rateLimit"]["key"]} zone=pol_rl_{policy["metadata"]["namespace"].replace("-", "_", -1)}_{pol_name.replace("-", "_", -1)}_{v_s_route_setup.route_m.namespace.replace("-", "_", -1)}_{v_s_route_setup.vs_name.replace("-", "_", -1)}_sync:{policy["spec"]["rateLimit"]["zoneSize"]} rate={policy["spec"]["rateLimit"]["rate"]} sync;"
        assert expected_conf_line in vsr_config

        # revert changes
        scale_deployment(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            "nginx-ingress",
            ingress_controller_prerequisites.namespace,
            1,
        )
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)

    @pytest.mark.skip_for_nginx_oss
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
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {jwt_token}"},
        )

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        self.restore_default_vsr(kube_apis, v_s_route_setup)


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
class TestTieredRateLimitingPoliciesVsr:
    def restore_default_vsr(self, kube_apis, v_s_route_setup) -> None:
        """
        Function to revert vsr deployments to valid state
        """
        patch_src_m = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
        delete_and_create_v_s_route_from_yaml(
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
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Default Rate Limit unlimited
        self.check_rate_limit_eq(
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
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Default Rate Limit 1r/s
        self.check_rate_limit_nearly_eq(
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
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Basic Default Rate Limit 1r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host},
        )
        wait_before_test(1)

        ##  Test Bronze Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {bronze_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Silver Rate Limit 10r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            10,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {silver_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Gold Rate Limit 15r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            15,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {gold_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Bronze Default Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
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

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize(
        "src",
        [rl_vsr_override_tiered_jwt_basic_premium_vs_spec_src, rl_vsr_override_tiered_jwt_basic_premium_vs_route_src],
    )
    def test_override_multiple_tiered_jwt_claim_sub_vs_vsr(
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

        # policies for virtualserver/vsr
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

        # patch vsr with bronze/silver/gold tier policies
        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            rl_vsr_bronze_silver_gold_jwt_claim_sub,
        )

        # patch vs with basic/premium policies
        apply_and_assert_valid_vs(
            kube_apis,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
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
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Basic Default Rate Limit 1r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host},
        )
        wait_before_test(1)

        ##  Test Bronze Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {bronze_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Silver Rate Limit 10r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            10,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {silver_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Gold Rate Limit 15r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            15,
            headers={"host": v_s_route_setup.vs_host, "Authorization": f"Bearer {gold_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Bronze Default Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
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
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, std_vs_src, v_s_route_setup.namespace
        )

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

    @pytest.mark.parametrize(
        "src",
        [
            rl_vsr_override_tiered_apikey_basic_premium_vs_spec_src,
            rl_vsr_override_tiered_apikey_basic_premium_vs_route_src,
        ],
    )
    def test_override_multiple_tiered_apikey_vs_vsr(
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

        # policies for virtualserver/vsr
        apikey_sec_name = create_secret_from_yaml(kube_apis.v1, v_s_route_setup.route_m.namespace, rl_sec_apikey)
        apikey_pol_name = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_apikey)
        basic_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_basic_with_default_apikey
        )
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_premium_no_default_apikey
        )
        bronze_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_bronze_with_default_apikey
        )
        silver_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_silver_no_default_apikey
        )
        gold_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_gold_no_default_apikey
        )

        # patch vsr with bronze/silver/gold tier policies
        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            rl_vsr_bronze_silver_gold_apikey,
        )

        # patch vs with basic/premium policies
        apply_and_assert_valid_vs(
            kube_apis,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            src,
        )

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"

        ##  Test Basic Rate Limit 1r/s
        print("Testing Basic Rate Limit 1r/s")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_basic_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        print("Testing Premium Rate Limit 5r/s")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_premium_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Basic Default Rate Limit 1r/s
        print("Testing Basic Default Rate Limit 1r/s")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_default_apikey_random},
        )
        wait_before_test(1)

        ##  Test Bronze Rate Limit 5r/s
        print("Testing Bronze Rate Limit 5r/s")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_bronze_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Silver Rate Limit 10r/s
        print("Testing Silver Rate Limit 10r/s")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            10,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_silver_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Gold Rate Limit 15r/s
        print("Testing Gold Rate Limit 15r/s")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            15,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_gold_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Bronze Default Rate Limit 5r/s
        print("Testing Bronze Default Rate Limit 5r/s")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_default_apikey_random},
        )

        self.restore_default_vsr(kube_apis, v_s_route_setup)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, std_vs_src, v_s_route_setup.namespace
        )
        delete_policy(kube_apis.custom_objects, basic_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, bronze_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, silver_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, gold_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, apikey_pol_name, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, apikey_sec_name, v_s_route_setup.route_m.namespace)

    @pytest.mark.parametrize("src", [rl_vsr_multiple_tiered_variables_apikey])
    def test_rl_policy_multiple_tiered_variables_apikey_vsr(
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
        applying the same basic/premium tier to /backend3.
        Policies are applied at the VirtualServerRoute level
        """

        apikey_sec_name = create_secret_from_yaml(kube_apis.v1, v_s_route_setup.route_m.namespace, rl_sec_apikey)
        apikey_pol_name = apply_and_assert_valid_policy(kube_apis, v_s_route_setup.route_m.namespace, rl_pol_apikey)
        basic_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_basic_with_default_apikey
        )
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, v_s_route_setup.route_m.namespace, rl_pol_premium_no_default_apikey
        )

        apply_and_assert_valid_vsr(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            src,
        )

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"

        ##  Test Basic Rate Limit 1r/s /backend1
        print(f"Testing Basic Rate Limit 1r/s {v_s_route_setup.route_m.paths[0]}")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_basic_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s /backend1
        print(f"Testing Premium Rate Limit 5r/s {v_s_route_setup.route_m.paths[0]}")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_premium_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Basic Default Rate Limit 1r/s /backend1
        print(f"Testing Basic Default Rate Limit 1r/s {v_s_route_setup.route_m.paths[0]}")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_default_apikey_random},
        )
        wait_before_test(1)

        ##  Test Basic Rate Limit 1r/s /backend3
        print(f"Testing Basic Rate Limit 1r/s {v_s_route_setup.route_m.paths[1]}")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_basic_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s /backend3
        print(f"Testing Premium Rate Limit 5r/s {v_s_route_setup.route_m.paths[1]}")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            5,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_premium_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Basic Default Rate Limit 5r/s /backend3
        print(f"Testing Basic Default Rate Limit 5r/s {v_s_route_setup.route_m.paths[1]}")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            200,
            1,
            headers={"host": v_s_route_setup.vs_host, "X-header-name": rl_default_apikey_random},
        )

        # ## Test Unlimited access /backend2
        print(f"Testing Unlimited access {v_s_route_setup.route_s.paths[0]}")
        self.check_rate_limit_nearly_eq(
            f"{req_url}{v_s_route_setup.route_s.paths[0]}",
            503,
            0,
        )

        self.restore_default_vsr(kube_apis, v_s_route_setup)
        delete_policy(kube_apis.custom_objects, basic_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, apikey_pol_name, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, apikey_sec_name, v_s_route_setup.route_m.namespace)

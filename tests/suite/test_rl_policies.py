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
    get_vs_nginx_template_conf,
    replace_configmap_from_yaml,
    scale_deployment,
    wait_before_test,
    wait_for_event,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    apply_and_assert_valid_vs,
    apply_and_assert_warning_vs,
    create_virtual_server_from_yaml,
    delete_virtual_server,
    patch_virtual_server_from_yaml,
)

NGINX_API_VERSION = 9

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
rl_vs_basic_premium_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/spec/virtual-server-tiered-basic-premium-jwt-claim-sub.yaml"
)
rl_vs_route_basic_premium_jwt_claim_sub = (
    f"{TEST_DATA}/rate-limit/spec/virtual-server-route-tiered-basic-premium-jwt-claim-sub.yaml"
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
rl_vs_basic_premium_variables_apikey = (
    f"{TEST_DATA}/rate-limit/spec/virtual-server-tiered-basic-premium-variables-apikey.yaml"
)
rl_basic_apikey_client1 = "client1basic"
rl_premium_apikey_client1 = "client1premium"
rl_default_apikey_random = "random"
rl_sec_apikey = f"{TEST_DATA}/rate-limit/policies/api-key-secret.yaml"
rl_pol_apikey = f"{TEST_DATA}/rate-limit/policies/api-key-policy.yaml"
rl_pol_basic_with_default_variables_apikey = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-basic-with-default-variables-apikey.yaml"
)
rl_pol_premium_no_default_variables_apikey = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-premium-no-default-variables-apikey.yaml"
)
rl_vs_read_write_variables_request_method = (
    f"{TEST_DATA}/rate-limit/spec/virtual-server-tiered-read-write-variables-request-method.yaml"
)
rl_pol_write_no_default_variables_request_method = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-write-no-default-variables-request-method.yaml"
)
rl_pol_write_with_default_variables_request_method = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-write-with-default-variables-request-method.yaml"
)
rl_pol_read_no_default_variables_request_method = (
    f"{TEST_DATA}/rate-limit/policies/rate-limit-tiered-read-no-default-variables-request-method.yaml"
)


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
                    "-nginx-status-allow-cidrs=0.0.0.0/0,::/0",
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
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_pri_src)

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            src,
        )

        # Run rate limit test 1r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host},
        )

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

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
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_sec_src)

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            src,
        )

        # Run rate limit test 5r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            5,
            headers={"host": virtual_server_setup.vs_host},
        )

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

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
        pol_name_pri = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_pri_src)
        pol_name_sec = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_sec_src)

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            src,
        )

        # Run rate limit test 1r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host},
        )

        delete_policy(kube_apis.custom_objects, pol_name_pri, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_name_sec, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

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
        pol_name_pri = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_pri_src)
        pol_name_sec = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_sec_src)

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            src,
        )

        # Run rate limit test 5r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            5,
            headers={"host": virtual_server_setup.vs_host},
        )

        delete_policy(kube_apis.custom_objects, pol_name_pri, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_name_sec, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

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

        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_pri_sca_src)

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            src,
        )

        ic_pods = get_pod_list(kube_apis.v1, ns)
        for i in range(len(ic_pods)):
            conf = ""
            for attempt in range(5):
                conf = get_vs_nginx_template_conf(
                    kube_apis.v1,
                    virtual_server_setup.namespace,
                    virtual_server_setup.vs_name,
                    ic_pods[i].metadata.name,
                    ingress_controller_prerequisites.namespace,
                )
                if "rate=10r/s" in conf:
                    break
                print(f"rate=10r/s not found in config for pod. Retrying...")
                wait_before_test()
            assert "rate=10r/s" in conf, f"Failed to find 'rate=10r/s' in config after multiple retries"
        # restore replicas, policy and vs
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ns, 1)
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vs_sec_src])
    def test_rl_policy_5rs_with_zone_sync(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test pods are scaled to 3, ZoneSync is enabled & Policy zone is synced
        """
        replica_count = 3
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_sec_src)

        configmap_name = "nginx-config"

        print("Step 1: apply minimal zone_sync nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-minimal.yaml",
        )

        print("Step 2: apply the policy to the virtual server")
        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
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
        self.restore_default_vs(kube_apis, virtual_server_setup)
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vs_pri_sca_src])
    def test_rl_policy_with_scale_and_zone_sync(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test pods are scaled to 3, ZoneSync is enabled & Policy zone is synced
        """
        replica_count = 3
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_pri_sca_src)

        configmap_name = "nginx-config"

        print("Step 1: apply minimal zone_sync nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-minimal.yaml",
        )

        print("Step 2: apply the policy to the virtual server")
        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
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
        vs_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            pod_name,
            ingress_controller_prerequisites.namespace,
        )

        policy = read_policy(kube_apis.custom_objects, test_namespace, pol_name)
        expected_conf_line = f"limit_req_zone {policy["spec"]["rateLimit"]["key"]} zone=pol_rl_{policy["metadata"]["namespace"].replace("-", "_", -1)}_{pol_name.replace("-", "_", -1)}_{virtual_server_setup.namespace.replace("-", "_", -1)}_{virtual_server_setup.vs_name.replace("-", "_", -1)}_sync:{policy["spec"]["rateLimit"]["zoneSize"]} rate={policy["spec"]["rateLimit"]["rate"]} sync;"
        assert expected_conf_line in vs_config

        # revert changes
        scale_deployment(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            "nginx-ingress",
            ingress_controller_prerequisites.namespace,
            1,
        )
        self.restore_default_vs(kube_apis, virtual_server_setup)
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

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
        Policy is applied at the VirtualServer Spec level
        """
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_jwt_claim_sub)

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            src,
        )

        jwt_token = jwt.encode(
            {"sub": "client1"},
            "nginx",
            algorithm="HS256",
        )

        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {jwt_token}"},
        )
        wait_before_test(1)

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)


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
class TestTieredRateLimitingPolicies:
    def restore_default_vs(self, kube_apis, virtual_server_setup) -> None:
        """
        Restore VirtualServer without policy spec
        """
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace)
        create_virtual_server_from_yaml(kube_apis.custom_objects, std_vs_src, virtual_server_setup.namespace)
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

    def check_rate_limit_nearly_eq(self, url, code, counter, plus_minus=1, delay=0.01, headers={}, method="GET"):
        occur = []
        t_end = time.perf_counter() + 1
        while time.perf_counter() < t_end:
            resp = requests.request(
                method.lower(),
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
    @pytest.mark.parametrize("src", [rl_vs_basic_premium_jwt_claim_sub])
    def test_speclevel_rl_policy_tiered_basic_premium_no_default_jwt_claim_sub(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if basic rate-limiting policy is working with 1 rps using $jwt_claim_sub as the rate limit key,
        if premium rate-limiting policy is working with 5 rps using $jwt_claim_sub as the rate limit key &
        if the default is unlimited when no default policy is applied.
        Policies are applied at the VirtualServer Spec level
        """
        basic_pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_basic_no_default_jwt_claim_sub)
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_premium_no_default_jwt_claim_sub
        )

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
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

        ##  Test Basic Rate Limit 1r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            5,
            headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Default Rate Limit unlimited
        self.check_rate_limit_eq(
            virtual_server_setup.backend_1_url, 503, 0, headers={"host": virtual_server_setup.vs_host}
        )

        delete_policy(kube_apis.custom_objects, basic_pol_name, test_namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vs_basic_premium_jwt_claim_sub])
    def test_speclevel_rl_policy_tiered_basic_premium_with_default_jwt_claim_sub(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if basic rate-limiting policy is working with 1 rps using $jwt_claim_sub as the rate limit key,
        if premium rate-limiting policy is working with 5 rps using $jwt_claim_sub as the rate limit key &
        if the default basic rate limit of 1r/s is applied.
        Policies are applied at the VirtualServer Spec level
        """
        basic_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_basic_with_default_jwt_claim_sub
        )
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_premium_no_default_jwt_claim_sub
        )

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
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

        ##  Test Default Rate Limit 1r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            5,
            headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Default Rate Limit 1r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url, 200, 1, headers={"host": virtual_server_setup.vs_host}
        )

        delete_policy(kube_apis.custom_objects, basic_pol_name, test_namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vs_route_basic_premium_jwt_claim_sub])
    def test_routelevel_rl_policy_tiered_basic_premium_with_default_jwt_claim_sub(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if basic rate-limiting policy is working with 1 rps using $jwt_claim_sub as the rate limit key,
        if premium rate-limiting policy is working with 5 rps using $jwt_claim_sub as the rate limit key,
        if the default basic rate limit of 1r/s is applied &
        if a route without policies is unlimited.
        Policies are applied at the VirtualServer Route level
        """
        basic_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_basic_with_default_jwt_claim_sub
        )
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_premium_no_default_jwt_claim_sub
        )

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
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

        ##  Test Basic Rate Limit 1r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            5,
            headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Default Rate Limit 1r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url, 200, 1, headers={"host": virtual_server_setup.vs_host}
        )
        wait_before_test(1)

        ##  Test different backend route
        self.check_rate_limit_eq(
            virtual_server_setup.backend_2_url, 503, 0, headers={"host": virtual_server_setup.vs_host}
        )

        delete_policy(kube_apis.custom_objects, basic_pol_name, test_namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vs_route_basic_premium_jwt_claim_sub])
    def test_routelevel_rl_policy_tiered_basic_premium_no_default_jwt_claim_sub(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if basic rate-limiting policy is working with 1 rps using $jwt_claim_sub as the rate limit key,
        if premium rate-limiting policy is working with 5 rps using $jwt_claim_sub as the rate limit key,
        if the default is unlimited when no default policy is applied &
        if a route without policies is unlimited.
        Policies are applied at the VirtualServer Route level
        """
        basic_pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_basic_no_default_jwt_claim_sub)
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_premium_no_default_jwt_claim_sub
        )

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
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

        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {basic_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_1_url,
            200,
            5,
            headers={"host": virtual_server_setup.vs_host, "Authorization": f"Bearer {premium_jwt_token}"},
        )
        wait_before_test(1)

        ##  Test Default Rate Limit unlimited
        self.check_rate_limit_eq(
            virtual_server_setup.backend_1_url, 503, 0, headers={"host": virtual_server_setup.vs_host}
        )
        wait_before_test(1)

        ##  Test different backend route
        self.check_rate_limit_eq(
            virtual_server_setup.backend_2_url, 503, 0, headers={"host": virtual_server_setup.vs_host}
        )
        wait_before_test(1)

        delete_policy(kube_apis.custom_objects, basic_pol_name, test_namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

    @pytest.mark.skip_for_nginx_oss
    @pytest.mark.parametrize("src", [rl_vs_route_basic_premium_jwt_claim_sub])
    def test_rl_duplicate_default_policy_tiered_basic_premium_with_default_jwt_claim_sub(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if when both a basic and premium rate-limiting policy are the default for the tier,
        the VS goes into a Invalid state and emits a Warning Event.
        Policies are applied at the VirtualServer Route level
        """
        basic_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_basic_with_default_jwt_claim_sub
        )
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_premium_with_default_jwt_claim_sub
        )

        # Patch VirtualServer
        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            src,
        )

        # Assert that the 'AddedOrUpdatedWithWarning' event is present
        assert (
            wait_for_event(
                kube_apis.v1,
                f"Tiered rate-limit Policies on [{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}] contain conflicting default values",
                virtual_server_setup.namespace,
                30,
            )
            is True
        )

        delete_policy(kube_apis.custom_objects, basic_pol_name, test_namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

    @pytest.mark.parametrize("src", [rl_vs_basic_premium_variables_apikey])
    def test_speclevel_rl_policy_tiered_basic_premium_with_default_variables_apikey(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if basic rate-limiting policy is working with 1 rps using $apikey_client_name as the rate limit key,
        if premium rate-limiting policy is working with 5 rps using $apikey_client_name as the rate limit key &
        if the default basic rate limit of 1r/s is applied.
        Policies are applied at the VirtualServer Spec level
        """
        apikey_sec_name = create_secret_from_yaml(kube_apis.v1, test_namespace, rl_sec_apikey)
        apikey_pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, rl_pol_apikey)
        basic_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_basic_with_default_variables_apikey
        )
        premium_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_premium_no_default_variables_apikey
        )

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            src,
        )

        ##  Test Basic Rate Limit 1r/s
        print("Test Basic Rate Limit 1r/s")
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_2_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host, "X-header-name": rl_basic_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Premium Rate Limit 5r/s
        print("Test Premium Rate Limit 5r/s")
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_2_url,
            200,
            5,
            headers={"host": virtual_server_setup.vs_host, "X-header-name": rl_premium_apikey_client1},
        )
        wait_before_test(1)

        ##  Test Default Rate Limit 1r/s
        print("Test Default Rate Limit 1r/s")
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_2_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host, "X-header-name": rl_default_apikey_random},
        )

        self.restore_default_vs(kube_apis, virtual_server_setup)
        delete_policy(kube_apis.custom_objects, basic_pol_name, test_namespace)
        delete_policy(kube_apis.custom_objects, premium_pol_name, test_namespace)
        delete_policy(kube_apis.custom_objects, apikey_pol_name, test_namespace)
        delete_secret(kube_apis.v1, apikey_sec_name, test_namespace)

    @pytest.mark.parametrize("src", [rl_vs_read_write_variables_request_method])
    def test_speclevel_rl_policy_tiered_read_write_with_default_variables_request_method(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if read rate-limiting policy is working with 5 rps using $request_method as the rate limit key,
        if write rate-limiting policy is working with 1 rps using $request_method as the rate limit key &
        if the default write rate limit of 1r/s is applied.
        Policies are applied at the VirtualServer Spec level
        """
        read_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_read_no_default_variables_request_method
        )
        write_pol_name = apply_and_assert_valid_policy(
            kube_apis, test_namespace, rl_pol_write_with_default_variables_request_method
        )

        # Patch VirtualServer
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            src,
        )

        ##  Test Write Rate Limit 1r/s
        print("Test Write Rate Limit 1r/s")
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_2_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host},
            method="DELETE",
        )
        wait_before_test(1)

        ##  Test Read Rate Limit 5r/s
        print("Test Read Rate Limit 5r/s")
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_2_url,
            200,
            5,
            headers={"host": virtual_server_setup.vs_host},
        )
        wait_before_test(1)

        ##  Test Default Rate Limit 1r/s
        print("Test Default Rate Limit 1r/s")
        self.check_rate_limit_nearly_eq(
            virtual_server_setup.backend_2_url,
            200,
            1,
            headers={"host": virtual_server_setup.vs_host},
            method="POST",
        )

        self.restore_default_vs(kube_apis, virtual_server_setup)
        delete_policy(kube_apis.custom_objects, read_pol_name, test_namespace)
        delete_policy(kube_apis.custom_objects, write_pol_name, test_namespace)

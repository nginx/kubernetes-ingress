import re

import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import ensure_connection_to_public_endpoint, pod_restart, wait_before_test
from suite.utils.vs_vsr_resources_utils import delete_and_create_v_s_route_from_yaml, delete_and_create_vs_from_yaml

std_vsr_src = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
cache_pol_basic_src = f"{TEST_DATA}/cache-policy/policies/cache-policy-basic.yaml"
cache_pol_advanced_src = f"{TEST_DATA}/cache-policy/policies/cache-policy-advanced.yaml"
cache_vs_vsr_src = f"{TEST_DATA}/cache-policy/vsr/virtual-server.yaml"
cache_vsr_basic_src = f"{TEST_DATA}/cache-policy/vsr/virtual-server-route-cache-policy-basic.yaml"
cache_vsr_advanced_src = f"{TEST_DATA}/cache-policy/vsr/virtual-server-route-cache-policy-advanced.yaml"


@pytest.mark.policies
@pytest.mark.policies_cache
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                    f"-enable-snippets",
                ],
            },
            {"example": "virtual-server-route"},
        )
    ],
    indirect=True,
)
class TestCachePoliciesVSR:

    def setup_vs_cache_policy(self, kube_apis, namespace, policy_src, vs_name):
        print(f"Create cache policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_src, namespace)
        print("Update Virtual Server with snippets")
        delete_and_create_vs_from_yaml(kube_apis.custom_objects, vs_name, cache_vs_vsr_src, namespace)
        wait_before_test()
        return pol_name

    def test_cache_policy_vsr_basic(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test cache policy basic (GET only) applied to VirtualServerRoute
        """

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        pol_name = self.setup_vs_cache_policy(
            kube_apis, v_s_route_setup.route_m.namespace, cache_pol_basic_src, v_s_route_setup.vs_name
        )

        print(f"VSR with basic cache policy: {cache_vsr_basic_src}")
        delete_and_create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            cache_vsr_basic_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        # Test cache behavior for GET requests on subroute
        resp_1 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers={"host": v_s_route_setup.vs_host})
        cache_status_1 = resp_1.headers.get("X-Cache-Status")
        print(f"Cache status for first GET request: {cache_status_1}")

        resp_2 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers={"host": v_s_route_setup.vs_host})
        cache_status_2 = resp_2.headers.get("X-Cache-Status")
        print(f"Cache status for second GET request: {cache_status_2}")

        # POST requests should not be cached (basic policy allows GET only)
        resp_3 = requests.post(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers={"host": v_s_route_setup.vs_host}
        )
        cache_status_3 = resp_3.headers.get("X-Cache-Status")
        print(f"Cache status for POST request: {cache_status_3}")

        resp_4 = requests.post(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers={"host": v_s_route_setup.vs_host}
        )
        cache_status_4 = resp_4.headers.get("X-Cache-Status")
        print(f"Cache status for second POST request: {cache_status_4}")

        # Extract Request IDs from response body
        req_id_1 = re.search(r"Request ID: (\S+)", resp_1.text)
        req_id_2 = re.search(r"Request ID: (\S+)", resp_2.text)
        req_id_3 = re.search(r"Request ID: (\S+)", resp_3.text)
        req_id_4 = re.search(r"Request ID: (\S+)", resp_4.text)

        assert all(
            [
                resp_1.status_code == 200,
                resp_2.status_code == 200,
                resp_3.status_code == 200,
                resp_4.status_code == 200,
                "Request ID:" in resp_1.text,
                "Request ID:" in resp_2.text,
                "Request ID:" in resp_3.text,
                "Request ID:" in resp_4.text,
                req_id_1.group(1) == req_id_2.group(1),  # GET requests cached (same Request ID)
                req_id_3.group(1) != req_id_4.group(1),  # POST requests not cached (different Request IDs)
                cache_status_1 in ["MISS", "EXPIRED"],
                cache_status_2 == "HIT",
                cache_status_3 in ["MISS", "EXPIRED", None],
                cache_status_4 in ["MISS", "EXPIRED", None],
            ]
        )

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        delete_and_create_v_s_route_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.route_m.name, std_vsr_src, v_s_route_setup.route_m.namespace
        )
        ns = ingress_controller_prerequisites.namespace
        # Purge all existing cache entries by removing pods
        pod_restart(kube_apis.v1, ns)
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

    def test_cache_policy_vsr_advanced(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test cache policy advanced (GET/HEAD/POST) applied to VirtualServerRoute
        """

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        pol_name = self.setup_vs_cache_policy(
            kube_apis, v_s_route_setup.route_m.namespace, cache_pol_advanced_src, v_s_route_setup.vs_name
        )

        print(f"VSR with advanced cache policy: {cache_vsr_advanced_src}")
        delete_and_create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            cache_vsr_advanced_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        # Test cache behavior for GET requests
        resp_1 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers={"host": v_s_route_setup.vs_host})
        cache_status_1 = resp_1.headers.get("X-Cache-Status")
        print(f"Cache status for first GET request: {cache_status_1}")

        resp_2 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers={"host": v_s_route_setup.vs_host})
        cache_status_2 = resp_2.headers.get("X-Cache-Status")
        print(f"Cache status for second GET request: {cache_status_2}")

        # Test cache behavior for POST requests (should be cached with advanced policy)
        resp_3 = requests.post(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers={"host": v_s_route_setup.vs_host}
        )
        cache_status_3 = resp_3.headers.get("X-Cache-Status")
        print(f"Cache status for first POST request: {cache_status_3}")

        # Test cache behavior for HEAD requests
        resp_4 = requests.head(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers={"host": v_s_route_setup.vs_host}
        )
        cache_status_4 = resp_4.headers.get("X-Cache-Status")
        print(f"Cache status for first HEAD request: {cache_status_4}")

        # Extract Request IDs from response body
        req_id_1 = re.search(r"Request ID: (\S+)", resp_1.text)
        req_id_2 = re.search(r"Request ID: (\S+)", resp_2.text)
        req_id_3 = re.search(r"Request ID: (\S+)", resp_3.text)

        assert all(
            [
                resp_1.status_code == 200,
                resp_2.status_code == 200,
                resp_3.status_code == 200,
                resp_4.status_code == 200,
                "Request ID:" in resp_1.text,
                "Request ID:" in resp_2.text,
                "Request ID:" in resp_3.text,
                req_id_1.group(1) == req_id_2.group(1) == req_id_3.group(1),
                cache_status_1 in ["MISS", "EXPIRED", None],
                cache_status_2 == "HIT",
                cache_status_3 == "HIT",
                cache_status_4 == "HIT",
            ]
        )

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        delete_and_create_v_s_route_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.route_m.name, std_vsr_src, v_s_route_setup.route_m.namespace
        )
        ns = ingress_controller_prerequisites.namespace
        # Purge all existing cache entries by removing pods
        pod_restart(kube_apis.v1, ns)
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

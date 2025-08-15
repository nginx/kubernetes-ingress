import re

import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import ensure_connection_to_public_endpoint, pod_restart, wait_before_test
from suite.utils.vs_vsr_resources_utils import delete_and_create_vs_from_yaml

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
cache_pol_basic_src = f"{TEST_DATA}/cache-policy/policies/cache-policy-basic.yaml"
cache_pol_advanced_src = f"{TEST_DATA}/cache-policy/policies/cache-policy-advanced.yaml"
cache_pol_purge_src = f"{TEST_DATA}/cache-policy/policies/cache-policy-purge.yaml"
cache_vs_basic_spec_src = f"{TEST_DATA}/cache-policy/spec/virtual-server-cache-policy-basic-spec.yaml"
cache_vs_advanced_spec_src = f"{TEST_DATA}/cache-policy/spec/virtual-server-cache-policy-advanced-spec.yaml"
cache_vs_basic_route_src = f"{TEST_DATA}/cache-policy/route/virtual-server-cache-policy-basic-route.yaml"
cache_vs_advanced_route_src = f"{TEST_DATA}/cache-policy/route/virtual-server-cache-policy-advanced-route.yaml"
cache_vs_purge_src = f"{TEST_DATA}/cache-policy/spec/virtual-server-cache-policy-purge.yaml"


@pytest.mark.policies
@pytest.mark.policies_cache
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [f"-enable-custom-resources", f"-enable-leader-election=false", f"-enable-snippets"],
            },
            {
                "example": "virtual-server",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestCachePolicies:
    def setup_cache_policy(self, kube_apis, test_namespace, policy_src):
        print(f"Create cache policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_src, test_namespace)
        wait_before_test()
        return pol_name

    @pytest.mark.parametrize("src", [cache_vs_basic_spec_src, cache_vs_basic_route_src])
    def test_cache_policy_basic(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test cache policy basic (GET only) configured at spec and route level
        """

        pol_name = self.setup_cache_policy(kube_apis, test_namespace, cache_pol_basic_src)

        # Apply VS with basic cache policy at spec level
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            test_namespace,
        )

        # Test cache behavior for GET requests
        # First request should populate cache
        resp_1 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_1 = resp_1.headers.get("X-Cache-Status")

        # Second request should return cached content (same Request ID)
        resp_2 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_2 = resp_2.headers.get("X-Cache-Status")

        # POST requests should not be cached (different Request IDs expected)
        resp_3 = requests.post(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_3 = resp_3.headers.get("X-Cache-Status")

        resp_4 = requests.post(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_4 = resp_4.headers.get("X-Cache-Status")

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
                "Request ID:" in resp_1.text,  # Verify response body contains Request ID
                "Request ID:" in resp_2.text,
                "Request ID:" in resp_3.text,
                "Request ID:" in resp_4.text,
                (
                    req_id_1.group(1) == req_id_2.group(1) if req_id_1 and req_id_2 else False
                ),  # GET requests cached (same Request ID)
                (
                    req_id_3.group(1) != req_id_4.group(1) if req_id_3 and req_id_4 else True
                ),  # POST requests not cached (different Request IDs)
                cache_status_1 in ["MISS", "EXPIRED"],  # First GET should be cache miss
                cache_status_2 == "HIT",  # Second GET should be cache hit
                cache_status_3 in ["MISS", "EXPIRED", None],  # POST should not be cached or use cached entry
                cache_status_4 in ["MISS", "EXPIRED", None],  # POST should not be cached
            ]
        )

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, test_namespace
        )
        ns = ingress_controller_prerequisites.namespace
        # Purge all existing cache entries by removing pods
        pod_restart(kube_apis.v1, ns)
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

    @pytest.mark.parametrize("src", [cache_vs_advanced_spec_src, cache_vs_advanced_route_src])
    def test_cache_policy_advanced(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test cache policy advanced (GET/HEAD/POST) configured at spec and route level
        """

        pol_name = self.setup_cache_policy(kube_apis, test_namespace, cache_pol_advanced_src)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            test_namespace,
        )

        # Test cache behavior for GET requests
        resp_1 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_1 = resp_1.headers.get("X-Cache-Status")

        resp_2 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_2 = resp_2.headers.get("X-Cache-Status")

        # Test cache behavior for POST requests
        resp_3 = requests.post(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_3 = resp_3.headers.get("X-Cache-Status")

        # Test cache behavior for HEAD requests
        resp_4 = requests.head(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_4 = resp_4.headers.get("X-Cache-Status")

        # Extract Request IDs from response body (HEAD responses don't have body, use GET and POST)
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

        # Cleanup
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, test_namespace
        )

        ns = ingress_controller_prerequisites.namespace
        # Purge all existing cache entries by removing pods
        pod_restart(kube_apis.v1, ns)
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

    @pytest.mark.skip_for_nginx_oss
    def test_cache_policy_purge(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test cache policy purge
        """

        pol_name = self.setup_cache_policy(kube_apis, test_namespace, cache_pol_purge_src)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            cache_vs_purge_src,
            test_namespace,
        )

        # Test cache behavior for GET requests
        resp_1 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_1 = resp_1.headers.get("X-Cache-Status")

        resp_2 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_2 = resp_2.headers.get("X-Cache-Status")

        # Purge request to remove cached content
        # geo $purge_allowed_test_namespace_virtual_server_mycache {
        #    default 0;
        #    0.0.0.0/0 1;
        # }
        resp_purge = requests.request(
            "PURGE", virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host}
        )

        resp_3 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_3 = resp_3.headers.get("X-Cache-Status")

        resp_4 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        cache_status_4 = resp_4.headers.get("X-Cache-Status")

        # Extract Request IDs from response body (HEAD responses don't have body, use GET and POST)
        req_id_1 = re.search(r"Request ID: (\S+)", resp_1.text)
        req_id_2 = re.search(r"Request ID: (\S+)", resp_2.text)
        req_id_3 = re.search(r"Request ID: (\S+)", resp_3.text)
        req_id_4 = re.search(r"Request ID: (\S+)", resp_4.text)

        assert all(
            [
                resp_1.status_code == 200,
                resp_2.status_code == 200,
                resp_purge.status_code == 204,  # PURGE should return 204 No Content
                resp_3.status_code == 200,
                resp_4.status_code == 200,
                "Request ID:" in resp_1.text,
                "Request ID:" in resp_2.text,
                "Request ID:" in resp_3.text,
                "Request ID:" in resp_4.text,
                req_id_1.group(1) == req_id_2.group(1),
                req_id_3.group(1) == req_id_4.group(1),
                cache_status_1 == "MISS",
                cache_status_2 == "HIT",
                cache_status_3 == "MISS",  # after PURGE, should be MISS
                cache_status_4 == "HIT",
            ]
        )

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, test_namespace
        )
        ns = ingress_controller_prerequisites.namespace
        # Purge all existing cache entries by removing pods
        pod_restart(kube_apis.v1, ns)
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

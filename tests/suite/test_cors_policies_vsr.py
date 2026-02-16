import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import ensure_connection_to_public_endpoint, pod_restart, wait_before_test
from suite.utils.vs_vsr_resources_utils import delete_and_create_v_s_route_from_yaml, delete_and_create_vs_from_yaml

std_vsr_src = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
cors_pol_simple_src = f"{TEST_DATA}/cors/policies/cors-policy-simple.yaml"
cors_pol_wildcard_src = f"{TEST_DATA}/cors/policies/cors-policy-wildcard.yaml"
cors_vs_vsr_src = f"{TEST_DATA}/cors/vsr/virtual-server.yaml"
cors_vsr_simple_src = f"{TEST_DATA}/cors/vsr/virtual-server-route-cors-simple.yaml"
cors_vsr_wildcard_src = f"{TEST_DATA}/cors/vsr/virtual-server-route-cors-wildcard.yaml"


@pytest.mark.policies
@pytest.mark.policies_cors
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
class TestCORSPoliciesVSR:
    def setup_vs_cors_policy(self, kube_apis, namespace, policy_src, vs_name):
        print(f"Create CORS policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_src, namespace)
        print("Update Virtual Server")
        delete_and_create_vs_from_yaml(kube_apis.custom_objects, vs_name, cors_vs_vsr_src, namespace)
        wait_before_test()
        return pol_name

    def test_cors_policy_vsr_simple(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test CORS policy with simple exact origins applied to VirtualServerRoute subroute
        """

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        pol_name = self.setup_vs_cors_policy(
            kube_apis, v_s_route_setup.route_m.namespace, cors_pol_simple_src, v_s_route_setup.vs_name
        )

        print(f"VSR with simple CORS policy: {cors_vsr_simple_src}")
        delete_and_create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            cors_vsr_simple_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        # Test 1: Request from allowed origin on subroute
        resp_allowed = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "Origin": "https://example.com"},
        )
        print(f"Response from allowed origin: status={resp_allowed.status_code}, headers={resp_allowed.headers}")

        # Test 2: Request from disallowed origin on subroute
        resp_disallowed = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "Origin": "https://evil.com"},
        )
        print(
            f"Response from disallowed origin: status={resp_disallowed.status_code}, headers={resp_disallowed.headers}"
        )

        # Test 3: OPTIONS preflight request from allowed origin
        resp_options = requests.options(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={
                "host": v_s_route_setup.vs_host,
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        print(f"OPTIONS preflight response: status={resp_options.status_code}, headers={resp_options.headers}")

        # Test 4: Request to different subroute without CORS policy should not have CORS headers
        resp_no_cors = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            headers={"host": v_s_route_setup.vs_host, "Origin": "https://example.com"},
        )
        print(f"Response from subroute without CORS: status={resp_no_cors.status_code}, headers={resp_no_cors.headers}")

        # Assertions for allowed origin
        assert resp_allowed.status_code == 200
        assert resp_allowed.headers.get("Access-Control-Allow-Origin") == "https://example.com"
        assert "Vary" in resp_allowed.headers
        assert "Origin" in resp_allowed.headers.get("Vary", "")
        assert resp_allowed.headers.get("Access-Control-Allow-Methods") == "GET, POST, PUT"
        assert resp_allowed.headers.get("Access-Control-Allow-Headers") == "Content-Type, Authorization"
        assert resp_allowed.headers.get("Access-Control-Expose-Headers") == "X-Custom-Header"
        assert resp_allowed.headers.get("Access-Control-Allow-Credentials") == "true"
        assert resp_allowed.headers.get("Access-Control-Max-Age") == "3600"

        # Assertions for disallowed origin
        assert resp_disallowed.status_code == 200
        cors_origin = resp_disallowed.headers.get("Access-Control-Allow-Origin", "")
        assert cors_origin == "" or cors_origin is None

        # Assertions for OPTIONS preflight
        assert resp_options.status_code == 204
        assert resp_options.headers.get("Access-Control-Allow-Origin") == "https://app.example.com"
        assert resp_options.headers.get("Access-Control-Allow-Methods") == "GET, POST, PUT"

        # Assertions for subroute without CORS policy
        assert resp_no_cors.status_code == 200
        # Should not have CORS headers since policy is only on first subroute
        cors_origin_no_policy = resp_no_cors.headers.get("Access-Control-Allow-Origin", "")
        assert cors_origin_no_policy == "" or cors_origin_no_policy is None

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        delete_and_create_v_s_route_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.route_m.name, std_vsr_src, v_s_route_setup.route_m.namespace
        )

    def test_cors_policy_vsr_wildcard(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test CORS policy with wildcard origin patterns applied to VirtualServerRoute subroute
        """

        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        pol_name = self.setup_vs_cors_policy(
            kube_apis, v_s_route_setup.route_m.namespace, cors_pol_wildcard_src, v_s_route_setup.vs_name
        )

        print(f"VSR with wildcard CORS policy: {cors_vsr_wildcard_src}")
        delete_and_create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            cors_vsr_wildcard_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        # Test 1: Request from wildcard-matched subdomain
        resp_wildcard_match = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "Origin": "https://api.example.com"},
        )
        print(
            f"Response from wildcard match: status={resp_wildcard_match.status_code}, headers={resp_wildcard_match.headers}"
        )

        # Test 2: Request from another wildcard-matched subdomain
        resp_wildcard_match2 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "Origin": "https://app.example.com"},
        )
        print(
            f"Response from wildcard match 2: status={resp_wildcard_match2.status_code}, headers={resp_wildcard_match2.headers}"
        )

        # Test 3: Request from exact match (localhost)
        resp_exact_match = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "Origin": "http://localhost:3000"},
        )
        print(f"Response from exact match: status={resp_exact_match.status_code}, headers={resp_exact_match.headers}")

        # Test 4: Request from disallowed origin
        resp_disallowed = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "Origin": "https://evil.com"},
        )
        print(
            f"Response from disallowed origin: status={resp_disallowed.status_code}, headers={resp_disallowed.headers}"
        )

        # Test 5: Request from base domain (should not match *.example.com)
        resp_base_domain = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "Origin": "https://example.com"},
        )
        print(f"Response from base domain: status={resp_base_domain.status_code}, headers={resp_base_domain.headers}")

        # Test 6: OPTIONS preflight with wildcard match
        resp_options = requests.options(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={
                "host": v_s_route_setup.vs_host,
                "Origin": "https://test.example.com",
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        print(f"OPTIONS preflight response: status={resp_options.status_code}, headers={resp_options.headers}")

        # Test 7: Request to different subroute without CORS policy
        resp_no_cors = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[1]}",
            headers={"host": v_s_route_setup.vs_host, "Origin": "https://api.example.com"},
        )
        print(f"Response from subroute without CORS: status={resp_no_cors.status_code}, headers={resp_no_cors.headers}")

        # Assertions for wildcard matched origin
        assert resp_wildcard_match.status_code == 200
        assert resp_wildcard_match.headers.get("Access-Control-Allow-Origin") == "https://api.example.com"
        assert "Vary" in resp_wildcard_match.headers
        assert "Origin" in resp_wildcard_match.headers.get("Vary", "")
        assert resp_wildcard_match.headers.get("Access-Control-Allow-Methods") == "GET, POST, DELETE"
        assert (
            resp_wildcard_match.headers.get("Access-Control-Allow-Headers")
            == "Content-Type, Authorization, X-Custom-Header"
        )
        assert resp_wildcard_match.headers.get("Access-Control-Expose-Headers") == "X-Request-ID, X-Custom-Header"
        assert resp_wildcard_match.headers.get("Access-Control-Allow-Credentials") == "true"
        assert resp_wildcard_match.headers.get("Access-Control-Max-Age") == "7200"

        # Assertions for second wildcard match
        assert resp_wildcard_match2.status_code == 200
        assert resp_wildcard_match2.headers.get("Access-Control-Allow-Origin") == "https://app.example.com"

        # Assertions for exact match
        assert resp_exact_match.status_code == 200
        assert resp_exact_match.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"

        # Assertions for disallowed origin
        assert resp_disallowed.status_code == 200
        cors_origin = resp_disallowed.headers.get("Access-Control-Allow-Origin", "")
        assert cors_origin == "" or cors_origin is None

        # Assertions for base domain (should not match *.example.com)
        assert resp_base_domain.status_code == 200
        cors_origin_base = resp_base_domain.headers.get("Access-Control-Allow-Origin", "")
        assert cors_origin_base == "" or cors_origin_base is None

        # Assertions for OPTIONS with wildcard match
        assert resp_options.status_code == 204
        assert resp_options.headers.get("Access-Control-Allow-Origin") == "https://test.example.com"
        assert resp_options.headers.get("Access-Control-Allow-Methods") == "GET, POST, DELETE"

        # Assertions for subroute without CORS policy
        assert resp_no_cors.status_code == 200
        cors_origin_no_policy = resp_no_cors.headers.get("Access-Control-Allow-Origin", "")
        assert cors_origin_no_policy == "" or cors_origin_no_policy is None

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        delete_and_create_v_s_route_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.route_m.name, std_vsr_src, v_s_route_setup.route_m.namespace
        )

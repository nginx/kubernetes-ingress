import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import wait_before_test
from suite.utils.vs_vsr_resources_utils import delete_and_create_vs_from_yaml

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
cors_pol_simple_src = f"{TEST_DATA}/cors/policies/cors-policy-simple.yaml"
cors_pol_wildcard_src = f"{TEST_DATA}/cors/policies/cors-policy-wildcard.yaml"
cors_vs_simple_spec_src = f"{TEST_DATA}/cors/spec/virtual-server-cors-simple-spec.yaml"
cors_vs_wildcard_spec_src = f"{TEST_DATA}/cors/spec/virtual-server-cors-wildcard-spec.yaml"
cors_vs_simple_route_src = f"{TEST_DATA}/cors/route/virtual-server-cors-simple-route.yaml"
cors_vs_wildcard_route_src = f"{TEST_DATA}/cors/route/virtual-server-cors-wildcard-route.yaml"


@pytest.mark.policies
@pytest.mark.policies_cors
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [f"-enable-custom-resources", f"-enable-leader-election=false"],
            },
            {
                "example": "virtual-server",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestCORSPolicies:
    def setup_cors_policy(self, kube_apis, test_namespace, policy_src):
        print(f"Create CORS policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_src, test_namespace)
        wait_before_test()
        return pol_name

    @pytest.mark.parametrize("src", [cors_vs_simple_spec_src, cors_vs_simple_route_src])
    def test_cors_policy_simple(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test CORS policy with simple exact origins configured at spec and route level
        """

        pol_name = self.setup_cors_policy(kube_apis, test_namespace, cors_pol_simple_src)

        # Apply VS with simple CORS policy
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            test_namespace,
        )

        # Test 1: Request from allowed origin should receive CORS headers
        resp_allowed = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "Origin": "https://example.com"},
        )
        print(f"Response from allowed origin: status={resp_allowed.status_code}, headers={resp_allowed.headers}")

        # Test 2: Request from disallowed origin should not receive CORS headers or receive empty origin
        resp_disallowed = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "Origin": "https://evil.com"},
        )
        print(
            f"Response from disallowed origin: status={resp_disallowed.status_code}, headers={resp_disallowed.headers}"
        )

        # Test 3: OPTIONS preflight request from allowed origin
        resp_options = requests.options(
            virtual_server_setup.backend_1_url,
            headers={
                "host": virtual_server_setup.vs_host,
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        print(f"OPTIONS preflight response: status={resp_options.status_code}, headers={resp_options.headers}")

        # Test 4: Request without Origin header should work normally
        resp_no_origin = requests.get(
            virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host}
        )
        print(f"Response without Origin: status={resp_no_origin.status_code}")

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
        # Disallowed origin should either not have CORS header or have empty string
        cors_origin = resp_disallowed.headers.get("Access-Control-Allow-Origin", "")
        assert cors_origin == "" or cors_origin is None

        # Assertions for OPTIONS preflight
        assert resp_options.status_code == 204
        assert resp_options.headers.get("Access-Control-Allow-Origin") == "https://app.example.com"
        assert resp_options.headers.get("Access-Control-Allow-Methods") == "GET, POST, PUT"
        assert resp_options.headers.get("Access-Control-Allow-Headers") == "Content-Type, Authorization"

        # Assertions for no origin
        assert resp_no_origin.status_code == 200

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, test_namespace
        )

    @pytest.mark.parametrize("src", [cors_vs_wildcard_spec_src, cors_vs_wildcard_route_src])
    def test_cors_policy_wildcard(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test CORS policy with wildcard origin patterns configured at spec and route level
        """

        pol_name = self.setup_cors_policy(kube_apis, test_namespace, cors_pol_wildcard_src)

        # Apply VS with wildcard CORS policy
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            test_namespace,
        )

        # Test 1: Request from wildcard-matched subdomain should receive CORS headers with actual origin
        resp_wildcard_match = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "Origin": "https://api.example.com"},
        )
        print(
            f"Response from wildcard match: status={resp_wildcard_match.status_code}, headers={resp_wildcard_match.headers}"
        )

        # Test 2: Request from another wildcard-matched subdomain
        resp_wildcard_match2 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "Origin": "https://app.example.com"},
        )
        print(
            f"Response from wildcard match 2: status={resp_wildcard_match2.status_code}, headers={resp_wildcard_match2.headers}"
        )

        # Test 3: Request from exact match (localhost)
        resp_exact_match = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "Origin": "http://localhost:3000"},
        )
        print(f"Response from exact match: status={resp_exact_match.status_code}, headers={resp_exact_match.headers}")

        # Test 4: Request from disallowed origin (doesn't match wildcard or exact)
        resp_disallowed = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "Origin": "https://evil.com"},
        )
        print(
            f"Response from disallowed origin: status={resp_disallowed.status_code}, headers={resp_disallowed.headers}"
        )

        # Test 5: Request from base domain (should not match *.example.com)
        resp_base_domain = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "Origin": "https://example.com"},
        )
        print(f"Response from base domain: status={resp_base_domain.status_code}, headers={resp_base_domain.headers}")

        # Test 6: OPTIONS preflight with wildcard match
        resp_options = requests.options(
            virtual_server_setup.backend_1_url,
            headers={
                "host": virtual_server_setup.vs_host,
                "Origin": "https://test.example.com",
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        print(f"OPTIONS preflight response: status={resp_options.status_code}, headers={resp_options.headers}")
        # Assertions for wildcard matched origin
        assert resp_wildcard_match.status_code == 200
        # For wildcard patterns, nginx returns the actual origin from the request
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

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, test_namespace
        )

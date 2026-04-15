import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

cors_pol_simple_src = f"{TEST_DATA}/cors/policies/cors-policy-simple.yaml"
cors_pol_wildcard_src = f"{TEST_DATA}/cors/policies/cors-policy-wildcard.yaml"
cors_ingress_simple_src = f"{TEST_DATA}/cors/ingress/cors-policy-simple-ingress.yaml"
cors_ingress_wildcard_src = f"{TEST_DATA}/cors/ingress/cors-policy-wildcard-ingress.yaml"


@pytest.mark.policies
@pytest.mark.policies_cors
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        pytest.param(
            {
                "type": "complete",
                "extra_args": ["-enable-custom-resources", "-enable-leader-election=false"],
            }
        )
    ],
    indirect=["crd_ingress_controller"],
)
class TestCORSPoliciesIngress:
    def setup_cors_policy(self, kube_apis, test_namespace, policy_src):
        print("Create CORS policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_src, test_namespace)
        wait_before_test()
        return pol_name

    def test_cors_policy_simple_ingress(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
    ):
        """
        Validate CORS policy attachment to Ingress via nginx.org/policies annotation.
        """

        ingress_host = get_first_ingress_host_from_yaml(cors_ingress_simple_src)
        request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        create_items_from_yaml(kube_apis, cors_ingress_simple_src, test_namespace)

        pol_name = self.setup_cors_policy(kube_apis, test_namespace, cors_pol_simple_src)

        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )
        ensure_response_from_backend(request_url, ingress_host, check404=True)

        # Request from allowed origin should receive CORS headers.
        resp_allowed = requests.get(
            request_url,
            headers={"host": ingress_host, "Origin": "https://example.com"},
        )

        # Request from disallowed origin should not receive CORS headers or receive empty origin.
        resp_disallowed = requests.get(
            request_url,
            headers={"host": ingress_host, "Origin": "https://evil.com"},
        )
        print(
            f"Response from disallowed origin: status={resp_disallowed.status_code}, headers={resp_disallowed.headers}"
        )

        # OPTIONS preflight request from allowed origin
        resp_options = requests.options(
            request_url,
            headers={
                "host": ingress_host,
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        print(f"OPTIONS preflight response: status={resp_options.status_code}, headers={resp_options.headers}")

        # Request without Origin header should work normally.
        resp_no_origin = requests.get(request_url, headers={"host": ingress_host})
        print(f"Response without Origin: status={resp_no_origin.status_code}")

        assert resp_allowed.status_code == 200
        assert resp_allowed.headers.get("Access-Control-Allow-Origin") == "https://example.com"
        assert "Vary" in resp_allowed.headers
        assert "Origin" in resp_allowed.headers.get("Vary", "")
        assert resp_allowed.headers.get("Access-Control-Allow-Methods") == "GET, POST, PUT"
        assert resp_allowed.headers.get("Access-Control-Allow-Headers") == "Content-Type, Authorization"
        assert resp_allowed.headers.get("Access-Control-Expose-Headers") == "X-Custom-Header"
        assert resp_allowed.headers.get("Access-Control-Allow-Credentials") == "true"
        assert resp_allowed.headers.get("Access-Control-Max-Age") == "3600"

        assert resp_disallowed.status_code == 200
        # Disallowed origin should either not have CORS header or have empty string
        disallowed_origin = resp_disallowed.headers.get("Access-Control-Allow-Origin", "")
        assert disallowed_origin == "" or disallowed_origin is None

        assert resp_options.status_code == 204
        assert resp_options.headers.get("Access-Control-Allow-Origin") == "https://app.example.com"
        assert resp_options.headers.get("Access-Control-Allow-Methods") == "GET, POST, PUT"
        assert resp_options.headers.get("Access-Control-Allow-Headers") == "Content-Type, Authorization"

        assert resp_no_origin.status_code == 200

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_items_from_yaml(kube_apis, cors_ingress_simple_src, test_namespace)
        delete_common_app(kube_apis, "simple", test_namespace)

    def test_cors_policy_wildcard_ingress(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
    ):
        """
        Validate wildcard CORS policy attachment to Ingress via nginx.org/policies annotation.
        """

        ingress_host = get_first_ingress_host_from_yaml(cors_ingress_wildcard_src)
        request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        create_items_from_yaml(kube_apis, cors_ingress_wildcard_src, test_namespace)

        pol_name = self.setup_cors_policy(kube_apis, test_namespace, cors_pol_wildcard_src)

        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )
        ensure_response_from_backend(request_url, ingress_host, check404=True)

        # Test 1: Request from wildcard-matched subdomain should receive CORS headers with actual origin
        resp_wildcard_match = requests.get(
            request_url,
            headers={"host": ingress_host, "Origin": "https://api.example.com"},
        )
        print(
            f"Response from wildcard match: status={resp_wildcard_match.status_code}, headers={resp_wildcard_match.headers}"
        )

        # Test 2: Request from another wildcard-matched subdomain
        resp_wildcard_match2 = requests.get(
            request_url,
            headers={"host": ingress_host, "Origin": "https://app.example.com"},
        )
        print(
            f"Response from wildcard match 2: status={resp_wildcard_match2.status_code}, headers={resp_wildcard_match2.headers}"
        )

        # Test 3: Request from exact match (localhost)
        resp_exact_match = requests.get(
            request_url,
            headers={"host": ingress_host, "Origin": "http://localhost:3000"},
        )
        print(f"Response from exact match: status={resp_exact_match.status_code}, headers={resp_exact_match.headers}")

        # Test 4: Request from disallowed origin (doesn't match wildcard or exact)
        resp_disallowed = requests.get(
            request_url,
            headers={"host": ingress_host, "Origin": "https://evil.com"},
        )
        print(
            f"Response from disallowed origin: status={resp_disallowed.status_code}, headers={resp_disallowed.headers}"
        )

        # Test 5: Request from base domain (should not match *.example.com)
        resp_base_domain = requests.get(
            request_url,
            headers={"host": ingress_host, "Origin": "https://example.com"},
        )
        print(f"Response from base domain: status={resp_base_domain.status_code}, headers={resp_base_domain.headers}")

        # Test 6: OPTIONS preflight with wildcard match
        resp_options = requests.options(
            request_url,
            headers={
                "host": ingress_host,
                "Origin": "https://test.example.com",
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        print(f"OPTIONS preflight response: status={resp_options.status_code}, headers={resp_options.headers}")

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

        assert resp_wildcard_match2.status_code == 200
        assert resp_wildcard_match2.headers.get("Access-Control-Allow-Origin") == "https://app.example.com"

        assert resp_exact_match.status_code == 200
        assert resp_exact_match.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"

        assert resp_disallowed.status_code == 200
        disallowed_origin = resp_disallowed.headers.get("Access-Control-Allow-Origin", "")
        assert disallowed_origin == "" or disallowed_origin is None

        assert resp_base_domain.status_code == 200
        base_domain_origin = resp_base_domain.headers.get("Access-Control-Allow-Origin", "")
        assert base_domain_origin == "" or base_domain_origin is None

        assert resp_options.status_code == 204
        assert resp_options.headers.get("Access-Control-Allow-Origin") == "https://test.example.com"
        assert resp_options.headers.get("Access-Control-Allow-Methods") == "GET, POST, DELETE"

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_items_from_yaml(kube_apis, cors_ingress_wildcard_src, test_namespace)
        delete_common_app(kube_apis, "simple", test_namespace)

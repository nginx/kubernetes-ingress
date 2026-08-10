import pytest
import requests
from settings import TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml


class CustomHTTPErrorsSetup:
    """Encapsulate custom-http-errors example details.

    Attributes:
        public_endpoint: PublicEndpoint
        ingress_host: hostname used by the Ingress under test
        namespace: test namespace
        http_url: base HTTP URL of the Ingress Controller
    """

    def __init__(self, public_endpoint: PublicEndpoint, ingress_host, namespace):
        self.public_endpoint = public_endpoint
        self.ingress_host = ingress_host
        self.namespace = namespace
        self.http_url = f"http://{public_endpoint.public_ip}:{public_endpoint.port}"


@pytest.fixture(scope="class")
def custom_http_errors_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    ingress_controller,
    test_namespace,
) -> CustomHTTPErrorsSetup:
    """Deploy the custom-http-errors example (standard or mergeable) plus the shared 'simple' app and a dedicated error-pages Service."""
    ingress_src = f"{TEST_DATA}/custom-http-errors/{request.param}/custom-http-errors-ingress.yaml"
    error_pages_src = f"{TEST_DATA}/custom-http-errors/error-pages.yaml"
    print(
        f"------------------------- Deploy custom-http-errors example ({request.param}) -----------------------------------"
    )
    create_items_from_yaml(kube_apis, ingress_src, test_namespace)
    ingress_host = get_first_ingress_host_from_yaml(ingress_src)
    create_example_app(kube_apis, "simple", test_namespace)
    create_items_from_yaml(kube_apis, error_pages_src, test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )
    req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"
    ensure_response_from_backend(req_url, ingress_host, check404=True)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up the custom-http-errors example:")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(kube_apis, error_pages_src, test_namespace)
            delete_items_from_yaml(kube_apis, ingress_src, test_namespace)

    request.addfinalizer(fin)

    return CustomHTTPErrorsSetup(ingress_controller_endpoint, ingress_host, test_namespace)


@pytest.mark.ingresses
@pytest.mark.custom_http_errors
@pytest.mark.parametrize("custom_http_errors_setup", ["standard", "mergeable"], indirect=True)
class TestCustomHTTPErrors:
    """End-to-end coverage for the `nginx.org/custom-http-errors` annotation.
    The same behaviour is exercised for both entry points:
      - `standard`, annotation lives directly on a single Ingress.
      - `mergeable`, annotation lives on the master; the minion contributes /backend1 and /fail.
    """

    def test_annotation_intercepts_upstream_error(self, kube_apis, custom_http_errors_setup, test_namespace):
        """When the upstream returns a matching error status, NGINX intercepts the response,
        serves the body from spec.defaultBackend, and preserves the original upstream status code.

        /backend1 is served by backend1-svc (returns 200) and confirms that the annotation only
        intercepts matched error codes, not successful responses.
        /fail is served by fail-backend-svc (returns 502) and produces a genuine proxied 502
        response so that`error_page` fires.
        """

        headers = {"host": custom_http_errors_setup.ingress_host}
        backend_url = f"{custom_http_errors_setup.http_url}/backend1"
        fail_url = f"{custom_http_errors_setup.http_url}/fail"

        print("Successful upstream response is passed through unchanged (no interception)")
        resp = requests.get(backend_url, headers=headers)
        assert resp.status_code == 200, f"Expected 200 from backend1, got {resp.status_code}: {resp.text[:200]}"
        assert "Server name: backend1" in resp.text, f"Expected response body from backend1, got: {resp.text[:200]}"

        print("Upstream 502 is intercepted, body swapped for error-pages-svc, original code preserved")
        resp = requests.get(fail_url, headers=headers)

        assert resp.status_code == 502, f"Expected 502 from fail-backend-svc, got {resp.status_code}: {resp.text[:200]}"

        assert (
            "Something went wrong and the application is temporarily unavailable" in resp.text
        ), f"Expected error-pages-svc to serve the response body, got: {resp.text[:200]}"

        print("Sanity check: /backend1 still returns 200 from backend1 after the intercepted request")
        resp = requests.get(backend_url, headers=headers)
        assert (
            resp.status_code == 200
        ), f"Expected 200 from backend1 after the intercept path, got {resp.status_code}: {resp.text[:200]}"
        assert (
            "Server name: backend1" in resp.text
        ), f"Expected response body from backend1 (not intercepted), got: {resp.text[:200]}"

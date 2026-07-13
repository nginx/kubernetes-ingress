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
    scale_deployment,
    wait_before_test,
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
      - `mergeable`, annotation lives on the master; the minion contributes /backend1.
    """

    def test_annotation_intercepts_upstream_error(self, kube_apis, custom_http_errors_setup, test_namespace):
        """When the upstream returns a matching error status, NGINX intercepts the response,
        serves the body from spec.defaultBackend, and preserves the original upstream status code.
        """

        request_url = f"{custom_http_errors_setup.http_url}/backend1"
        headers = {"host": custom_http_errors_setup.ingress_host}

        print("Baseline: backend1 is up, /backend1 returns 200 from backend1")
        resp = requests.get(request_url, headers=headers)
        assert resp.status_code == 200, f"Expected 200 from backend1, got {resp.status_code}: {resp.text[:200]}"
        assert "Server name: backend1" in resp.text, f"Expected response body from backend1, got: {resp.text[:200]}"

        print("Scale backend1 to 0 so NGINX synthesizes 502 on the upstream call")
        original = scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", test_namespace, 0)
        try:
            wait_before_test()

            resp = requests.get(request_url, headers=headers)

            assert (
                resp.status_code == 502
            ), f"Expected 502 with backend1 down, got {resp.status_code}: {resp.text[:200]}"
            assert (
                "Something went wrong and the application is temporarily unavailable" in resp.text
            ), f"Expected error-pages-svc to serve the response body, got: {resp.text[:200]}"
            assert (
                "Server name:" not in resp.text
            ), f"Did not expect an app backend (backend1/backend2) in the response body, got: {resp.text[:200]}"

        finally:
            print("Restore backend1 replicas")
            scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", test_namespace, original)

        print("After restore: /backend1 returns 200 from backend1 again, no interception on success")
        wait_before_test()
        resp = requests.get(request_url, headers=headers)
        assert (
            resp.status_code == 200
        ), f"Expected 200 after backend1 restored, got {resp.status_code}: {resp.text[:200]}"
        assert (
            "Server name: backend1" in resp.text
        ), f"Expected response body from backend1 (not intercepted), got: {resp.text[:200]}"

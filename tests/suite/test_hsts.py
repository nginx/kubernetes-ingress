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
    generate_ingresses_with_annotation,
    replace_ingress,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml, get_name_from_yaml


class HSTSSetup:
    """Encapsulate HSTS example details.

    Attributes:
        public_endpoint: PublicEndpoint
        ingress_name:
        ingress_host:
        namespace: example namespace
    """

    def __init__(self, public_endpoint: PublicEndpoint, ingress_src_file, ingress_name, ingress_host, namespace):
        self.public_endpoint = public_endpoint
        self.ingress_name = ingress_name
        self.ingress_host = ingress_host
        self.ingress_src_file = ingress_src_file
        self.namespace = namespace
        self.https_url = f"https://{public_endpoint.public_ip}:{public_endpoint.port_ssl}"
        self.http_url = f"http://{public_endpoint.public_ip}:{public_endpoint.port}"


@pytest.fixture(scope="class")
def hsts_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    ingress_controller,
    test_namespace,
) -> HSTSSetup:
    print("------------------------- Deploy HSTS-Example -----------------------------------")
    if request.param in ["standard-tls", "mergeable-tls"]:
        create_items_from_yaml(kube_apis, f"{TEST_DATA}/hsts/{request.param}/tls-secret.yaml", test_namespace)
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/hsts/{request.param}/hsts-ingress.yaml", test_namespace)
    ingress_name = get_name_from_yaml(f"{TEST_DATA}/hsts/{request.param}/hsts-ingress.yaml")
    ingress_host = get_first_ingress_host_from_yaml(f"{TEST_DATA}/hsts/{request.param}/hsts-ingress.yaml")
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port, ingress_controller_endpoint.port_ssl
    )
    req_https_url = (
        f"https://{ingress_controller_endpoint.public_ip}:" f"{ingress_controller_endpoint.port_ssl}/backend1"
    )
    ensure_response_from_backend(req_https_url, ingress_host)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up HSTS Example:")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(kube_apis, f"{TEST_DATA}/hsts/{request.param}/hsts-ingress.yaml", test_namespace)
            if request.param in ["standard-tls", "mergeable-tls"]:
                delete_items_from_yaml(kube_apis, f"{TEST_DATA}/hsts/{request.param}/tls-secret.yaml", test_namespace)

    request.addfinalizer(fin)

    return HSTSSetup(
        ingress_controller_endpoint,
        f"{TEST_DATA}/hsts/{request.param}/hsts-ingress.yaml",
        ingress_name,
        ingress_host,
        test_namespace,
    )


@pytest.mark.ingresses
@pytest.mark.hsts
@pytest.mark.parametrize("hsts_setup", ["standard-tls", "mergeable-tls"], indirect=True)
class TestTLSHSTSFlows:
    def test_headers(self, kube_apis, hsts_setup, ingress_controller_prerequisites):
        print("\nCase 1: TLS enabled, secret is in place, hsts is True, hsts-behind-proxy is False")
        annotations = {"nginx.org/hsts-behind-proxy": "False"}
        new_ing = generate_ingresses_with_annotation(hsts_setup.ingress_src_file, annotations)
        for ing in new_ing:
            if ing["metadata"]["name"] == hsts_setup.ingress_name:
                replace_ingress(kube_apis.networking_v1, hsts_setup.ingress_name, hsts_setup.namespace, ing)
        wait_before_test(1)

        https_headers = {"host": hsts_setup.ingress_host}
        http_headers = {"host": hsts_setup.ingress_host}
        https_resp = requests.get(f"{hsts_setup.https_url}/backend1", headers=https_headers, verify=False)
        http_resp = requests.get(f"{hsts_setup.http_url}/backend1", headers=http_headers, allow_redirects=False)

        assert "'Strict-Transport-Security': 'max-age=2592000; preload'" in str(https_resp.headers)
        assert "'Strict-Transport-Security'" not in str(http_resp.headers)

        print("Case 3: TLS enabled, secret is in place, hsts is True, hsts-behind-proxy is True")
        annotations = {"nginx.org/hsts-behind-proxy": "True"}
        new_ing = generate_ingresses_with_annotation(hsts_setup.ingress_src_file, annotations)
        for ing in new_ing:
            if ing["metadata"]["name"] == hsts_setup.ingress_name:
                replace_ingress(kube_apis.networking_v1, hsts_setup.ingress_name, hsts_setup.namespace, ing)
        wait_before_test(1)

        xfp_https_headers = {"host": hsts_setup.ingress_host, "X-Forwarded-Proto": "https"}
        xfp_http_headers = {"host": hsts_setup.ingress_host, "X-Forwarded-Proto": "http"}
        xfp_https_resp = requests.get(f"{hsts_setup.https_url}/backend1", headers=xfp_https_headers, verify=False)
        xfp_http_resp = requests.get(f"{hsts_setup.https_url}/backend1", headers=xfp_http_headers, verify=False)

        assert "'Strict-Transport-Security': 'max-age=2592000; preload'" in str(xfp_https_resp.headers)
        assert "'Strict-Transport-Security'" not in str(xfp_http_resp.headers)


@pytest.mark.ingresses
@pytest.mark.hsts
@pytest.mark.parametrize("hsts_setup", ["tls-no-secret"], indirect=True)
class TestBrokenTLSHSTSFlows:
    def test_headers_without_secret(self, kube_apis, hsts_setup, ingress_controller_prerequisites):
        print("\nCase 2: TLS enabled, secret is NOT in place, hsts is True, hsts-behind-proxy is default (False)")
        https_headers = {"host": hsts_setup.ingress_host}
        http_headers = {"host": hsts_setup.ingress_host}
        https_resp = requests.get(f"{hsts_setup.https_url}/backend1", headers=https_headers, verify=False)
        http_resp = requests.get(f"{hsts_setup.http_url}/backend1", headers=http_headers, allow_redirects=False)

        assert "'Strict-Transport-Security': 'max-age=2592000; preload'" in str(https_resp.headers)
        assert "'Strict-Transport-Security'" not in str(http_resp.headers)


@pytest.mark.ingresses
@pytest.mark.hsts
@pytest.mark.parametrize("hsts_setup", ["standard", "mergeable"], indirect=True)
class TestNoTLSHSTS:
    def test_headers(self, kube_apis, hsts_setup, ingress_controller_prerequisites):
        print("Case 4: no TLS, hsts is True, hsts-behind-proxy is True")
        annotations = {"nginx.org/hsts-behind-proxy": "True"}
        new_ing = generate_ingresses_with_annotation(hsts_setup.ingress_src_file, annotations)
        for ing in new_ing:
            if ing["metadata"]["name"] == hsts_setup.ingress_name:
                replace_ingress(kube_apis.networking_v1, hsts_setup.ingress_name, hsts_setup.namespace, ing)
        wait_before_test(1)

        xfp_https_headers = {"host": hsts_setup.ingress_host, "X-Forwarded-Proto": "https"}
        xfp_http_headers = {"host": hsts_setup.ingress_host, "X-Forwarded-Proto": "http"}
        xfp_https_resp = requests.get(
            f"{hsts_setup.http_url}/backend1", headers=xfp_https_headers, allow_redirects=False
        )
        xfp_http_resp = requests.get(f"{hsts_setup.http_url}/backend1", headers=xfp_http_headers, allow_redirects=False)

        assert "'Strict-Transport-Security': 'max-age=2592000; preload'" in str(xfp_https_resp.headers)
        assert "'Strict-Transport-Security'" not in str(xfp_http_resp.headers)

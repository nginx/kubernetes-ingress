from ssl import SSLError

import pytest
import requests
from requests.exceptions import ConnectionError
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_secret_from_yaml,
    delete_secret,
    ensure_connection,
    is_secret_present,
    replace_secret,
    wait_before_test,
)
from suite.utils.ssl_utils import get_server_certificate_subject


def assert_cn(endpoint, cn):
    host = "random"  # any host would work
    subject_dict = get_server_certificate_subject(endpoint.public_ip, host, endpoint.port_ssl)
    assert subject_dict[b"CN"] == cn.encode("ascii")


def assert_unrecognized_name_error(endpoint):
    try:
        host = "random"  # any host would work
        get_server_certificate_subject(endpoint.public_ip, host, endpoint.port_ssl)
        pytest.fail("We expected an SSLError here, but didn't get it or got another error. Exiting...")
    except SSLError as e:
        assert "SSL" in e.library
        assert "TLSV1_UNRECOGNIZED_NAME" in e.reason


secret_path = f"{TEST_DATA}/common/default-server-secret.yaml"
test_data_path = f"{TEST_DATA}/default-server"
invalid_secret_path = f"{test_data_path}/invalid-tls-secret.yaml"
new_secret_path = f"{test_data_path}/new-tls-secret.yaml"
secret_name = "default-server-secret"
secret_namespace = "nginx-ingress"


@pytest.fixture(scope="class")
def default_server_setup(ingress_controller_endpoint, ingress_controller):
    ensure_connection(f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/")


@pytest.fixture(scope="class")
def default_server_setup_custom_port(ingress_controller_endpoint, ingress_controller):
    ensure_connection(f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.custom_http}/")
    ensure_connection(f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.custom_https}/")


@pytest.fixture(scope="class")
def secret_setup(request, kube_apis):
    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            if is_secret_present(kube_apis.v1, secret_name, secret_namespace):
                print("cleaning up secret!")
                delete_secret(kube_apis.v1, secret_name, secret_namespace)
                # restore the original secret created in ingress_controller_prerequisites fixture
                create_secret_from_yaml(kube_apis.v1, secret_namespace, secret_path)

    request.addfinalizer(fin)


@pytest.mark.ingresses
class TestDefaultServer:
    def test_with_default_tls_secret(self, kube_apis, ingress_controller_endpoint, secret_setup, default_server_setup):
        print("Step 1: ensure CN of the default server TLS cert")
        assert_cn(ingress_controller_endpoint, "NGINXIngressController")

        print("Step 2: ensure CN of the default server TLS cert after removing the secret")
        delete_secret(kube_apis.v1, secret_name, secret_namespace)
        wait_before_test(1)
        # Ingress Controller retains the previous valid secret
        assert_cn(ingress_controller_endpoint, "NGINXIngressController")

        print("Step 3: ensure CN of the default TLS cert after creating an updated secret")
        create_secret_from_yaml(kube_apis.v1, secret_namespace, new_secret_path)
        wait_before_test(1)
        assert_cn(ingress_controller_endpoint, "cafe.example.com")

        print("Step 4: ensure CN of the default TLS cert after making the secret invalid")
        replace_secret(kube_apis.v1, secret_name, secret_namespace, invalid_secret_path)
        wait_before_test(1)
        # Ingress Controller retains the previous valid secret
        assert_cn(ingress_controller_endpoint, "cafe.example.com")

        print("Step 5: ensure CN of the default TLS cert after restoring the secret")
        replace_secret(kube_apis.v1, secret_name, secret_namespace, secret_path)
        wait_before_test(1)
        assert_cn(ingress_controller_endpoint, "NGINXIngressController")

    @pytest.mark.parametrize(
        "ingress_controller",
        [
            pytest.param(
                {"extra_args": ["-default-server-tls-secret="]},
            ),
        ],
        indirect=True,
    )
    def test_without_default_tls_secret(self, ingress_controller_endpoint, default_server_setup):
        print("Ensure connection to HTTPS cannot be established")
        assert_unrecognized_name_error(ingress_controller_endpoint)

    @pytest.mark.parametrize(
        "ingress_controller",
        [
            pytest.param(
                {"extra_args": [f"-default-http-listener-port=8085", f"-default-https-listener-port=8445"]},
            ),
        ],
        indirect=True,
    )
    def test_disable_default_listeners_true(self, ingress_controller_endpoint, ingress_controller):
        print("Ensure ports 80 and 443 return result in an ERR_CONNECTION_REFUSED")
        request_url_80 = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/"
        with pytest.raises(ConnectionError, match="Connection refused") as e:
            requests.get(request_url_80, headers={})

        request_url_443 = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/"
        with pytest.raises(ConnectionError, match="Connection refused") as e:
            requests.get(request_url_443, headers={}, verify=False)

    @pytest.mark.parametrize(
        "ingress_controller",
        [
            pytest.param(
                {"extra_args": [f"-default-http-listener-port=8085", f"-default-https-listener-port=8445"]},
            ),
        ],
        indirect=True,
    )
    def test_custom_default_listeners(
        self, kube_apis, ingress_controller_endpoint, ingress_controller, default_server_setup_custom_port
    ):
        print("Ensure custom ports for default listeners return 404")
        request_url_http = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.custom_http}/"
        resp = requests.get(request_url_http, headers={})
        assert resp.status_code == 404

        request_url_https = (
            f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.custom_https}/"
        )
        resp = requests.get(request_url_https, headers={}, verify=False)
        assert resp.status_code == 404

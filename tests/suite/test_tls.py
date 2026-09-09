from _ssl import SSLError

import pytest
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_ingress_from_yaml,
    create_secret_from_yaml,
    delete_items_from_yaml,
    delete_secret,
    ensure_connection_to_public_endpoint,
    get_reload_count,
    is_secret_present,
    replace_secret,
    wait_before_test,
)
from suite.utils.ssl_utils import get_server_certificate_subject
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml, get_name_from_yaml


def assert_unrecognized_name_error(endpoint, host):
    try:
        get_server_certificate_subject(endpoint.public_ip, host, endpoint.port_ssl)
        pytest.fail("We expected an SSLError here, but didn't get it or got another error. Exiting...")
    except SSLError as e:
        assert "SSL" in e.library
        assert "TLSV1_UNRECOGNIZED_NAME" in e.reason


def assert_us_subject(endpoint, host):
    subject_dict = get_server_certificate_subject(endpoint.public_ip, host, endpoint.port_ssl)

    assert subject_dict[b"C"] == b"US"
    assert subject_dict[b"ST"] == b"CA"
    assert subject_dict[b"O"] == b"Internet Widgits Pty Ltd"
    assert subject_dict[b"CN"] == b"cafe.example.com"


def assert_gb_subject(endpoint, host):
    subject_dict = get_server_certificate_subject(endpoint.public_ip, host, endpoint.port_ssl)

    assert subject_dict[b"C"] == b"GB"
    assert subject_dict[b"ST"] == b"Cambridgeshire"
    assert subject_dict[b"O"] == b"nginx"
    assert subject_dict[b"CN"] == b"cafe.example.com"


class TLSSetup:
    def __init__(self, ingress_host, secret_name, secret_path, new_secret_path, invalid_secret_path, metrics_url):
        self.ingress_host = ingress_host
        self.secret_name = secret_name
        self.secret_path = secret_path
        self.new_secret_path = new_secret_path
        self.invalid_secret_path = invalid_secret_path
        self.metrics_url = metrics_url


@pytest.fixture(scope="class")
def tls_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    ingress_controller,
    test_namespace,
) -> TLSSetup:
    print("------------------------- Deploy TLS setup -----------------------------------")

    test_data_path = f"{TEST_DATA}/tls"
    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"

    ingress_path = f"{test_data_path}/{request.param}/ingress.yaml"
    create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_path)
    wait_before_test(1)

    ingress_host = get_first_ingress_host_from_yaml(ingress_path)
    secret_name = get_name_from_yaml(f"{test_data_path}/tls-secret.yaml")

    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port, ingress_controller_endpoint.port_ssl
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up TLS setup")
            delete_items_from_yaml(kube_apis, ingress_path, test_namespace)
            if is_secret_present(kube_apis.v1, secret_name, test_namespace):
                delete_secret(kube_apis.v1, secret_name, test_namespace)

    request.addfinalizer(fin)

    return TLSSetup(
        ingress_host,
        secret_name,
        f"{test_data_path}/tls-secret.yaml",
        f"{test_data_path}/new-tls-secret.yaml",
        f"{test_data_path}/invalid-tls-secret.yaml",
        metrics_url,
    )


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller, tls_setup",
    [
        pytest.param({"extra_args": ["-enable-prometheus-metrics", "-ssl-dynamic-reload=false"]}, "standard"),
        pytest.param({"extra_args": ["-enable-prometheus-metrics", "-ssl-dynamic-reload=false"]}, "mergeable"),
    ],
    indirect=True,
)
class TestIngressTLS:
    def test_tls_termination(self, kube_apis, ingress_controller_endpoint, test_namespace, tls_setup):
        print("Step 1: no secret")
        assert_unrecognized_name_error(ingress_controller_endpoint, tls_setup.ingress_host)

        print("Step 2: deploy secret and check")
        create_secret_from_yaml(kube_apis.v1, test_namespace, tls_setup.secret_path)
        wait_before_test(1)
        assert_us_subject(ingress_controller_endpoint, tls_setup.ingress_host)

        print("Step 3: remove secret and check")
        delete_secret(kube_apis.v1, tls_setup.secret_name, test_namespace)
        wait_before_test(1)
        assert_unrecognized_name_error(ingress_controller_endpoint, tls_setup.ingress_host)

        print("Step 4: restore secret and check")
        create_secret_from_yaml(kube_apis.v1, test_namespace, tls_setup.secret_path)
        wait_before_test(1)
        assert_us_subject(ingress_controller_endpoint, tls_setup.ingress_host)

        print("Step 5: deploy invalid secret and check")
        delete_secret(kube_apis.v1, tls_setup.secret_name, test_namespace)
        create_secret_from_yaml(kube_apis.v1, test_namespace, tls_setup.invalid_secret_path)
        wait_before_test(1)
        assert_unrecognized_name_error(ingress_controller_endpoint, tls_setup.ingress_host)

        print("Step 6: restore secret and check")
        delete_secret(kube_apis.v1, tls_setup.secret_name, test_namespace)
        create_secret_from_yaml(kube_apis.v1, test_namespace, tls_setup.secret_path)
        wait_before_test(1)
        assert_us_subject(ingress_controller_endpoint, tls_setup.ingress_host)

        # with -ssl-dynamic-reload=false, we expect
        # replacing a secret to trigger a reload
        count_before_replace = get_reload_count(tls_setup.metrics_url)

        print("Step 7: update secret and check")
        replace_secret(kube_apis.v1, tls_setup.secret_name, test_namespace, tls_setup.new_secret_path)
        wait_before_test(1)
        assert_gb_subject(ingress_controller_endpoint, tls_setup.ingress_host)

        count_after = get_reload_count(tls_setup.metrics_url)
        reloads = count_after - count_before_replace
        expected_reloads = 1
        assert reloads == expected_reloads, f"expected {expected_reloads} reloads, got {reloads}"


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller, tls_setup",
    [
        pytest.param({"extra_args": ["-enable-prometheus-metrics"]}, "standard"),
        pytest.param({"extra_args": ["-enable-prometheus-metrics"]}, "mergeable"),
    ],
    indirect=True,
)
class TestIngressTLSDynamicReloads:
    def test_tls_termination(self, kube_apis, ingress_controller_endpoint, test_namespace, tls_setup):
        print("Step 1: no secret")
        assert_unrecognized_name_error(ingress_controller_endpoint, tls_setup.ingress_host)

        print("Step 2: deploy secret and check")
        create_secret_from_yaml(kube_apis.v1, test_namespace, tls_setup.secret_path)
        wait_before_test(1)
        assert_us_subject(ingress_controller_endpoint, tls_setup.ingress_host)

        # for Plus with -ssl-dynamic-reload=true, we expect
        # replacing a secret not to trigger a reload
        count_before_replace = get_reload_count(tls_setup.metrics_url)

        print("Step 3: update secret and check")
        replace_secret(kube_apis.v1, tls_setup.secret_name, test_namespace, tls_setup.new_secret_path)
        wait_before_test(1)
        assert_gb_subject(ingress_controller_endpoint, tls_setup.ingress_host)

        count_after = get_reload_count(tls_setup.metrics_url)
        reloads = count_after - count_before_replace
        expected_reloads = 0
        assert reloads == expected_reloads, f"expected {expected_reloads} reloads, got {reloads}"

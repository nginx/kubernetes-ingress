from _ssl import SSLError

import pytest
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_secret_from_yaml,
    delete_secret,
    get_reload_count,
    is_secret_present,
    replace_secret,
    wait_before_test,
)
from suite.utils.ssl_utils import get_server_certificate_subject
from suite.utils.yaml_utils import get_name_from_yaml


@pytest.fixture(scope="class")
def clean_up(request, kube_apis, test_namespace) -> None:
    """
    Clean up test data.

    :param request: internal pytest fixture
    :param kube_apis: client apis
    :param test_namespace: str
    :return:
    """
    secret_name = get_name_from_yaml(f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up after test:")
            if is_secret_present(kube_apis.v1, secret_name, test_namespace):
                delete_secret(kube_apis.v1, secret_name, test_namespace)

    request.addfinalizer(fin)


def assert_unrecognized_name_error(virtual_server_setup):
    try:
        get_server_certificate_subject(
            virtual_server_setup.public_endpoint.public_ip,
            virtual_server_setup.vs_host,
            virtual_server_setup.public_endpoint.port_ssl,
        )
        pytest.fail("We expected an SSLError here, but didn't get it or got another error. Exiting...")
    except SSLError as e:
        assert "SSL" in e.library
        assert "TLSV1_UNRECOGNIZED_NAME" in e.reason


def assert_us_subject(virtual_server_setup):
    subject_dict = get_server_certificate_subject(
        virtual_server_setup.public_endpoint.public_ip,
        virtual_server_setup.vs_host,
        virtual_server_setup.public_endpoint.port_ssl,
    )
    assert subject_dict[b"C"] == b"US"
    assert subject_dict[b"ST"] == b"CA"
    assert subject_dict[b"O"] == b"Internet Widgits Pty Ltd"
    assert subject_dict[b"CN"] == b"cafe.example.com"


def assert_gb_subject(virtual_server_setup):
    subject_dict = get_server_certificate_subject(
        virtual_server_setup.public_endpoint.public_ip,
        virtual_server_setup.vs_host,
        virtual_server_setup.public_endpoint.port_ssl,
    )
    assert subject_dict[b"C"] == b"GB"
    assert subject_dict[b"ST"] == b"Cambridgeshire"
    assert subject_dict[b"O"] == b"nginx"
    assert subject_dict[b"CN"] == b"cafe.example.com"


@pytest.mark.vs
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-prometheus-metrics",
                    f"-ssl-dynamic-reload=false",
                ],
            },
            {"example": "virtual-server-tls", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVirtualServerTLS:
    def test_tls_termination(self, kube_apis, crd_ingress_controller, virtual_server_setup, clean_up):
        print("\nStep 1: no secret")
        assert_unrecognized_name_error(virtual_server_setup)

        print("\nStep 2: deploy secret and check")
        secret_name = create_secret_from_yaml(
            kube_apis.v1, virtual_server_setup.namespace, f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
        )
        wait_before_test(1)
        assert_us_subject(virtual_server_setup)

        print("\nStep 3: remove secret and check")
        delete_secret(kube_apis.v1, secret_name, virtual_server_setup.namespace)
        wait_before_test(1)
        assert_unrecognized_name_error(virtual_server_setup)

        print("\nStep 4: restore secret and check")
        create_secret_from_yaml(
            kube_apis.v1, virtual_server_setup.namespace, f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
        )
        wait_before_test(1)
        assert_us_subject(virtual_server_setup)

        print("\nStep 5: deploy invalid secret and check")
        delete_secret(kube_apis.v1, secret_name, virtual_server_setup.namespace)
        create_secret_from_yaml(
            kube_apis.v1, virtual_server_setup.namespace, f"{TEST_DATA}/virtual-server-tls/invalid-tls-secret.yaml"
        )
        wait_before_test(1)
        assert_unrecognized_name_error(virtual_server_setup)

        print("\nStep 6: restore secret and check")
        delete_secret(kube_apis.v1, secret_name, virtual_server_setup.namespace)
        create_secret_from_yaml(
            kube_apis.v1, virtual_server_setup.namespace, f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
        )
        wait_before_test(1)
        assert_us_subject(virtual_server_setup)

        # with -ssl-dynamic-reload=false, we expect
        # replacing a secret to trigger a reload
        count_before_replace = get_reload_count(virtual_server_setup.metrics_url)

        print("\nStep 7: update secret and check")
        replace_secret(
            kube_apis.v1,
            secret_name,
            virtual_server_setup.namespace,
            f"{TEST_DATA}/virtual-server-tls/new-tls-secret.yaml",
        )
        wait_before_test(1)
        assert_gb_subject(virtual_server_setup)

        count_after = get_reload_count(virtual_server_setup.metrics_url)
        reloads = count_after - count_before_replace
        expected_reloads = 1
        assert reloads == expected_reloads, f"expected {expected_reloads} reloads, got {reloads}"


@pytest.mark.vs
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-prometheus-metrics",
                ],
            },
            {"example": "virtual-server-tls", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVirtualServerTLSDynamicReloads:
    def test_tls_termination(self, kube_apis, crd_ingress_controller, virtual_server_setup, clean_up):
        print("\nStep 1: no secret")
        assert_unrecognized_name_error(virtual_server_setup)

        print("\nStep 2: deploy secret and check")
        secret_name = create_secret_from_yaml(
            kube_apis.v1, virtual_server_setup.namespace, f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
        )
        wait_before_test(1)
        assert_us_subject(virtual_server_setup)

        # for Plus with -ssl-dynamic-reload=true, we expect
        # replacing a secret not to trigger a reload
        count_before_replace = get_reload_count(virtual_server_setup.metrics_url)

        print("\nStep 3: update secret and check")
        replace_secret(
            kube_apis.v1,
            secret_name,
            virtual_server_setup.namespace,
            f"{TEST_DATA}/virtual-server-tls/new-tls-secret.yaml",
        )
        wait_before_test(1)
        assert_gb_subject(virtual_server_setup)

        count_after = get_reload_count(virtual_server_setup.metrics_url)
        reloads = count_after - count_before_replace
        expected_reloads = 0
        assert reloads == expected_reloads, f"expected {expected_reloads} reloads, got {reloads}"

import pytest
from settings import TEST_DATA
from suite.utils.custom_assertions import wait_and_assert_status_code
from suite.utils.resources_utils import (
    create_secret_from_yaml,
    is_secret_present,
    patch_namespace_with_label,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import patch_virtual_server_from_yaml
from suite.utils.yaml_utils import get_secret_name_from_vs_or_ts_yaml


@pytest.mark.vs
@pytest.mark.vs_certmanager
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller, create_certmanager, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources", f"-enable-cert-manager"]},
            {"issuer_name": "self-signed"},
            {"example": "virtual-server-certmanager", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestCertManagerVirtualServer:
    def test_responses_after_setup(self, kube_apis, crd_ingress_controller, create_certmanager, virtual_server_setup):
        print("\nStep 1: Verify secret exists")
        secret_name = get_secret_name_from_vs_or_ts_yaml(
            f"{TEST_DATA}/virtual-server-certmanager/standard/virtual-server.yaml"
        )
        retry = 0
        found = False
        while retry <= 30:
            if is_secret_present(kube_apis.v1, secret_name, virtual_server_setup.namespace):
                found = True
                break
            wait_before_test(5)
            retry += 1
            print(f"Retrying {retry}")
        assert found, f"Secret {secret_name} was not found in namespace {virtual_server_setup.namespace}"

        print("\nStep 2: verify connectivity")
        wait_and_assert_status_code(
            200, virtual_server_setup.backend_1_url_ssl, virtual_server_setup.vs_host, verify=False
        )
        wait_and_assert_status_code(
            200, virtual_server_setup.backend_2_url_ssl, virtual_server_setup.vs_host, verify=False
        )


@pytest.mark.vs
@pytest.mark.vs_certmanager
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller, create_certmanager, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources", f"-enable-cert-manager"]},
            {"issuer_name": "ca-issuer"},
            {"example": "virtual-server-certmanager", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestCertManagerVirtualServerCA:
    def test_responses_after_setup(self, kube_apis, crd_ingress_controller, create_certmanager, virtual_server_setup):
        vs_src = f"{TEST_DATA}/virtual-server-certmanager/virtual-server-updated.yaml"
        print("\nStep 1: Verify no secret exists with bad issuer name")
        secret_name = get_secret_name_from_vs_or_ts_yaml(
            f"{TEST_DATA}/virtual-server-certmanager/standard/virtual-server.yaml"
        )
        sec = is_secret_present(kube_apis.v1, secret_name, virtual_server_setup.namespace)
        assert sec is False
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, vs_src, virtual_server_setup.namespace
        )
        print("\nStep 2: Verify secret exists with updated issuer name")
        secret_name = get_secret_name_from_vs_or_ts_yaml(
            f"{TEST_DATA}/virtual-server-certmanager/virtual-server-updated.yaml"
        )

        retry = 0
        found = False
        while retry <= 30:
            if is_secret_present(kube_apis.v1, secret_name, virtual_server_setup.namespace):
                found = True
                break
            wait_before_test(5)
            retry += 1
            print(f"Retrying {retry}")
        assert found, f"Secret {secret_name} was not found in namespace {virtual_server_setup.namespace}"

        print("\nStep 3: verify connectivity")
        wait_and_assert_status_code(
            200, virtual_server_setup.backend_1_url_ssl, virtual_server_setup.vs_host, verify=False
        )
        wait_and_assert_status_code(
            200, virtual_server_setup.backend_2_url_ssl, virtual_server_setup.vs_host, verify=False
        )

    def test_virtual_server_no_cm(self, kube_apis, crd_ingress_controller, create_certmanager, virtual_server_setup):
        vs_src = f"{TEST_DATA}/virtual-server-certmanager/virtual-server-no-tls.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, vs_src, virtual_server_setup.namespace
        )
        print("\nStep 1: verify connectivity with no TLS block")
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

        print("\nStep 2: verify connectivity with TLS block but no cert-manager")
        vs_src = f"{TEST_DATA}/virtual-server-certmanager/virtual-server-no-cm.yaml"
        secret_src = f"{TEST_DATA}/virtual-server-certmanager/tls-secret.yaml"
        create_secret_from_yaml(kube_apis.v1, virtual_server_setup.namespace, secret_src)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, vs_src, virtual_server_setup.namespace
        )
        wait_and_assert_status_code(
            200, virtual_server_setup.backend_1_url_ssl, virtual_server_setup.vs_host, verify=False
        )
        wait_and_assert_status_code(
            200, virtual_server_setup.backend_2_url_ssl, virtual_server_setup.vs_host, verify=False
        )


@pytest.mark.vs
@pytest.mark.vs_certmanager
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller, create_certmanager, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-cert-manager",
                    f"-watch-namespace-label=app=watch",
                ],
            },
            {"issuer_name": "self-signed"},
            {"example": "virtual-server-certmanager", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestCertManagerVirtualServerWatchLabel:
    def test_responses_after_setup(
        self, kube_apis, crd_ingress_controller, create_certmanager, virtual_server_setup, test_namespace
    ):
        print("\nStep 1: Not watching namespace - verify secret does not exist")
        secret_name = get_secret_name_from_vs_or_ts_yaml(
            f"{TEST_DATA}/virtual-server-certmanager/standard/virtual-server.yaml"
        )
        # add a wait to avoid a false negative
        wait_before_test(10)
        check = is_secret_present(kube_apis.v1, secret_name, virtual_server_setup.namespace)
        assert check == False

        print("\nStep 2: Add label to namespace - Verify secret exists now")
        patch_namespace_with_label(kube_apis.v1, test_namespace, "watch", f"{TEST_DATA}/common/ns-patch.yaml")
        wait_before_test()
        secret_name = get_secret_name_from_vs_or_ts_yaml(
            f"{TEST_DATA}/virtual-server-certmanager/standard/virtual-server.yaml"
        )
        retry = 0
        found = False
        while retry <= 30:
            if is_secret_present(kube_apis.v1, secret_name, virtual_server_setup.namespace):
                found = True
                break
            wait_before_test(5)
            retry += 1
            print(f"Retrying {retry}")
        assert found, f"Secret {secret_name} was not found in namespace {virtual_server_setup.namespace}"

        print("\nStep 2: verify connectivity")
        wait_and_assert_status_code(
            200, virtual_server_setup.backend_1_url_ssl, virtual_server_setup.vs_host, verify=False
        )
        wait_and_assert_status_code(
            200, virtual_server_setup.backend_2_url_ssl, virtual_server_setup.vs_host, verify=False
        )

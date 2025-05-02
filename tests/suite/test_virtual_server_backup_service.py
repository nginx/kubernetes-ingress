import pytest
import requests
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_deployment_with_name,
    create_namespace_with_name_from_yaml,
    create_service_from_yaml,
    create_service_with_name,
    delete_namespace,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    get_first_pod_name,
    get_vs_nginx_template_conf,
    replace_configmap,
    replace_configmap_from_yaml,
    scale_deployment,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import delete_and_create_vs_from_yaml


def make_request(url, host):
    return requests.get(
        url,
        headers={"host": host},
        allow_redirects=False,
        verify=False,
    )


def get_result_in_conf_with_retry(
    kube_apis_v1, expected_conf_line, external_host, vs_name, vs_namespace, ic_pod_name, ic_pod_namespace
):
    retry = 0
    result_conf = ""
    while (expected_conf_line not in result_conf) and retry < 5:
        wait_before_test()
        result_conf = get_vs_nginx_template_conf(
            kube_apis_v1,
            vs_namespace,
            vs_name,
            ic_pod_name,
            ic_pod_namespace,
        )
        retry = retry + 1
    return result_conf


class ExternalNameSetup:
    """Encapsulate ExternalName example details.

    Attributes:
        ic_pod_name:
        external_host: external service host
    """

    def __init__(self, ic_pod_name, external_svc, external_host):
        self.ic_pod_name = ic_pod_name
        self.external_svc = external_svc
        self.external_host = external_host


@pytest.fixture(scope="class")
def vs_externalname_setup(
    request, kube_apis, ingress_controller_prerequisites, virtual_server_setup
) -> ExternalNameSetup:
    print("------------------------- Deploy External-Backend -----------------------------------")
    external_ns = create_namespace_with_name_from_yaml(kube_apis.v1, "external-ns", f"{TEST_DATA}/common/ns.yaml")
    external_svc_name = create_service_with_name(kube_apis.v1, external_ns, "external-backend-svc")
    create_deployment_with_name(kube_apis.apps_v1_api, external_ns, "external-backend")
    print("------------------------- Prepare ExternalName Setup -----------------------------------")
    external_svc_src = f"{TEST_DATA}/virtual-server-backup-service/backup-svc.yaml"
    external_svc_host = f"{external_svc_name}.{external_ns}.svc.cluster.local"
    config_map_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
    replace_configmap_from_yaml(
        kube_apis.v1,
        config_map_name,
        ingress_controller_prerequisites.namespace,
        f"{TEST_DATA}/virtual-server-backup-service/nginx-config.yaml",
    )
    external_svc = create_service_from_yaml(kube_apis.v1, virtual_server_setup.namespace, external_svc_src)
    wait_before_test(2)
    ensure_connection_to_public_endpoint(
        virtual_server_setup.public_endpoint.public_ip,
        virtual_server_setup.public_endpoint.port,
        virtual_server_setup.public_endpoint.port_ssl,
    )
    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
    ensure_response_from_backend(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("\nClean up ExternalName Setup:")
            delete_namespace(kube_apis.v1, external_ns)
            replace_configmap(
                kube_apis.v1,
                config_map_name,
                ingress_controller_prerequisites.namespace,
                ingress_controller_prerequisites.config_map,
            )

    request.addfinalizer(fin)

    return ExternalNameSetup(ic_pod_name, external_svc, external_svc_host)


@pytest.mark.vs
@pytest.mark.vs_backup
@pytest.mark.skip_for_nginx_oss
@pytest.mark.skip(reason="issue with VS config")
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-log-level=debug",
                ],
            },
            {
                "example": "virtual-server-backup-service",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestVirtualServerWithBackupService:
    """
    This test validates that we still get a response back from the default
    service, and not the backup service, as long as the default service is still available
    """

    def test_get_response_from_application(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        vs_externalname_setup,
    ) -> None:
        vs_backup_service = f"{TEST_DATA}/virtual-server-backup-service/virtual-server-backup.yaml"
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_backup_service,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        print("\nStep 1: Get response from VS with backup service")
        print(virtual_server_setup.backend_1_url + "\n")
        res = make_request(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
        )

        assert res.status_code == 200
        assert "backend1-" in res.text
        assert "external-backend" not in res.text

        expected_conf_line = f"server {vs_externalname_setup.external_host}:80 backup resolve;"
        result_conf = get_result_in_conf_with_retry(
            kube_apis.v1,
            expected_conf_line,
            vs_externalname_setup.external_host,
            virtual_server_setup.vs_name,
            virtual_server_setup.namespace,
            vs_externalname_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert "least_conn;" in result_conf
        assert expected_conf_line in result_conf

    """
    This test validates that we get a response back from the backup service.
    This test also scales the application back to 2 replicas after confirming a response from the backup service.
    """

    def test_get_response_from_backup(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        vs_externalname_setup,
    ) -> None:
        vs_backup_service = f"{TEST_DATA}/virtual-server-backup-service/virtual-server-backup.yaml"
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_backup_service,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        print("\nStep 1: Get response from VS with backup service")
        print(virtual_server_setup.backend_1_url + "\n")
        res = make_request(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
        )

        assert res.status_code == 200
        assert "backend1-" in res.text
        assert "external-backend" not in res.text

        expected_conf_line = f"server {vs_externalname_setup.external_host}:80 backup resolve;"
        result_conf = get_result_in_conf_with_retry(
            kube_apis.v1,
            expected_conf_line,
            vs_externalname_setup.external_host,
            virtual_server_setup.vs_name,
            virtual_server_setup.namespace,
            vs_externalname_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert "least_conn;" in result_conf
        assert expected_conf_line in result_conf

        print("\nStep 2: Scale deployment to zero replicas")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", virtual_server_setup.namespace, 0)
        wait_before_test()

        print("\nStep 3: Get response from backup service")
        res_from_backup = make_request(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
        )

        assert res_from_backup.status_code == 200
        assert "external-backend" in res_from_backup.text
        assert "backend1-" not in res_from_backup.text

        result_conf = get_result_in_conf_with_retry(
            kube_apis.v1,
            expected_conf_line,
            vs_externalname_setup.external_host,
            virtual_server_setup.vs_name,
            virtual_server_setup.namespace,
            vs_externalname_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert "least_conn;" in result_conf
        assert expected_conf_line in result_conf

        print("\nStep 4: Scale deployment back to 2 replicas")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", virtual_server_setup.namespace, 2)
        wait_before_test()

        print("\nStep 5: Get response")
        res_after_scaleup = make_request(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
        )

        assert res_after_scaleup.status_code == 200
        assert "external-backend" not in res_after_scaleup.text
        assert "backend1-" in res_after_scaleup.text

        result_conf = get_result_in_conf_with_retry(
            kube_apis.v1,
            expected_conf_line,
            vs_externalname_setup.external_host,
            virtual_server_setup.vs_name,
            virtual_server_setup.namespace,
            vs_externalname_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert "least_conn;" in result_conf
        assert expected_conf_line in result_conf

    """
    This test validates that getting an error response after deleting the backup service.
    """

    def test_delete_backup_service(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        vs_externalname_setup,
    ) -> None:
        vs_backup_service = f"{TEST_DATA}/virtual-server-backup-service/virtual-server-backup.yaml"
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_backup_service,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        print("\nStep 1: Get response from VS with backup service")
        print(virtual_server_setup.backend_1_url + "\n")
        res = make_request(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
        )

        assert res.status_code == 200
        assert "backend1-" in res.text
        assert "external-backend" not in res.text

        expected_conf_line = f"server {vs_externalname_setup.external_host}:80 backup resolve;"
        result_conf = get_result_in_conf_with_retry(
            kube_apis.v1,
            expected_conf_line,
            vs_externalname_setup.external_host,
            virtual_server_setup.vs_name,
            virtual_server_setup.namespace,
            vs_externalname_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert "least_conn;" in result_conf
        assert expected_conf_line in result_conf

        print("\nStep 2: Scale deployment to zero replicas")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", virtual_server_setup.namespace, 0)
        wait_before_test()

        print("\nStep 3: Get response from backup service")
        res_from_backup = make_request(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
        )

        assert res_from_backup.status_code == 200
        assert "external-backend" in res_from_backup.text
        assert "backend1-" not in res_from_backup.text

        result_conf = get_result_in_conf_with_retry(
            kube_apis.v1,
            expected_conf_line,
            vs_externalname_setup.external_host,
            virtual_server_setup.vs_name,
            virtual_server_setup.namespace,
            vs_externalname_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert "least_conn;" in result_conf
        assert expected_conf_line in result_conf

        print("\nStep 4: Delete backup service by deleting the namespace")
        delete_namespace(kube_apis.v1, "external-ns")
        wait_before_test()

        print("\nStep 5: Get response")
        res_after_delete = make_request(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
        )

        assert res_after_delete.status_code != 200

        # Re-add the external-ns namespace.
        # This is done to ensure the vs_externalname_setup will cleanup correctly.
        create_namespace_with_name_from_yaml(kube_apis.v1, "external-ns", f"{TEST_DATA}/common/ns.yaml")

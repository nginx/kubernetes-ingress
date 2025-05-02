import pytest
from settings import TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.custom_resources_utils import create_ts_from_yaml, delete_ts, patch_ts_from_yaml
from suite.utils.resources_utils import (
    create_configmap_from_yaml,
    create_items_from_yaml,
    create_namespace_with_name_from_yaml,
    create_secret_from_yaml,
    create_secure_app_deployment_with_name,
    create_service_from_yaml,
    create_service_with_name,
    delete_items_from_yaml,
    delete_namespace,
    ensure_connection,
    ensure_response_from_backend,
    get_first_pod_name,
    get_ts_nginx_template_conf,
    replace_configmap,
    replace_configmap_from_yaml,
    scale_deployment,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.ssl_utils import create_sni_session
from suite.utils.yaml_utils import get_first_host_from_yaml

secure_app_secret = f"{TEST_DATA}/common/app/secure/secret/app-tls-secret.yaml"
secure_app_config_map = f"{TEST_DATA}/common/app/secure/config-map/secure-config.yaml"
ts_with_backup = f"{TEST_DATA}/transport-server-backup-service/transport-server-with-backup.yaml"


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
def ts_externalname_setup(
    request, kube_apis, ingress_controller_prerequisites, transport_server_tls_passthrough_setup, test_namespace
) -> ExternalNameSetup:
    print("------------------------- Deploy External-Backend -----------------------------------")
    external_ns = create_namespace_with_name_from_yaml(kube_apis.v1, "external-ns", f"{TEST_DATA}/common/ns.yaml")
    external_svc_name = create_service_with_name(kube_apis.v1, external_ns, "external-backend-svc", 8443, 8443)
    create_secret_from_yaml(kube_apis.v1, external_ns, secure_app_secret)
    create_configmap_from_yaml(kube_apis.v1, external_ns, secure_app_config_map)
    create_secure_app_deployment_with_name(kube_apis.apps_v1_api, external_ns, "external-backend")
    print("------------------------- Prepare ExternalName Setup -----------------------------------")
    external_svc_src = f"{TEST_DATA}/transport-server-backup-service/backup-svc.yaml"
    external_svc_host = f"{external_svc_name}.{external_ns}.svc.cluster.local"
    config_map_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
    replace_configmap_from_yaml(
        kube_apis.v1,
        config_map_name,
        ingress_controller_prerequisites.namespace,
        f"{TEST_DATA}/transport-server-backup-service/nginx-config.yaml",
    )
    external_svc = create_service_from_yaml(kube_apis.v1, test_namespace, external_svc_src)
    req_url = (
        f"https://{transport_server_tls_passthrough_setup.public_endpoint.public_ip}:"
        f"{transport_server_tls_passthrough_setup.public_endpoint.port_ssl}"
    )
    wait_before_test(2)
    ensure_connection(req_url)
    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
    ensure_response_from_backend(
        req_url,
        transport_server_tls_passthrough_setup.ts_host,
    )

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


class TransportServerTlsSetup:
    """
    Encapsulate Transport Server details.

    Attributes:
        public_endpoint (object):
        tls_passthrough_port (int):
        ts_resource (dict):
        name (str):
        namespace (str):
        ts_host (str):
    """

    def __init__(
        self, public_endpoint: PublicEndpoint, tls_passthrough_port: int, ts_resource, name, namespace, ts_host
    ):
        self.public_endpoint = public_endpoint
        self.tls_passthrough_port = tls_passthrough_port
        self.ts_resource = ts_resource
        self.name = name
        self.namespace = namespace
        self.ts_host = ts_host


@pytest.fixture(scope="class")
def transport_server_tls_passthrough_setup(
    request, kube_apis, test_namespace, ingress_controller_endpoint
) -> TransportServerTlsSetup:
    """
    Prepare Transport Server Example.

    :param request: internal pytest fixture to parametrize this method
    :param kube_apis: client apis
    :param test_namespace: namespace for test resources
    :param ingress_controller_endpoint: ip and port information
    :return TransportServerTlsSetup:
    """
    print("------------------------- Deploy Transport Server with tls passthrough -----------------------------------")
    # deploy secure_app
    secure_app_file = f"{TEST_DATA}/{request.param['example']}/standard/secure-app.yaml"
    create_items_from_yaml(kube_apis, secure_app_file, test_namespace)

    # deploy transport server
    transport_server_std_src = f"{TEST_DATA}/{request.param['example']}/standard/transport-server.yaml"
    ts_resource = create_ts_from_yaml(kube_apis.custom_objects, transport_server_std_src, test_namespace)
    ts_host = get_first_host_from_yaml(transport_server_std_src)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up TransportServer and app:")
            delete_ts(kube_apis.custom_objects, ts_resource, test_namespace)
            delete_items_from_yaml(kube_apis, secure_app_file, test_namespace)

    request.addfinalizer(fin)

    return TransportServerTlsSetup(
        ingress_controller_endpoint,
        request.param["tls_passthrough_port"],
        ts_resource,
        ts_resource["metadata"]["name"],
        test_namespace,
        ts_host,
    )


@pytest.mark.ts
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, transport_server_tls_passthrough_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-tls-passthrough=true",
                    "-log-level=debug",
                ],
            },
            {"example": "transport-server-backup-service", "tls_passthrough_port": 443},
        ),
    ],
    indirect=True,
    ids=["tls_passthrough_with_default_port"],
)
class TestTransportServerWithBackupService:
    """
    This test validates that we still get a response back from the default
    service, and not the backup service, as long as the default service is still available
    """

    def test_get_response_from_application(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ts_externalname_setup,
        transport_server_tls_passthrough_setup,
        test_namespace,
    ):
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_tls_passthrough_setup.name,
            ts_with_backup,
            transport_server_tls_passthrough_setup.namespace,
        )
        wait_before_test()
        session = create_sni_session()
        req_url = (
            f"https://{transport_server_tls_passthrough_setup.public_endpoint.public_ip}:"
            f"{transport_server_tls_passthrough_setup.public_endpoint.port_ssl}"
        )
        print(req_url)
        wait_before_test()
        resp = session.get(
            req_url,
            headers={"host": transport_server_tls_passthrough_setup.ts_host},
            verify=False,
        )

        assert resp.status_code == 200
        assert f"hello from pod {get_first_pod_name(kube_apis.v1, test_namespace)}" in resp.text

        result_conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            test_namespace,
            transport_server_tls_passthrough_setup.name,
            ts_externalname_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert "least_conn;" in result_conf
        assert f"server {ts_externalname_setup.external_host}:8443 resolve backup;" in result_conf

    """
    This test validates that we get a response back from the backup service.
    This test also scales the application back to 2 replicas after confirming a response from the backup service.
    """

    def test_get_response_from_backup(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ts_externalname_setup,
        transport_server_tls_passthrough_setup,
        test_namespace,
    ):
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_tls_passthrough_setup.name,
            ts_with_backup,
            transport_server_tls_passthrough_setup.namespace,
        )
        wait_before_test()
        session = create_sni_session()
        req_url = (
            f"https://{transport_server_tls_passthrough_setup.public_endpoint.public_ip}:"
            f"{transport_server_tls_passthrough_setup.public_endpoint.port_ssl}"
        )
        wait_before_test()
        resp = session.get(
            req_url,
            headers={"host": transport_server_tls_passthrough_setup.ts_host},
            verify=False,
        )

        assert resp.status_code == 200
        assert f"hello from pod {get_first_pod_name(kube_apis.v1, test_namespace)}" in resp.text

        result_conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            test_namespace,
            transport_server_tls_passthrough_setup.name,
            ts_externalname_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "least_conn;" in result_conf
        assert f"server {ts_externalname_setup.external_host}:8443 resolve backup;" in result_conf

        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "secure-app", test_namespace, 0)
        wait_before_test()

        result_conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            test_namespace,
            transport_server_tls_passthrough_setup.name,
            ts_externalname_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "least_conn;" in result_conf
        assert f"server {ts_externalname_setup.external_host}:8443 resolve backup;" in result_conf

        resp_after_scale = session.get(
            req_url,
            headers={"host": transport_server_tls_passthrough_setup.ts_host},
            verify=False,
        )

        assert resp_after_scale.status_code == 200

        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "secure-app", test_namespace, 1)

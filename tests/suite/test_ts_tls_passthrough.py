from pprint import pprint

import pytest
from settings import DEPLOYMENTS, TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.custom_resources_utils import create_ts_from_yaml, delete_ts, read_ts
from suite.utils.resources_utils import (
    create_items_from_yaml,
    delete_items_from_yaml,
    get_first_pod_name,
    get_nginx_template_conf,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.ssl_utils import create_sni_session
from suite.utils.vs_vsr_resources_utils import create_virtual_server_from_yaml, delete_virtual_server, read_vs
from suite.utils.yaml_utils import get_first_host_from_yaml


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
    secure_app_secret_file = f"{TEST_DATA}/{request.param['example']}/standard/secure-app-secret.yaml"
    create_items_from_yaml(kube_apis, secure_app_secret_file, test_namespace)
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
            delete_items_from_yaml(kube_apis, secure_app_secret_file, test_namespace)
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
@pytest.mark.parametrize(
    "crd_ingress_controller, transport_server_tls_passthrough_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-leader-election=false",
                    "-enable-tls-passthrough=true",
                ],
            },
            {"example": "transport-server-tls-passthrough", "tls_passthrough_port": 443},
        ),
        (
            {
                "type": "tls-passthrough-custom-port",
                # set publicEndpoint.port_ssl to 8443 when checking connection to public endpoint and in all tests
                "extra_args": [
                    "-enable-leader-election=false",
                    "-enable-tls-passthrough=true",
                    "-tls-passthrough-port=8443",
                ],
            },
            {"example": "transport-server-tls-passthrough", "tls_passthrough_port": 8443},
        ),
    ],
    indirect=True,
    ids=["tls_passthrough_with_default_port", "tls_passthrough_with_custom_port"],
)
class TestTransportServerTlsPassthrough:
    def restore_ts(self, kube_apis, transport_server_tls_passthrough_setup) -> None:
        """
        Function to create std TS resource
        """
        ts_std_src = f"{TEST_DATA}/transport-server-tls-passthrough/standard/transport-server.yaml"
        ts_std_res = create_ts_from_yaml(
            kube_apis.custom_objects,
            ts_std_src,
            transport_server_tls_passthrough_setup.namespace,
        )
        wait_before_test(1)
        pprint(ts_std_res)

    @pytest.mark.smoke
    def test_tls_passthrough(
        self,
        kube_apis,
        crd_ingress_controller,
        transport_server_tls_passthrough_setup,
        test_namespace,
    ):
        """
        Test TransportServer TLS passthrough on https port.
        """
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

    def test_tls_passthrough_proxy_protocol_config(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        transport_server_tls_passthrough_setup,
        test_namespace,
    ):
        """
        Test TransportServer TLS passthrough on https port with proxy protocol enabled.
        """
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/transport-server-tls-passthrough/nginx-config.yaml",
        )
        wait_before_test(1)
        config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert f"listen {transport_server_tls_passthrough_setup.tls_passthrough_port} proxy_protocol;" in config
        assert f"listen [::]:{transport_server_tls_passthrough_setup.tls_passthrough_port} proxy_protocol;" in config
        std_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            std_cm_src,
        )

    def test_tls_passthrough_host_collision_ts(
        self,
        kube_apis,
        crd_ingress_controller,
        transport_server_tls_passthrough_setup,
        test_namespace,
    ):
        """
        Test host collision handling in TransportServer with another TransportServer.
        """
        print("Step 1: Create second TS with same host")
        ts_src_same_host = f"{TEST_DATA}/transport-server-tls-passthrough/transport-server-same-host.yaml"
        ts_same_host = create_ts_from_yaml(kube_apis.custom_objects, ts_src_same_host, test_namespace)
        wait_before_test()
        response = read_ts(kube_apis.custom_objects, test_namespace, ts_same_host["metadata"]["name"])
        assert (
            response["status"]["reason"] == "Rejected"
            and response["status"]["message"] == "Host is taken by another resource"
        )

        print("Step 2: Delete TS taking up the host")
        delete_ts(
            kube_apis.custom_objects,
            transport_server_tls_passthrough_setup.ts_resource,
            test_namespace,
        )
        wait_before_test(1)
        response = read_ts(kube_apis.custom_objects, test_namespace, ts_same_host["metadata"]["name"])
        assert response["status"]["reason"] == "AddedOrUpdated" and response["status"]["state"] == "Valid"
        print("Step 3: Delete second TS and re-create standard one")
        delete_ts(kube_apis.custom_objects, ts_same_host, test_namespace)
        self.restore_ts(kube_apis, transport_server_tls_passthrough_setup)
        response = read_ts(kube_apis.custom_objects, test_namespace, transport_server_tls_passthrough_setup.name)
        assert response["status"]["reason"] == "AddedOrUpdated" and response["status"]["state"] == "Valid"

    def test_tls_passthrough_host_collision_vs(
        self,
        kube_apis,
        crd_ingress_controller,
        transport_server_tls_passthrough_setup,
        test_namespace,
    ):
        """
        Test host collision handling in TransportServer with VirtualServer.
        """
        print("Step 1: Create VirtualServer with same host")
        vs_src_same_host = f"{TEST_DATA}/transport-server-tls-passthrough/virtual-server-same-host.yaml"
        vs_same_host_name = create_virtual_server_from_yaml(kube_apis.custom_objects, vs_src_same_host, test_namespace)
        wait_before_test(1)
        response = read_vs(kube_apis.custom_objects, test_namespace, vs_same_host_name)
        delete_virtual_server(kube_apis.custom_objects, vs_same_host_name, test_namespace)

        assert (
            response["status"]["reason"] == "Rejected"
            and response["status"]["message"] == "Host is taken by another resource"
        )

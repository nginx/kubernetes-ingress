from unittest import mock

import pytest
import requests
from settings import TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.custom_resources_utils import create_ts_from_yaml, delete_ts
from suite.utils.resources_utils import (
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_items_from_yaml,
    delete_secret,
    get_first_pod_name,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.ssl_utils import create_sni_session
from suite.utils.yaml_utils import get_first_host_from_yaml


class TransportServerTlsSetup:
    """
    Encapsulate Transport Server details.

    Attributes:
        public_endpoint (object):
        ts_resource (dict):
        name (str):
        namespace (str):
        ts_host (str):
    """

    def __init__(self, public_endpoint: PublicEndpoint, ts_resource, name, namespace, ts_host):
        self.public_endpoint = public_endpoint
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
                    "-enable-service-insight",
                ],
            },
            {"example": "transport-server-tls-passthrough"},
        )
    ],
    indirect=True,
)
class TestTransportServerTSServiceInsightHTTP:
    def test_ts_service_insight(
        self,
        kube_apis,
        crd_ingress_controller,
        transport_server_tls_passthrough_setup,
        test_namespace,
        ingress_controller_endpoint,
    ):
        """
        Test Service Insight Endpoint with Transport Server on HTTP port.
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

        # Service Insight test
        retry = 0
        resp = mock.Mock()
        resp.json.return_value = {}
        resp.status_code == 502

        service_insight_endpoint = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.service_insight_port}/probe/ts/secure-app"
        resp = requests.get(service_insight_endpoint)
        assert resp.status_code == 200, f"Expected 200 code for /probe/ts/secure-app but got {resp.status_code}"

        while (resp.json() != {"Total": 1, "Up": 1, "Unhealthy": 0}) and retry < 5:
            resp = requests.get(service_insight_endpoint)
            wait_before_test()
            retry = retry + 1
        assert resp.json() == {"Total": 1, "Up": 1, "Unhealthy": 0}


@pytest.fixture(scope="class")
def https_secret_setup(request, kube_apis, test_namespace):
    print("------------------------- Deploy Secret -----------------------------------")
    secret_name = create_secret_from_yaml(kube_apis.v1, "nginx-ingress", f"{TEST_DATA}/service-insight/secret.yaml")

    def fin():
        delete_secret(kube_apis.v1, secret_name, "nginx-ingress")

    request.addfinalizer(fin)


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
                    "-enable-service-insight",
                    "-service-insight-tls-secret=nginx-ingress/test-secret",
                ],
            },
            {"example": "transport-server-tls-passthrough"},
        )
    ],
    indirect=True,
)
class TestTransportServerTSServiceInsightHTTPS:
    def test_ts_service_insight_https(
        self,
        kube_apis,
        https_secret_setup,
        crd_ingress_controller,
        transport_server_tls_passthrough_setup,
        test_namespace,
        ingress_controller_endpoint,
    ):
        """
        Test Service Insight Endpoint with Transport Server on HTTPS port.
        """
        retry = 0
        resp = mock.Mock()
        resp.json.return_value = {}
        resp.status_code == 502

        service_insight_endpoint = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.service_insight_port}/probe/ts/secure-app"
        resp = requests.get(service_insight_endpoint, verify=False)
        assert resp.status_code == 200, f"Expected 200 code for /probe/ts/secure-app but got {resp.status_code}"

        while (resp.json() != {"Total": 1, "Up": 1, "Unhealthy": 0}) and retry < 5:
            resp = requests.get(service_insight_endpoint, verify=False)
            wait_before_test()
            retry = retry + 1
        assert resp.json() == {"Total": 1, "Up": 1, "Unhealthy": 0}

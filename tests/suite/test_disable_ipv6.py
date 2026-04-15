import pytest
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_secret,
    ensure_connection_to_public_endpoint,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    get_nginx_template_conf,
    get_ts_nginx_template_conf,
    get_vs_nginx_template_conf,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_name_from_yaml


@pytest.mark.vs
@pytest.mark.ts
@pytest.mark.vs_ipv6
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-global-configuration=nginx-ingress/nginx-configuration",
                    "-disable-ipv6=true",
                ],
            },
            {"example": "virtual-server-status", "app_type": "simple"},
            {"example": "transport-server-status", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestDisableIpv6VsTs:
    def test_ipv6_listeners_not_in_config(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        transport_server_setup,
    ):
        wait_before_test()
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        ts_config = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        vs_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "listen [::]:" not in nginx_config
        assert "listen [::]:" not in vs_config
        assert "listen [::]:" not in ts_config


class IngressSetup:
    """
    Encapsulate the ingress_setup details.

    Attributes:
        ingress_name (str):
        ingress_pod_name (str):
        namespace (str):
    """

    def __init__(self, ingress_name, ingress_pod_name, namespace):
        self.ingress_name = ingress_name
        self.ingress_pod_name = ingress_pod_name
        self.namespace = namespace


@pytest.fixture(scope="class")
def ingress_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    ingress_controller,
    test_namespace,
) -> IngressSetup:
    print("------------------------- Deploy Disable IPV6 Example -----------------------------------")
    secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, f"{TEST_DATA}/smoke/smoke-secret.yaml")
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml", test_namespace)
    ingress_name = get_name_from_yaml(f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml")
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )
    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up the Disable IPV6 Application:")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(kube_apis, f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml", test_namespace)
            delete_secret(kube_apis.v1, secret_name, test_namespace)

    request.addfinalizer(fin)

    return IngressSetup(ingress_name, ic_pod_name, test_namespace)


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller",
    [
        pytest.param({"extra_args": ["-disable-ipv6=true"]}),
    ],
    indirect=True,
)
class TestDisableIPV6Ingress:
    def test_ipv6_listeners_not_in_config(
        self,
        kube_apis,
        ingress_setup,
        ingress_controller_prerequisites,
    ):
        wait_before_test()
        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        upstream_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            ingress_setup.namespace,
            ingress_setup.ingress_name,
            ingress_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "listen [::]:" not in nginx_config
        assert "listen [::]:" not in upstream_conf

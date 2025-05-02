import grpc
import pytest
from settings import DEPLOYMENTS, TEST_DATA
from suite.grpc.helloworld_pb2 import HelloRequest
from suite.grpc.helloworld_pb2_grpc import GreeterStub
from suite.utils.custom_assertions import (
    assert_grpc_entries_exist,
    assert_proxy_entries_exist,
    wait_and_assert_status_code,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    get_first_pod_name,
    replace_configmap_from_yaml,
    wait_until_all_pods_are_ready,
)
from suite.utils.ssl_utils import get_certificate
from suite.utils.vs_vsr_resources_utils import get_vs_nginx_template_conf


@pytest.fixture(scope="function")
def backend_setup(request, kube_apis, ingress_controller_prerequisites, test_namespace):
    """
    Replace the ConfigMap and deploy the secret.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param test_namespace:
    """
    app_name = request.param.get("app_type")
    try:
        print("------------------------- Replace ConfigMap with HTTP2 -------------------------")
        cm_source = f"{TEST_DATA}/virtual-server-grpc/nginx-config.yaml"
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_source,
        )
        print("------------------------- Deploy Secret -----------------------------")
        src_sec_yaml = f"{TEST_DATA}/virtual-server-grpc/tls-secret.yaml"
        create_secret_from_yaml(kube_apis.v1, test_namespace, src_sec_yaml)
        print("------------------------- Deploy App -----------------------------")
        app_name = request.param.get("app_type")
        create_example_app(kube_apis, app_name, test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    except Exception:
        print("Failed to complete setup, cleaning up..")
        delete_items_from_yaml(kube_apis, src_sec_yaml, test_namespace)
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{DEPLOYMENTS}/common/nginx-config.yaml",
        )
        delete_common_app(kube_apis, app_name, test_namespace)
        pytest.fail(f"VS GRPC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            delete_items_from_yaml(kube_apis, src_sec_yaml, test_namespace)
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )
            delete_common_app(kube_apis, app_name, test_namespace)

    request.addfinalizer(fin)


@pytest.mark.vs
@pytest.mark.vs_grpc
@pytest.mark.smoke
@pytest.mark.flaky(max_runs=3)
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [({"type": "complete", "extra_args": [f"-enable-custom-resources"]}, {"example": "virtual-server-grpc-mixed"})],
    indirect=True,
)
class TestVirtualServerMixedUpstreamType:
    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs-mixed"}], indirect=True)
    def test_config_after_setup(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, virtual_server_setup
    ):
        print("\nStep 1: assert config")
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert_grpc_entries_exist(config)
        assert_proxy_entries_exist(config)

        print("\nStep 2: check connection to http backend")
        print("\nrequest URL: ", virtual_server_setup.backend_2_url)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

        print("\nStep 3: Check connection to app")
        cert = get_certificate(
            virtual_server_setup.public_endpoint.public_ip,
            virtual_server_setup.vs_host,
            virtual_server_setup.public_endpoint.port_ssl,
        )
        target = f"{virtual_server_setup.public_endpoint.public_ip}:{virtual_server_setup.public_endpoint.port_ssl}"
        credentials = grpc.ssl_channel_credentials(root_certificates=cert.encode())
        options = (("grpc.ssl_target_name_override", virtual_server_setup.vs_host),)

        with grpc.secure_channel(target, credentials, options) as channel:
            stub = GreeterStub(channel)
            response = ""
            try:
                response = stub.SayHello(HelloRequest(name=virtual_server_setup.public_endpoint.public_ip))
                valid_message = "Hello {}".format(virtual_server_setup.public_endpoint.public_ip)
                assert valid_message in response.message
            except grpc.RpcError as e:
                print(e.details())
                pytest.fail("RPC error was not expected during call, exiting...")

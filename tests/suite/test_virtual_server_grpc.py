import grpc
import pytest
from settings import DEPLOYMENTS, TEST_DATA
from suite.grpc.helloworld_pb2 import HelloRequest
from suite.grpc.helloworld_pb2_grpc import GreeterStub
from suite.utils.custom_assertions import (
    assert_event,
    assert_event_starts_with_text_and_contains_errors,
    assert_grpc_entries_exist,
    assert_proxy_entries_do_not_exist,
    assert_vs_conf_not_exists,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    get_events,
    get_first_pod_name,
    replace_configmap_from_yaml,
    scale_deployment,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.ssl_utils import get_certificate
from suite.utils.vs_vsr_resources_utils import get_vs_nginx_template_conf, patch_virtual_server_from_yaml


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
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [({"type": "complete", "extra_args": [f"-enable-custom-resources"]}, {"example": "virtual-server-grpc"})],
    indirect=True,
)
class TestVirtualServerGrpc:
    def patch_valid_vs(self, kube_apis, virtual_server_setup) -> None:
        """
        Function to revert vs deployment to valid state
        """
        patch_src = f"{TEST_DATA}/virtual-server-grpc/standard/virtual-server.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            patch_src,
            virtual_server_setup.namespace,
        )

    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
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
        assert_proxy_entries_do_not_exist(config)

    @pytest.mark.flaky(max_runs=3)
    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_validation_flow(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, virtual_server_setup
    ):
        print("\nTest 1: Wrong type")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-grpc/virtual-server-invalid-type.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test()
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        event_text1 = f"VirtualServer {text} was rejected with error:"
        invalid_fields1 = ["spec.upstreams[0].type"]
        vs_events1 = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_event_starts_with_text_and_contains_errors(event_text1, vs_events1, invalid_fields1)

        self.patch_valid_vs(kube_apis, virtual_server_setup)
        wait_before_test()

    @pytest.mark.flaky(max_runs=3)
    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_connect_grpc_backend(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, virtual_server_setup
    ) -> None:
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

    @pytest.mark.flaky(max_runs=3)
    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_grpc_error_intercept(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, virtual_server_setup
    ):
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
                # no status has been returned in the response
                assert valid_message in response.message
            except grpc.RpcError as e:
                print(e.details())
                pytest.fail("RPC error was not expected during call, exiting...")
        # Assert grpc_status is in the logs. The gRPC response in a successful call is 0.
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        log_contents = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ingress_controller_prerequisites.namespace)
        retry = 0
        while '"POST /helloworld.Greeter/SayHello HTTP/2.0" 200 0' not in log_contents and retry <= 60:
            log_contents = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ingress_controller_prerequisites.namespace)
            retry += 1
            wait_before_test(1)
            print(f"Logs not yet updated, retrying... #{retry}")
        assert '"POST /helloworld.Greeter/SayHello HTTP/2.0" 200 0' in log_contents

        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "grpc1", virtual_server_setup.namespace, 0)
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "grpc2", virtual_server_setup.namespace, 0)
        wait_before_test()

        with grpc.secure_channel(target, credentials, options) as channel:
            stub = GreeterStub(channel)
            try:
                response = stub.SayHello(HelloRequest(name=virtual_server_setup.public_endpoint.public_ip))
                # assert the grpc status has been returned in the header
                assert response.status == 14
                pytest.fail("RPC error was expected during call, exiting...")
            except grpc.RpcError as e:
                print(e)
        # Assert the grpc_status is also in the logs.
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        wait_before_test()
        # Need to get full log because of a race condition on the last log entry.
        log_contents = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ingress_controller_prerequisites.namespace)
        retry = 0
        while '"POST /helloworld.Greeter/SayHello HTTP/2.0" 204 14' not in log_contents and retry <= 60:
            log_contents = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ingress_controller_prerequisites.namespace)
            retry += 1
            wait_before_test(1)
            print(f"Logs not yet updated, retrying... #{retry}")

    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_config_error_page_warning(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, virtual_server_setup
    ):
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_warning_text = f"Configuration for {text} was added or updated ; with warning(s): "
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-grpc/virtual-server-error-page.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(5)
        events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_event(vs_event_warning_text, events)
        self.patch_valid_vs(kube_apis, virtual_server_setup)
        wait_before_test()

    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_config_after_enable_tls(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, virtual_server_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-grpc/virtual-server-updated.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test()
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "grpc_pass grpcs://" in config


@pytest.mark.vs
@pytest.mark.vs_grpc
@pytest.mark.smoke
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [({"type": "complete", "extra_args": [f"-enable-custom-resources"]}, {"example": "virtual-server-grpc"})],
    indirect=True,
)
class TestVirtualServerGrpcHealthCheck:
    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_config_after_enable_healthcheck(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, virtual_server_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-grpc/virtual-server-healthcheck.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test()
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        param_list = [
            "health_check port=50051 interval=1s jitter=2s",
            "type=grpc grpc_status=12",
            "grpc_service=none.None;",
        ]
        for p in param_list:
            assert p in config

    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_grpc_healthcheck_validation(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, virtual_server_setup
    ):
        invalid_fields = [
            "upstreams[0].healthCheck.path",
            "upstreams[0].healthCheck.statusMatch",
            "upstreams[0].healthCheck.grpcStatus",
            "upstreams[0].healthCheck.grpcService",
        ]
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"VirtualServer {text} was rejected with error:"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-grpc/virtual-server-healthcheck-invalid.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(2)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_event_starts_with_text_and_contains_errors(vs_event_text, vs_events, invalid_fields)
        assert_vs_conf_not_exists(
            kube_apis, ic_pod_name, ingress_controller_prerequisites.namespace, virtual_server_setup
        )

    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_grpc_healthcheck_send_hello(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, virtual_server_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-grpc/virtual-server-healthcheck.yaml",
            virtual_server_setup.namespace,
        )

        # Ensure the initial health check configuration
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "grpc_service=none.None" in config

        # Attempt to send a Hello message
        cert = get_certificate(
            virtual_server_setup.public_endpoint.public_ip,
            virtual_server_setup.vs_host,
            virtual_server_setup.public_endpoint.port_ssl,
        )
        target = f"{virtual_server_setup.public_endpoint.public_ip}:{virtual_server_setup.public_endpoint.port_ssl}"
        credentials = grpc.ssl_channel_credentials(root_certificates=cert.encode())
        options = (("grpc.ssl_target_name_override", virtual_server_setup.vs_host),)

        try:
            with grpc.secure_channel(target, credentials, options) as channel:
                stub = GreeterStub(channel)
                response = stub.SayHello(HelloRequest(name=""))
                valid_message = "Hello "
                assert response.message == valid_message, f"Expected '{valid_message}', but got '{response.message}'"
        except grpc.RpcError as e:
            print(e.details())
            pytest.fail("RPC error was not expected during call, exiting...")

        # Update health check to expect gRPC status code 0
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-grpc/virtual-server-healthcheck-fail.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test()

        # Re-fetch the config to confirm the update
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "grpc_status=0" in config

        # Verify that the health check fails
        log_contents = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ingress_controller_prerequisites.namespace)
        assert (
            "peer is unhealthy while checking grpc response" in log_contents
        ), "Expected 'peer is unhealthy while checking grpc response' in logs but it was not found"

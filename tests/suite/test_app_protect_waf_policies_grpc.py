import grpc
import pytest
from settings import DEPLOYMENTS, TEST_DATA
from suite.fixtures.custom_resource_fixtures import VirtualServerRoute, VirtualServerRouteSetup, VirtualServerSetup
from suite.grpc.helloworld_pb2 import HelloRequest
from suite.grpc.helloworld_pb2_grpc import GreeterStub
from suite.utils.ap_resources_utils import (
    create_ap_logconf_from_yaml,
    create_ap_policy_from_yaml,
    create_ap_waf_policy_from_yaml,
    delete_ap_logconf,
    delete_ap_policy,
)
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_namespace_with_name_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_namespace,
    get_file_contents,
    get_service_endpoint,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.ssl_utils import get_certificate
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route_from_yaml,
    create_virtual_server_from_yaml,
    delete_virtual_server,
)
from suite.utils.yaml_utils import get_first_host_from_yaml, get_paths_from_vs_yaml, get_paths_from_vsr_yaml

log_loc = f"/var/log/messages"
valid_resp_txt = "Hello"
invalid_resp_text = "The request was rejected. Please consult with your administrator."

cm_source = f"{TEST_DATA}/ap-waf-grpc/nginx-config.yaml"
src_vs_sec_yaml = f"{TEST_DATA}/ap-waf-grpc/tls-secret.yaml"
src_log_yaml = f"{TEST_DATA}/ap-waf-grpc/logconf.yaml"
src_syslog_yaml = f"{TEST_DATA}/ap-waf-grpc/syslog.yaml"
std_vs_src = f"{TEST_DATA}/ap-waf-grpc/standard/virtual-server.yaml"
waf_spec_vs_src = f"{TEST_DATA}/ap-waf-grpc/virtual-server-waf-spec.yaml"
waf_route_vs_src = f"{TEST_DATA}/ap-waf-grpc/virtual-server-waf-route.yaml"
waf_subroute_vsr_src = f"{TEST_DATA}/ap-waf-grpc/virtual-server-route-waf.yaml"
vsr_vs_yaml = f"{TEST_DATA}/ap-waf-grpc/vsr-virtual-server-spec.yaml"


@pytest.fixture(scope="class")
def appprotect_setup(
    request, kube_apis, ingress_controller_endpoint, ingress_controller_prerequisites, test_namespace
) -> None:
    """
    Replace the config map, create the TLS secret, deploy grpc application, and deploy
    all the AppProtect(dataguard-alarm) resources under test in one namespace.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_prerequisites:
    :param test_namespace:
    """
    policy_method = request.param["policy"]
    vs_or_vsr = request.param["vs_or_vsr"]
    vsr = None
    try:
        print("------------------------- Replace ConfigMap with HTTP2 -------------------------")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_source,
        )
        if vs_or_vsr == "vs":
            (src_pol_name, vs_name, vs_host, vs_paths) = ap_vs_setup(kube_apis, test_namespace, policy_method)
        elif vs_or_vsr == "vsr":
            (src_pol_name, vsr_ns, vs_host, vs_name, vsr) = ap_vsr_setup(kube_apis, test_namespace, policy_method)
        wait_before_test(120)
    except Exception:
        cleanup(kube_apis, ingress_controller_prerequisites, src_pol_name, test_namespace, vs_or_vsr, vs_name, vsr)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            cleanup(kube_apis, ingress_controller_prerequisites, src_pol_name, test_namespace, vs_or_vsr, vs_name, vsr)

    request.addfinalizer(fin)
    if vs_or_vsr == "vs":
        return VirtualServerSetup(ingress_controller_endpoint, test_namespace, vs_host, vs_name, vs_paths)
    elif vs_or_vsr == "vsr":
        return VirtualServerRouteSetup(ingress_controller_endpoint, vsr_ns, vs_host, vs_name, vsr, None)


def ap_vs_setup(kube_apis, test_namespace, policy_method) -> tuple:
    src_pol_name, vs_name = ap_generic_setup(kube_apis, test_namespace, test_namespace, policy_method, waf_spec_vs_src)
    vs_host = get_first_host_from_yaml(waf_spec_vs_src)
    vs_paths = get_paths_from_vs_yaml(waf_spec_vs_src)
    return (src_pol_name, vs_name, vs_host, vs_paths)


def ap_vsr_setup(kube_apis, test_namespace, policy_method) -> tuple:
    print(f"------------------------- Deploy namespace ---------------------------")
    vs_routes_ns = "grpcs"
    vsr_ns = create_namespace_with_name_from_yaml(kube_apis.v1, vs_routes_ns, f"{TEST_DATA}/common/ns.yaml")
    src_pol_name, vs_name = ap_generic_setup(kube_apis, vsr_ns, test_namespace, policy_method, vsr_vs_yaml)
    vs_host = get_first_host_from_yaml(vsr_vs_yaml)
    print("------------------------- Deploy Virtual Server Route ----------------------------")
    vsr_name = create_v_s_route_from_yaml(kube_apis.custom_objects, waf_subroute_vsr_src, vsr_ns)
    vsr_paths = get_paths_from_vsr_yaml(waf_subroute_vsr_src)
    vsr = VirtualServerRoute(vsr_ns, vsr_name, vsr_paths)

    return (src_pol_name, vsr_ns, vs_host, vs_name, vsr)


def ap_generic_setup(kube_apis, vs_namespace, test_namespace, policy_method, vs_yaml):
    src_pol_yaml = f"{TEST_DATA}/ap-waf-grpc/policies/waf-block-{policy_method}.yaml"
    print("------------------------- Deploy logconf -----------------------------")
    global log_name
    log_name = create_ap_logconf_from_yaml(kube_apis.custom_objects, src_log_yaml, test_namespace)
    print(f"------------------------- Deploy AP policy ---------------------------")
    src_appol_yaml = f"{TEST_DATA}/ap-waf-grpc/grpc-block-{policy_method}.yaml"
    global ap_pol_name
    ap_pol_name = create_ap_policy_from_yaml(kube_apis.custom_objects, src_appol_yaml, test_namespace)
    print("------------------------- Deploy Syslog -----------------------------")
    create_items_from_yaml(kube_apis, src_syslog_yaml, test_namespace)
    wait_before_test(20)
    syslog_ep = get_service_endpoint(kube_apis, "syslog-svc", test_namespace)
    print("------------------------- Deploy App -----------------------------")
    create_example_app(kube_apis, "grpc-vs", vs_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, vs_namespace)
    print("------------------------- Deploy Secret -----------------------------")
    create_secret_from_yaml(kube_apis.v1, vs_namespace, src_vs_sec_yaml)
    print(f"------------------------- Deploy policy ---------------------------")
    src_pol_name = create_ap_waf_policy_from_yaml(
        kube_apis.custom_objects,
        src_pol_yaml,
        vs_namespace,
        test_namespace,
        True,
        True,
        ap_pol_name,
        log_name,
        f"syslog:server={syslog_ep}:514",
    )
    print("------------------------- Deploy Virtual Server -----------------------------------")
    vs_name = create_virtual_server_from_yaml(kube_apis.custom_objects, vs_yaml, vs_namespace)
    return (src_pol_name, vs_name)


def cleanup(kube_apis, ingress_controller_prerequisites, src_pol_name, test_namespace, vs_or_vsr, vs_name, vsr) -> None:
    vsr_namespace = test_namespace if vs_or_vsr == "vs" else vsr.namespace
    replace_configmap_from_yaml(
        kube_apis.v1,
        ingress_controller_prerequisites.config_map["metadata"]["name"],
        ingress_controller_prerequisites.namespace,
        f"{DEPLOYMENTS}/common/nginx-config.yaml",
    )
    delete_ap_logconf(kube_apis.custom_objects, log_name, test_namespace)
    delete_ap_policy(kube_apis.custom_objects, ap_pol_name, test_namespace)
    delete_policy(kube_apis.custom_objects, src_pol_name, vsr_namespace)
    delete_common_app(kube_apis, "grpc-vs", vsr_namespace)
    delete_items_from_yaml(kube_apis, src_syslog_yaml, test_namespace)
    if vs_or_vsr == "vs":
        delete_virtual_server(kube_apis.custom_objects, vs_name, test_namespace)
        delete_items_from_yaml(kube_apis, src_vs_sec_yaml, test_namespace)
    elif vs_or_vsr == "vsr":
        print("Delete test namespaces")
        delete_namespace(kube_apis.v1, vsr.namespace)


def grpc_waf_block(kube_apis, test_namespace, public_ip, vs_host, port_ssl):
    cert = get_certificate(public_ip, vs_host, port_ssl)
    target = f"{public_ip}:{port_ssl}"
    credentials = grpc.ssl_channel_credentials(root_certificates=cert.encode())
    options = (("grpc.ssl_target_name_override", vs_host),)

    with grpc.secure_channel(target, credentials, options) as channel:
        stub = GreeterStub(channel)
        ex = ""
        try:
            stub.SayHello(HelloRequest(name=public_ip))
            pytest.fail("RPC error was expected during call, exiting...")
        except grpc.RpcError as e:
            ex = e.details()
            print(ex)
    assert invalid_resp_text in ex


def grpc_waf_allow(kube_apis, test_namespace, public_ip, vs_host, port_ssl):
    cert = get_certificate(public_ip, vs_host, port_ssl)
    target = f"{public_ip}:{port_ssl}"
    credentials = grpc.ssl_channel_credentials(root_certificates=cert.encode())
    options = (("grpc.ssl_target_name_override", vs_host),)

    with grpc.secure_channel(target, credentials, options) as channel:
        stub = GreeterStub(channel)
        response = ""
        try:
            response = stub.SayHello(HelloRequest(name=public_ip))
            print(response)
        except grpc.RpcError as e:
            print(e.details())
            pytest.fail("RPC error was not expected during call, exiting...")
    assert valid_resp_txt in response.message


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect
@pytest.mark.appprotect_waf_policies_grpc
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
    [
        {
            "type": "complete",
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-leader-election=false",
                f"-enable-app-protect",
            ],
        },
    ],
    indirect=True,
)
class TestAppProtectVSGrpc:
    @pytest.mark.parametrize(
        "appprotect_setup",
        [
            {
                "policy": "sayhello",
                "vs_or_vsr": "vs",
            }
        ],
        indirect=True,
    )
    def test_responses_grpc_block(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_ap,
        appprotect_setup,
        test_namespace,
    ):
        """
        Test grpc-block-hello AppProtect policy: Blocks /sayhello gRPC method only
        Client sends request to /sayhello
        """
        grpc_waf_block(
            kube_apis,
            test_namespace,
            appprotect_setup.public_endpoint.public_ip,
            appprotect_setup.vs_host,
            appprotect_setup.public_endpoint.port_ssl,
        )
        syslog_pod = kube_apis.v1.list_namespaced_pod(test_namespace).items[-1].metadata.name
        log_contents = get_file_contents(kube_apis.v1, log_loc, syslog_pod, test_namespace)
        assert (
            "ASM:attack_type=" in str(log_contents)
            and "violations=" in str(log_contents)
            and "severity=" in str(log_contents)
            and "outcome=" in str(log_contents)
        )

    @pytest.mark.parametrize(
        "appprotect_setup",
        [
            {
                "policy": "saygoodbye",
                "vs_or_vsr": "vs",
            }
        ],
        indirect=True,
    )
    def test_responses_grpc_allow(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_ap,
        appprotect_setup,
        test_namespace,
    ):
        """
        Test grpc-block-goodbye AppProtect policy: Blocks /saygoodbye gRPC method only
        Client sends request to /sayhello thus should pass
        """
        grpc_waf_allow(
            kube_apis,
            test_namespace,
            appprotect_setup.public_endpoint.public_ip,
            appprotect_setup.vs_host,
            appprotect_setup.public_endpoint.port_ssl,
        )
        syslog_pod = kube_apis.v1.list_namespaced_pod(test_namespace).items[-1].metadata.name
        log_contents = get_file_contents(kube_apis.v1, log_loc, syslog_pod, test_namespace)
        assert (
            "ASM:attack_type=" in str(log_contents)
            and "violations=" in str(log_contents)
            and "severity=" in str(log_contents)
            and "outcome=" in str(log_contents)
        )


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect
@pytest.mark.appprotect_waf_policies_grpc
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
    [
        {
            "type": "complete",
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-leader-election=false",
                f"-enable-app-protect",
            ],
        },
    ],
    indirect=True,
)
class TestAppProtectVSRGrpc:
    @pytest.mark.parametrize(
        "appprotect_setup",
        [
            {
                "policy": "sayhello",
                "vs_or_vsr": "vsr",
            }
        ],
        indirect=True,
    )
    def test_responses_grpc_block(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_ap,
        appprotect_setup,
        test_namespace,
    ):
        """
        Test grpc-block-hello AppProtect policy: Blocks /sayhello gRPC method only
        Client sends request to /sayhello
        """
        grpc_waf_block(
            kube_apis,
            appprotect_setup.namespace,
            appprotect_setup.public_endpoint.public_ip,
            appprotect_setup.vs_host,
            appprotect_setup.public_endpoint.port_ssl,
        )

    @pytest.mark.parametrize("appprotect_setup", [{"policy": "saygoodbye", "vs_or_vsr": "vsr"}], indirect=True)
    def test_responses_grpc_allow(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_ap,
        appprotect_setup,
        test_namespace,
    ):
        """
        Test grpc-block-goodbye AppProtect policy: Blocks /saygoodbye gRPC method only
        Client sends request to /sayhello thus should pass
        """
        grpc_waf_allow(
            kube_apis,
            appprotect_setup.namespace,
            appprotect_setup.public_endpoint.public_ip,
            appprotect_setup.vs_host,
            appprotect_setup.public_endpoint.port_ssl,
        )

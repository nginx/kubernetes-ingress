import pytest
from settings import TEST_DATA
from suite.fixtures.custom_resource_fixtures import VirtualServerRoute
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.custom_assertions import (
    assert_event_and_count,
    assert_event_and_get_count,
    wait_and_assert_status_code,
    wait_for_event_count_increases,
)
from suite.utils.resources_utils import (
    create_deployment_with_name,
    create_namespace_with_name_from_yaml,
    create_service_from_yaml,
    create_service_with_name,
    delete_namespace,
    ensure_response_from_backend,
    get_events,
    get_first_pod_name,
    read_service,
    replace_configmap,
    replace_configmap_from_yaml,
    replace_service,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route_from_yaml,
    create_virtual_server_from_yaml,
    get_vs_nginx_template_conf,
)
from suite.utils.yaml_utils import get_first_host_from_yaml, get_paths_from_vsr_yaml, get_route_namespace_from_vs_yaml


class ReducedVirtualServerRouteSetup:
    """
    Encapsulate Virtual Server Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        namespace (str):
        vs_host (str):
        vs_name (str):
        route (VirtualServerRoute): route with single subroute
    """

    def __init__(
        self,
        public_endpoint: PublicEndpoint,
        namespace,
        vs_host,
        vs_name,
        route: VirtualServerRoute,
        external_svc,
        external_host,
    ):
        self.public_endpoint = public_endpoint
        self.namespace = namespace
        self.vs_host = vs_host
        self.vs_name = vs_name
        self.route = route
        self.external_svc = external_svc
        self.external_host = external_host


@pytest.fixture(scope="class")
def vsr_externalname_setup(
    request, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint
) -> ReducedVirtualServerRouteSetup:
    """
    Prepare an example app for Virtual Server Route.

    1st namespace with externalName svc and VS+VSR.

    :param request: internal pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint:
    :param ingress_controller_prerequisites:
    :return:
    """
    vs_routes_ns = get_route_namespace_from_vs_yaml(
        f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml"
    )
    ns_1 = create_namespace_with_name_from_yaml(kube_apis.v1, vs_routes_ns[0], f"{TEST_DATA}/common/ns.yaml")
    print("------------------------- Deploy External-Backend -----------------------------------")
    external_ns = create_namespace_with_name_from_yaml(kube_apis.v1, "external-ns", f"{TEST_DATA}/common/ns.yaml")
    external_svc_name = create_service_with_name(kube_apis.v1, external_ns, "external-backend-svc")
    create_deployment_with_name(kube_apis.apps_v1_api, external_ns, "external-backend")

    print("------------------------- Deploy Virtual Server -----------------------------------")
    vs_name = create_virtual_server_from_yaml(
        kube_apis.custom_objects, f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml", ns_1
    )
    vs_host = get_first_host_from_yaml(f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml")

    print("------------------------- Deploy Virtual Server Route -----------------------------------")
    vsr_name = create_v_s_route_from_yaml(
        kube_apis.custom_objects, f"{TEST_DATA}/{request.param['example']}/route-single.yaml", ns_1
    )
    vsr_paths = get_paths_from_vsr_yaml(f"{TEST_DATA}/{request.param['example']}/route-single.yaml")
    route = VirtualServerRoute(ns_1, vsr_name, vsr_paths)

    print("---------------------- Deploy ExternalName service and update ConfigMap ----------------------------")
    config_map_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
    replace_configmap_from_yaml(
        kube_apis.v1,
        config_map_name,
        ingress_controller_prerequisites.namespace,
        f"{TEST_DATA}/{request.param['example']}/nginx-config.yaml",
    )
    external_svc_host = f"{external_svc_name}.{external_ns}.svc.cluster.local"
    svc_name = create_service_from_yaml(
        kube_apis.v1, ns_1, f"{TEST_DATA}/{request.param['example']}/externalname-svc.yaml"
    )
    wait_before_test(2)
    req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}"
    ensure_response_from_backend(f"{req_url}{route.paths[0]}", vs_host)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete test namespaces")
            delete_namespace(kube_apis.v1, external_ns)
            delete_namespace(kube_apis.v1, ns_1)

    request.addfinalizer(fin)

    return ReducedVirtualServerRouteSetup(
        ingress_controller_endpoint, ns_1, vs_host, vs_name, route, svc_name, external_svc_host
    )


@pytest.mark.vsr
@pytest.mark.vsr_external_name
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, vsr_externalname_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-route-externalname"},
        )
    ],
    indirect=True,
)
class TestVSRWithExternalNameService:
    def test_responses(self, kube_apis, crd_ingress_controller, vsr_externalname_setup):
        req_url = (
            f"http://{vsr_externalname_setup.public_endpoint.public_ip}:"
            f"{vsr_externalname_setup.public_endpoint.port}"
        )
        wait_and_assert_status_code(
            200, f"{req_url}{vsr_externalname_setup.route.paths[0]}", vsr_externalname_setup.vs_host
        )

    def test_template_config(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, vsr_externalname_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        initial_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            vsr_externalname_setup.namespace,
            vsr_externalname_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        line = (
            f"zone vs_{vsr_externalname_setup.namespace}_{vsr_externalname_setup.vs_name}"
            f"_vsr_{vsr_externalname_setup.route.namespace}_{vsr_externalname_setup.route.name}_ext-backend 512k;"
        )
        assert line in initial_config
        assert "random two least_conn;" in initial_config
        assert (
            f"server {vsr_externalname_setup.external_host}:80 max_fails=1 fail_timeout=10s max_conns=0 resolve;"
            in initial_config
        )

    @pytest.mark.xfail
    def test_events_flows(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, vsr_externalname_setup
    ):
        text_vsr = f"{vsr_externalname_setup.route.namespace}/{vsr_externalname_setup.route.name}"
        text_vs = f"{vsr_externalname_setup.namespace}/{vsr_externalname_setup.vs_name}"
        vsr_event_text = f"Configuration for {text_vsr} was added or updated"
        vsr_event_warning_text = f"Configuration for {text_vsr} was added or updated with warning(s):"
        vs_event_text = f"Configuration for {text_vs} was added or updated"
        wait_before_test(10)
        initial_events = get_events(kube_apis.v1, vsr_externalname_setup.route.namespace)
        initial_count_vsr = assert_event_and_get_count(vsr_event_text, initial_events)
        initial_warning_count_vsr = assert_event_and_get_count(vsr_event_warning_text, initial_events)
        initial_count_vs = assert_event_and_get_count(vs_event_text, initial_events)

        print("Step 1: Update external host in externalName service")
        external_svc = read_service(kube_apis.v1, vsr_externalname_setup.external_svc, vsr_externalname_setup.namespace)
        external_svc.spec.external_name = "demo.nginx.com"
        replace_service(
            kube_apis.v1, vsr_externalname_setup.external_svc, vsr_externalname_setup.namespace, external_svc
        )
        wait_before_test(10)

        wait_for_event_count_increases(
            kube_apis, vsr_event_text, initial_count_vsr, vsr_externalname_setup.route.namespace
        )
        events_step_1 = get_events(kube_apis.v1, vsr_externalname_setup.route.namespace)
        assert_event_and_count(vsr_event_text, initial_count_vsr + 1, events_step_1)
        assert_event_and_count(vs_event_text, initial_count_vs + 1, events_step_1)

        print("Step 2: Remove resolver from ConfigMap to trigger an error")
        config_map_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
        replace_configmap(
            kube_apis.v1,
            config_map_name,
            ingress_controller_prerequisites.namespace,
            ingress_controller_prerequisites.config_map,
        )
        wait_before_test(10)

        events_step_2 = get_events(kube_apis.v1, vsr_externalname_setup.route.namespace)
        assert_event_and_count(vsr_event_warning_text, initial_warning_count_vsr + 1, events_step_2)
        assert_event_and_count(vs_event_text, initial_count_vs + 2, events_step_2)

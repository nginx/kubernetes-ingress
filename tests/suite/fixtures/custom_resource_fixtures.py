"""Describe project shared pytest fixtures related to setup of custom resources and apps."""

import pytest
from settings import TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.custom_resources_utils import create_gc_from_yaml, create_ts_from_yaml, delete_gc, delete_ts
from suite.utils.resources_utils import (
    create_deployment_with_name,
    create_example_app,
    create_items_from_yaml,
    create_namespace_with_name_from_yaml,
    create_service_with_name,
    delete_common_app,
    delete_deployment,
    delete_items_from_yaml,
    delete_namespace,
    delete_service,
    get_first_pod_name,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route_from_yaml,
    create_virtual_server_from_yaml,
    delete_v_s_route,
    delete_virtual_server,
)
from suite.utils.yaml_utils import (
    get_first_host_from_yaml,
    get_paths_from_vs_yaml,
    get_paths_from_vsr_yaml,
    get_route_namespace_from_vs_yaml,
)


class VirtualServerSetup:
    """
    Encapsulate  Virtual Server Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        namespace (str):
        vs_host (str):
        vs_name (str):
        backend_1_url (str):
        backend_2_url (str):
    """

    def __init__(self, public_endpoint: PublicEndpoint, namespace, vs_host, vs_name, vs_paths):
        self.public_endpoint = public_endpoint
        self.namespace = namespace
        self.vs_host = vs_host
        self.vs_name = vs_name
        self.backend_1_url = f"http://{public_endpoint.public_ip}:{public_endpoint.port}{vs_paths[0]}"
        self.backend_2_url = f"http://{public_endpoint.public_ip}:{public_endpoint.port}{vs_paths[1]}"
        self.backend_1_url_ssl = f"https://{public_endpoint.public_ip}:{public_endpoint.port_ssl}{vs_paths[0]}"
        self.backend_2_url_ssl = f"https://{public_endpoint.public_ip}:{public_endpoint.port_ssl}{vs_paths[1]}"
        self.backend_1_url_custom = f"http://{public_endpoint.public_ip}:{public_endpoint.custom_http}{vs_paths[0]}"
        self.backend_2_url_custom = f"http://{public_endpoint.public_ip}:{public_endpoint.custom_http}{vs_paths[1]}"
        self.backend_1_url_custom_ssl = (
            f"https://{public_endpoint.public_ip}:{public_endpoint.custom_https}{vs_paths[0]}"
        )
        self.backend_2_url_custom_ssl = (
            f"https://{public_endpoint.public_ip}:{public_endpoint.custom_https}{vs_paths[1]}"
        )
        self.metrics_url = f"http://{public_endpoint.public_ip}:{public_endpoint.metrics_port}/metrics"


@pytest.fixture(scope="class")
def virtual_server_setup(request, kube_apis, ingress_controller_endpoint, test_namespace) -> VirtualServerSetup:
    """
    Prepare Virtual Server Example.

    :param request: internal pytest fixture to parametrize this method:
        {example: virtual-server|virtual-server-tls|..., app_type: simple|split|...}
        'example' is a directory name in TEST_DATA,
        'app_type' is a directory name in TEST_DATA/common/app
    :param kube_apis: client apis
    :param crd_ingress_controller:
    :param ingress_controller_endpoint:
    :param test_namespace:
    :return: VirtualServerSetup
    """
    print("------------------------- Deploy Virtual Server Example -----------------------------------")
    vs_source = f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml"
    vs_name = create_virtual_server_from_yaml(kube_apis.custom_objects, vs_source, test_namespace)
    vs_host = get_first_host_from_yaml(vs_source)
    vs_paths = get_paths_from_vs_yaml(vs_source)
    if request.param.get("app_type"):
        create_example_app(kube_apis, request.param["app_type"], test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up Virtual Server Example:")
            delete_virtual_server(kube_apis.custom_objects, vs_name, test_namespace)
            if request.param.get("app_type"):
                delete_common_app(kube_apis, request.param["app_type"], test_namespace)

    request.addfinalizer(fin)

    return VirtualServerSetup(ingress_controller_endpoint, test_namespace, vs_host, vs_name, vs_paths)


class TransportServerSetup:
    """
    Encapsulate Transport Server Example details.

    Attributes:
        name (str):
        namespace (str):
    """

    def __init__(
        self, name, namespace, ingress_pod_name, ic_namespace, public_endpoint: PublicEndpoint, resource, metrics_url
    ):
        self.name = name
        self.namespace = namespace
        self.ingress_pod_name = ingress_pod_name
        self.ic_namespace = ic_namespace
        self.public_endpoint = public_endpoint
        self.resource = resource
        self.metrics_url = metrics_url


@pytest.fixture(scope="class")
def transport_server_setup(
    request, kube_apis, ingress_controller_prerequisites, test_namespace, ingress_controller_endpoint
) -> TransportServerSetup:
    """
    Prepare Transport Server Example.

    :param ingress_controller_endpoint:
    :param ingress_controller_prerequisites:
    :param request: internal pytest fixture to parametrize this method
    :param kube_apis: client apis
    :param test_namespace:
    :return: TransportServerSetup
    """
    print("------------------------- Deploy Transport Server Example -----------------------------------")

    # deploy global config
    global_config_file = f"{TEST_DATA}/{request.param['example']}/standard/global-configuration.yaml"
    gc_resource = create_gc_from_yaml(kube_apis.custom_objects, global_config_file, "nginx-ingress")

    # deploy service_file
    service_file = f"{TEST_DATA}/{request.param['example']}/standard/service_deployment.yaml"
    create_items_from_yaml(kube_apis, service_file, test_namespace)

    # deploy transport server
    transport_server_file = f"{TEST_DATA}/{request.param['example']}/standard/transport-server.yaml"
    ts_resource = create_ts_from_yaml(kube_apis.custom_objects, transport_server_file, test_namespace)

    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up TransportServer Example:")
            delete_ts(kube_apis.custom_objects, ts_resource, test_namespace)
            delete_items_from_yaml(kube_apis, service_file, test_namespace)
            delete_gc(kube_apis.custom_objects, gc_resource, "nginx-ingress")

    request.addfinalizer(fin)

    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
    ic_namespace = ingress_controller_prerequisites.namespace

    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"

    return TransportServerSetup(
        ts_resource["metadata"]["name"],
        test_namespace,
        ic_pod_name,
        ic_namespace,
        ingress_controller_endpoint,
        ts_resource,
        metrics_url,
    )


@pytest.fixture(scope="class")
def v_s_route_app_setup(request, kube_apis, v_s_route_setup) -> None:
    """
    Prepare an example app for Virtual Server Route.

    1st namespace with backend1-svc and backend3-svc and deployment and 2nd namespace with backend2-svc and deployment.

    :param request: internal pytest fixture
    :param kube_apis: client apis
    :param v_s_route_setup:
    :return:
    """
    print("---------------------- Deploy a VS Route Example Application ----------------------------")
    svc_one = create_service_with_name(kube_apis.v1, v_s_route_setup.route_m.namespace, "backend1-svc")
    svc_three = create_service_with_name(kube_apis.v1, v_s_route_setup.route_m.namespace, "backend3-svc")
    deployment_one = create_deployment_with_name(kube_apis.apps_v1_api, v_s_route_setup.route_m.namespace, "backend1")
    deployment_three = create_deployment_with_name(kube_apis.apps_v1_api, v_s_route_setup.route_m.namespace, "backend3")

    svc_two = create_service_with_name(kube_apis.v1, v_s_route_setup.route_s.namespace, "backend2-svc")
    deployment_two = create_deployment_with_name(kube_apis.apps_v1_api, v_s_route_setup.route_s.namespace, "backend2")

    wait_until_all_pods_are_ready(kube_apis.v1, v_s_route_setup.route_m.namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, v_s_route_setup.route_s.namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up the Application:")
            delete_deployment(kube_apis.apps_v1_api, deployment_one, v_s_route_setup.route_m.namespace)
            delete_service(kube_apis.v1, svc_one, v_s_route_setup.route_m.namespace)
            delete_deployment(kube_apis.apps_v1_api, deployment_three, v_s_route_setup.route_m.namespace)
            delete_service(kube_apis.v1, svc_three, v_s_route_setup.route_m.namespace)
            delete_deployment(kube_apis.apps_v1_api, deployment_two, v_s_route_setup.route_s.namespace)
            delete_service(kube_apis.v1, svc_two, v_s_route_setup.route_s.namespace)

    request.addfinalizer(fin)


class VirtualServerRoute:
    """
    Encapsulate  Virtual Server Route details.

    Attributes:
        namespace (str):
        name (str):
        paths ([]):
    """

    def __init__(self, namespace, name, paths):
        self.namespace = namespace
        self.name = name
        self.paths = paths

    def __str__(self):
        return f"VirtualServerRoute: namespace={self.namespace}, name={self.name}, paths={self.paths}"


class VirtualServerRouteSetup:
    """
    Encapsulate Virtual Server Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        namespace (str):
        vs_host (str):
        vs_name (str):
        route_m (VirtualServerRoute): route with multiple subroutes
        route_s (VirtualServerRoute): route with single subroute
    """

    def __init__(
        self,
        public_endpoint: PublicEndpoint,
        namespace,
        vs_host,
        vs_name,
        route_m: VirtualServerRoute,
        route_s: VirtualServerRoute,
    ):
        self.public_endpoint = public_endpoint
        self.namespace = namespace
        self.vs_host = vs_host
        self.vs_name = vs_name
        self.route_m = route_m
        self.route_s = route_s

    def __str__(self):
        return f"VirtualServerRouteSetup: namespace={self.namespace}, vs_host={self.vs_host}, vs_name={self.vs_name}, route_m={self.route_m}, route_s={self.route_s}"


@pytest.fixture(scope="class")
def v_s_route_setup(request, kube_apis, ingress_controller_endpoint) -> VirtualServerRouteSetup:
    """
    Prepare Virtual Server Route Example.

    1st namespace with VS and 1st addressed VSR and 2nd namespace with second addressed VSR.

    :param request: internal pytest fixture to parametrize this method:
        {example: virtual-server|virtual-server-tls|...}
        'example' is a directory name in TEST_DATA
    :param kube_apis: client apis
    :param crd_ingress_controller:
    :param ingress_controller_endpoint:

    :return: VirtualServerRouteSetup
    """
    vs_routes_ns = get_route_namespace_from_vs_yaml(
        f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml"
    )
    ns_1 = create_namespace_with_name_from_yaml(kube_apis.v1, vs_routes_ns[0], f"{TEST_DATA}/common/ns.yaml")
    ns_2 = create_namespace_with_name_from_yaml(kube_apis.v1, vs_routes_ns[1], f"{TEST_DATA}/common/ns.yaml")
    print("------------------------- Deploy Virtual Server -----------------------------------")
    vs_name = create_virtual_server_from_yaml(
        kube_apis.custom_objects,
        f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml",
        ns_1,
    )
    vs_host = get_first_host_from_yaml(f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml")

    print("------------------------- Deploy Virtual Server Routes -----------------------------------")
    vsr_m_name = create_v_s_route_from_yaml(
        kube_apis.custom_objects,
        f"{TEST_DATA}/{request.param['example']}/route-multiple.yaml",
        ns_1,
    )
    vsr_m_paths = get_paths_from_vsr_yaml(f"{TEST_DATA}/{request.param['example']}/route-multiple.yaml")
    route_m = VirtualServerRoute(ns_1, vsr_m_name, vsr_m_paths)

    vsr_s_name = create_v_s_route_from_yaml(
        kube_apis.custom_objects, f"{TEST_DATA}/{request.param['example']}/route-single.yaml", ns_2
    )
    vsr_s_paths = get_paths_from_vsr_yaml(f"{TEST_DATA}/{request.param['example']}/route-single.yaml")
    route_s = VirtualServerRoute(ns_2, vsr_s_name, vsr_s_paths)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up the Virtual Server Route:")
            delete_v_s_route(kube_apis.custom_objects, vsr_m_name, ns_1)
            delete_v_s_route(kube_apis.custom_objects, vsr_s_name, ns_2)
            print("Clean up Virtual Server:")
            delete_virtual_server(kube_apis.custom_objects, vs_name, ns_1)
            print("Delete test namespaces")
            delete_namespace(kube_apis.v1, ns_1)
            delete_namespace(kube_apis.v1, ns_2)

    request.addfinalizer(fin)

    return VirtualServerRouteSetup(ingress_controller_endpoint, ns_1, vs_host, vs_name, route_m, route_s)

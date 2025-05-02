from unittest import mock

import pytest
import requests
from settings import TEST_DATA
from suite.fixtures.custom_resource_fixtures import VirtualServerRoute
from suite.utils.resources_utils import (
    create_example_app,
    create_namespace_with_name_from_yaml,
    delete_namespace,
    ensure_response_from_backend,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route_from_yaml,
    create_virtual_server_from_yaml,
    patch_v_s_route_from_yaml,
)
from suite.utils.yaml_utils import get_first_host_from_yaml, get_paths_from_vsr_yaml, get_route_namespace_from_vs_yaml

resp_1 = mock.Mock()
resp_2 = mock.Mock()
resp_3 = mock.Mock()


def execute_assertions(resp_1, resp_2, resp_3):
    assert resp_1.status_code == 200
    assert "Server name: backend1-" in resp_1.text, "Expected response from backend1"
    assert resp_2.status_code == 200
    assert "Server name: backend3-" in resp_2.text, "Expected response from backend3"
    assert resp_3.status_code == 200
    assert "Server name: backend4-" in resp_3.text, "Expected response from backend4"


def ensure_responses_from_backends(req_url, host) -> None:
    ensure_response_from_backend(req_url, host, {"x-version": "future"})
    ensure_response_from_backend(req_url, host, {"x-version": "deprecated"})
    ensure_response_from_backend(req_url, host, {"x-version-invalid": "deprecated"})


class VSRAdvancedRoutingSetup:
    """
    Encapsulate advanced routing VSR example details.

    Attributes:
        namespace (str):
        vs_host (str):
        vs_name (str):
        route (VirtualServerRoute):
        backends_url (str): backend url
    """

    def __init__(self, namespace, vs_host, vs_name, route: VirtualServerRoute, backends_url):
        self.namespace = namespace
        self.vs_host = vs_host
        self.vs_name = vs_name
        self.route = route
        self.backends_url = backends_url


@pytest.fixture(scope="class")
def vsr_adv_routing_setup(
    request, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint
) -> VSRAdvancedRoutingSetup:
    """
    Prepare an example app for advanced routing VSR.

    Single namespace with VS+VSR and advanced-routing app.

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
    print("------------------------- Deploy Virtual Server -----------------------------------")
    vs_name = create_virtual_server_from_yaml(
        kube_apis.custom_objects, f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml", ns_1
    )
    vs_host = get_first_host_from_yaml(f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml")

    print("------------------------- Deploy Virtual Server Route -----------------------------------")
    vsr_name = create_v_s_route_from_yaml(
        kube_apis.custom_objects, f"{TEST_DATA}/{request.param['example']}/virtual-server-route-header.yaml", ns_1
    )
    vsr_paths = get_paths_from_vsr_yaml(f"{TEST_DATA}/{request.param['example']}/virtual-server-route-header.yaml")
    route = VirtualServerRoute(ns_1, vsr_name, vsr_paths)
    backends_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}{vsr_paths[0]}"

    print("---------------------- Deploy advanced-routing app ----------------------------")
    create_example_app(kube_apis, "advanced-routing", ns_1)
    wait_until_all_pods_are_ready(kube_apis.v1, ns_1)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete test namespace")
            delete_namespace(kube_apis.v1, ns_1)

    request.addfinalizer(fin)

    return VSRAdvancedRoutingSetup(ns_1, vs_host, vs_name, route, backends_url)


@pytest.mark.vsr
@pytest.mark.vsr_routing
@pytest.mark.parametrize(
    "crd_ingress_controller, vsr_adv_routing_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-route-advanced-routing"},
        )
    ],
    indirect=True,
)
class TestVSRAdvancedRouting:
    def test_flow_with_header(self, kube_apis, crd_ingress_controller, vsr_adv_routing_setup):
        ensure_responses_from_backends(vsr_adv_routing_setup.backends_url, vsr_adv_routing_setup.vs_host)
        wait_before_test()
        global resp_1, resp_2, resp_3
        resp_1.status_code = resp_2.status_code = resp_3.status_code = 502
        while resp_1.status_code == 502 and resp_2.status_code == 502 and resp_3.status_code == 502:
            resp_1 = requests.get(
                vsr_adv_routing_setup.backends_url,
                headers={"host": vsr_adv_routing_setup.vs_host, "x-version": "future"},
            )
            resp_2 = requests.get(
                vsr_adv_routing_setup.backends_url,
                headers={"host": vsr_adv_routing_setup.vs_host, "x-version": "deprecated"},
            )
            resp_3 = requests.get(
                vsr_adv_routing_setup.backends_url,
                headers={"host": vsr_adv_routing_setup.vs_host, "x-version-invalid": "deprecated"},
            )
        execute_assertions(resp_1, resp_2, resp_3)

    def test_flow_with_argument(self, kube_apis, crd_ingress_controller, vsr_adv_routing_setup):
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            vsr_adv_routing_setup.route.name,
            f"{TEST_DATA}/virtual-server-route-advanced-routing/virtual-server-route-argument.yaml",
            vsr_adv_routing_setup.namespace,
        )
        ensure_response_from_backend(vsr_adv_routing_setup.backends_url, vsr_adv_routing_setup.vs_host, check404=True)
        wait_before_test()
        global resp_1, resp_2, resp_3
        resp_1.status_code = resp_2.status_code = resp_3.status_code = 502
        while resp_1.status_code == 502 and resp_2.status_code == 502 and resp_3.status_code == 502:
            resp_1 = requests.get(
                vsr_adv_routing_setup.backends_url + "?arg1=v1", headers={"host": vsr_adv_routing_setup.vs_host}
            )
            resp_2 = requests.get(
                vsr_adv_routing_setup.backends_url + "?arg1=v2", headers={"host": vsr_adv_routing_setup.vs_host}
            )
            resp_3 = requests.get(
                vsr_adv_routing_setup.backends_url + "?argument1=v1", headers={"host": vsr_adv_routing_setup.vs_host}
            )
        execute_assertions(resp_1, resp_2, resp_3)

    def test_flow_with_cookie(self, kube_apis, crd_ingress_controller, vsr_adv_routing_setup):
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            vsr_adv_routing_setup.route.name,
            f"{TEST_DATA}/virtual-server-route-advanced-routing/virtual-server-route-cookie.yaml",
            vsr_adv_routing_setup.namespace,
        )
        ensure_response_from_backend(vsr_adv_routing_setup.backends_url, vsr_adv_routing_setup.vs_host, check404=True)
        wait_before_test()
        global resp_1, resp_2, resp_3
        resp_1.status_code = resp_2.status_code = resp_3.status_code = 502
        while resp_1.status_code == 502 and resp_2.status_code == 502 and resp_3.status_code == 502:
            resp_1 = requests.get(
                vsr_adv_routing_setup.backends_url,
                headers={"host": vsr_adv_routing_setup.vs_host},
                cookies={"user": "some"},
            )
            resp_2 = requests.get(
                vsr_adv_routing_setup.backends_url,
                headers={"host": vsr_adv_routing_setup.vs_host},
                cookies={"user": "bad"},
            )
            resp_3 = requests.get(
                vsr_adv_routing_setup.backends_url,
                headers={"host": vsr_adv_routing_setup.vs_host},
                cookies={"user": "anonymous"},
            )
        execute_assertions(resp_1, resp_2, resp_3)

    def test_flow_with_variable(self, kube_apis, crd_ingress_controller, vsr_adv_routing_setup):
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            vsr_adv_routing_setup.route.name,
            f"{TEST_DATA}/virtual-server-route-advanced-routing/virtual-server-route-variable.yaml",
            vsr_adv_routing_setup.namespace,
        )
        ensure_response_from_backend(vsr_adv_routing_setup.backends_url, vsr_adv_routing_setup.vs_host, check404=True)
        wait_before_test()
        global resp_1, resp_2, resp_3
        resp_1.status_code = resp_2.status_code = resp_3.status_code = 502
        while resp_1.status_code == 502 and resp_2.status_code == 502 and resp_3.status_code == 502:
            resp_1 = requests.get(vsr_adv_routing_setup.backends_url, headers={"host": vsr_adv_routing_setup.vs_host})
            resp_2 = requests.post(vsr_adv_routing_setup.backends_url, headers={"host": vsr_adv_routing_setup.vs_host})
            resp_3 = requests.put(vsr_adv_routing_setup.backends_url, headers={"host": vsr_adv_routing_setup.vs_host})
        execute_assertions(resp_1, resp_2, resp_3)

    def test_flow_with_complex_conditions(self, kube_apis, crd_ingress_controller, vsr_adv_routing_setup):
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            vsr_adv_routing_setup.route.name,
            f"{TEST_DATA}/virtual-server-route-advanced-routing/virtual-server-route-complex.yaml",
            vsr_adv_routing_setup.namespace,
        )
        ensure_response_from_backend(vsr_adv_routing_setup.backends_url, vsr_adv_routing_setup.vs_host, check404=True)
        wait_before_test()
        global resp_1, resp_2, resp_3
        resp_1.status_code = resp_2.status_code = resp_3.status_code = 502
        while resp_1.status_code == 502 and resp_2.status_code == 502 and resp_3.status_code == 502:
            resp_1 = requests.get(
                vsr_adv_routing_setup.backends_url + "?arg1=v1",
                headers={"host": vsr_adv_routing_setup.vs_host, "x-version": "future"},
                cookies={"user": "some"},
            )
            resp_2 = requests.post(
                vsr_adv_routing_setup.backends_url + "?arg1=v2",
                headers={"host": vsr_adv_routing_setup.vs_host, "x-version": "deprecated"},
                cookies={"user": "bad"},
            )
            resp_3 = requests.get(
                vsr_adv_routing_setup.backends_url + "?arg1=v2",
                headers={"host": vsr_adv_routing_setup.vs_host, "x-version": "deprecated"},
                cookies={"user": "bad"},
            )
        execute_assertions(resp_1, resp_2, resp_3)

import pytest
import requests
import yaml
from settings import TEST_DATA
from suite.fixtures.custom_resource_fixtures import VirtualServerRoute
from suite.utils.resources_utils import (
    create_example_app,
    create_namespace_with_name_from_yaml,
    delete_namespace,
    ensure_response_from_backend,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import create_v_s_route_from_yaml, create_virtual_server_from_yaml
from suite.utils.yaml_utils import get_first_host_from_yaml, get_paths_from_vsr_yaml, get_route_namespace_from_vs_yaml
from yaml.loader import Loader


def get_weights_of_splitting(file) -> []:
    """
    Parse VSR yaml file into an array of weights.

    :param file: an absolute path to file
    :return: []
    """
    weights = []
    with open(file) as f:
        docs = yaml.load_all(f, Loader=Loader)
        for dep in docs:
            for item in dep["spec"]["subroutes"][0]["matches"][0]["splits"]:
                weights.append(item["weight"])
    return weights


def get_upstreams_of_splitting(file) -> []:
    """
    Parse VSR yaml file into an array of upstreams.

    :param file: an absolute path to file
    :return: []
    """
    upstreams = []
    with open(file) as f:
        docs = yaml.load_all(f, Loader=Loader)
        for dep in docs:
            for item in dep["spec"]["subroutes"][0]["matches"][0]["splits"]:
                upstreams.append(item["action"]["pass"])
    return upstreams


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
def vsr_canary_setup(
    request, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint
) -> VSRAdvancedRoutingSetup:
    """
    Prepare an example app for advanced routing VSR.

    Single namespace with VS+VSR and simple app.

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
        kube_apis.custom_objects, f"{TEST_DATA}/{request.param['example']}/virtual-server-route.yaml", ns_1
    )
    vsr_paths = get_paths_from_vsr_yaml(f"{TEST_DATA}/{request.param['example']}/virtual-server-route.yaml")
    route = VirtualServerRoute(ns_1, vsr_name, vsr_paths)
    backends_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}{vsr_paths[0]}"

    print("---------------------- Deploy simple app ----------------------------")
    create_example_app(kube_apis, "simple", ns_1)
    wait_until_all_pods_are_ready(kube_apis.v1, ns_1)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete test namespace")
            delete_namespace(kube_apis.v1, ns_1)

    request.addfinalizer(fin)

    return VSRAdvancedRoutingSetup(ns_1, vs_host, vs_name, route, backends_url)


@pytest.mark.flaky(max_runs=3)
@pytest.mark.vsr
@pytest.mark.vsr_canary
@pytest.mark.parametrize(
    "crd_ingress_controller, vsr_canary_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-route-focused-canary"},
        )
    ],
    indirect=True,
)
class TestVSRFocusedCanaryRelease:
    def test_flow_with_header(self, kube_apis, crd_ingress_controller, vsr_canary_setup):
        ensure_response_from_backend(vsr_canary_setup.backends_url, vsr_canary_setup.vs_host)

        weights = get_weights_of_splitting(f"{TEST_DATA}/virtual-server-route-focused-canary/virtual-server-route.yaml")
        upstreams = get_upstreams_of_splitting(
            f"{TEST_DATA}/virtual-server-route-focused-canary/virtual-server-route.yaml"
        )
        sum_weights = sum(weights)
        ratios = [round(i / sum_weights, 1) for i in weights]

        counter_v1, counter_v2 = 0, 0
        for _ in range(100):
            ensure_response_from_backend(
                vsr_canary_setup.backends_url, vsr_canary_setup.vs_host, {"x-version": "canary"}, check404=True
            )
            status_code = 502
            while status_code == 502:
                resp = requests.get(
                    vsr_canary_setup.backends_url, headers={"host": vsr_canary_setup.vs_host, "x-version": "canary"}
                )
                status_code = resp.status_code

            if upstreams[0] in resp.text in resp.text:
                counter_v1 = counter_v1 + 1
            elif upstreams[1] in resp.text in resp.text:
                counter_v2 = counter_v2 + 1
            else:
                pytest.fail(f"An unexpected backend in response: {resp.text}")

        assert abs(round(counter_v1 / (counter_v1 + counter_v2), 1) - ratios[0]) <= 0.2
        assert abs(round(counter_v2 / (counter_v1 + counter_v2), 1) - ratios[1]) <= 0.2

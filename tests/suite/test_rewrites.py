import pytest
import requests
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_items_from_yaml,
    delete_items_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route_from_yaml,
    create_virtual_server_from_yaml,
    delete_v_s_route,
    delete_virtual_server,
)

hello_app_yaml = f"{TEST_DATA}/rewrites/hello.yaml"


@pytest.fixture(scope="class")
def hello_app(request, kube_apis, test_namespace):
    create_items_from_yaml(kube_apis, hello_app_yaml, test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            delete_items_from_yaml(kube_apis, hello_app_yaml, test_namespace)

    request.addfinalizer(fin)


class RewritesSetup:
    def __init__(self, public_endpoint):
        self.url_base = f"http://{public_endpoint.public_ip}:{public_endpoint.port}"


vs_yaml = f"{TEST_DATA}/rewrites/virtual-server-rewrite.yaml"


@pytest.fixture(scope="class")
def vs_rewrites_setup(
    request, kube_apis, test_namespace, hello_app, ingress_controller_endpoint, crd_ingress_controller
):
    vs = create_virtual_server_from_yaml(kube_apis.custom_objects, vs_yaml, test_namespace)
    wait_before_test()

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            delete_virtual_server(kube_apis.custom_objects, vs, test_namespace)

    request.addfinalizer(fin)

    return RewritesSetup(ingress_controller_endpoint)


vs_parent_yaml = f"{TEST_DATA}/rewrites/virtual-server-parent.yaml"
vsr_prefixes_yaml = f"{TEST_DATA}/rewrites/virtual-server-route-prefixes.yaml"
vsr_regex1_yaml = f"{TEST_DATA}/rewrites/virtual-server-route-regex1.yaml"
vsr_regex2_yaml = f"{TEST_DATA}/rewrites/virtual-server-route-regex2.yaml"


@pytest.fixture(scope="class")
def vsr_rewrites_setup(
    request, kube_apis, test_namespace, hello_app, ingress_controller_endpoint, crd_ingress_controller
):
    vs_parent = create_virtual_server_from_yaml(kube_apis.custom_objects, vs_parent_yaml, test_namespace)
    vsr_prefixes = create_v_s_route_from_yaml(kube_apis.custom_objects, vsr_prefixes_yaml, test_namespace)
    vsr_regex1 = create_v_s_route_from_yaml(kube_apis.custom_objects, vsr_regex1_yaml, test_namespace)
    vsr_regex2 = create_v_s_route_from_yaml(kube_apis.custom_objects, vsr_regex2_yaml, test_namespace)
    wait_before_test()

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            delete_virtual_server(kube_apis.custom_objects, vs_parent, test_namespace)
            delete_v_s_route(kube_apis.custom_objects, vsr_prefixes, test_namespace)
            delete_v_s_route(kube_apis.custom_objects, vsr_regex1, test_namespace)
            delete_v_s_route(kube_apis.custom_objects, vsr_regex2, test_namespace)

    request.addfinalizer(fin)

    return RewritesSetup(ingress_controller_endpoint)


test_data = [
    ("/backend1/", {"arg": "value"}, {}, "/?arg=value"),
    ("/backend1/abc", {"arg": "value"}, {}, "/abc?arg=value"),
    ("/backend2", {"arg": "value"}, {}, "/backend2_1?arg=value"),
    ("/backend2/", {"arg": "value"}, {}, "/backend2_1/?arg=value"),
    ("/backend2/abc", {"arg": "value"}, {}, "/backend2_1/abc?arg=value"),
    ("/match/", {"arg": "value"}, {}, "/?arg=value"),
    ("/match/abc", {"arg": "value"}, {}, "/abc?arg=value"),
    ("/match/", {"arg": "value"}, {"user": "john"}, "/user/john/?arg=value"),
    ("/match/abc", {"arg": "value"}, {"user": "john"}, "/user/john/abc?arg=value"),
    ("/regex1/", {"arg": "value"}, {}, "/?arg=value"),
    ("/regex1//", {"arg": "value"}, {}, "/?arg=value"),
    ("/regex2/abc", {"arg": "value"}, {}, "/abc?arg=value"),
]


@pytest.mark.parametrize("crd_ingress_controller", [{"type": "complete"}], indirect=True)
class TestRewrites:
    @pytest.mark.vs
    @pytest.mark.vs_rewrite
    @pytest.mark.parametrize("path,args,cookies,expected", test_data)
    def test_vs_rewrite(self, vs_rewrites_setup, path, args, cookies, expected):
        """
        Test VirtualServer URI rewrite
        """
        url = vs_rewrites_setup.url_base + path
        resp = requests.get(url, headers={"host": "vs.example.com"}, params=args, cookies=cookies)

        assert f"URI: {expected}\nRequest" in resp.text

    @pytest.mark.vsr
    @pytest.mark.vsr_rewrite
    @pytest.mark.parametrize("path,args,cookies,expected", test_data)
    def test_vsr_rewrite(self, vsr_rewrites_setup, path, args, cookies, expected):
        """
        Test VirtualServerRoute URI rewrite
        """
        url = vsr_rewrites_setup.url_base + path
        resp = requests.get(url, headers={"host": "vsr.example.com"}, params=args, cookies=cookies)

        assert f"URI: {expected}\nRequest" in resp.text

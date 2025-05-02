import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_event, assert_vs_conf_not_exists
from suite.utils.resources_utils import (
    create_example_app,
    ensure_response_from_backend,
    get_events,
    get_first_pod_name,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route_from_yaml,
    create_virtual_server_from_yaml,
    get_vs_nginx_template_conf,
    patch_v_s_route_from_yaml,
    patch_virtual_server_from_yaml,
)
from suite.utils.yaml_utils import get_first_host_from_yaml


@pytest.mark.vsr
@pytest.mark.vsr_regexes
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-route-regexp-location"},
        )
    ],
    indirect=True,
)
class TestRegexpLocation:
    @pytest.mark.parametrize(
        "test_data",
        [
            pytest.param(
                {
                    "regex_type": "exact",
                    "expected_results": {
                        "/exact-match$request": 200,
                        "/exact-match$request/": 404,
                        "/exact-match$request?var1=value": 200,
                    },
                },
                id="exact",
            ),
            pytest.param(
                {
                    "regex_type": "case-sensitive",
                    "expected_results": {
                        "/case-SENsitiVe/match": 200,
                        "/case-sensitive/match/": 404,
                        "/case-SENsitiVe/match/": 200,
                    },
                },
                id="case-sensitive",
            ),
            pytest.param(
                {
                    "regex_type": "case-insensitive",
                    "expected_results": {
                        "/case-inSENsitiVe/match": 200,
                        "/case-insensitive/match/": 200,
                        "/case-inSENsitiVe/match/": 200,
                    },
                },
                id="case-insensitive",
            ),
        ],
    )
    def test_response_for_regex_location(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_setup,
        v_s_route_app_setup,
        test_data,
    ):
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        vs_src_yaml = (
            f"{TEST_DATA}"
            f"/virtual-server-route-regexp-location/standard/virtual-server-{test_data['regex_type']}.yaml"
        )
        vsr_src_yaml = f"{TEST_DATA}/virtual-server-route-regexp-location/route-single-{test_data['regex_type']}.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, vs_src_yaml, v_s_route_setup.namespace
        )
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.route_s.name, vsr_src_yaml, v_s_route_setup.route_s.namespace
        )
        wait_before_test(1)

        for item in test_data["expected_results"]:
            uri = item
            expected_code = test_data["expected_results"][uri]
            ensure_response_from_backend(f"{req_url}{uri}", v_s_route_setup.vs_host)
            resp = requests.get(f"{req_url}{uri}", headers={"host": v_s_route_setup.vs_host})
            if expected_code == 200:
                assert resp.status_code == expected_code and "Server name: backend2-" in resp.text
            else:
                assert resp.status_code == expected_code, "Expected 404 for URI that doesn't match"

    def test_flow_for_invalid_vs(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, v_s_route_setup, v_s_route_app_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        text_vs = f"{v_s_route_setup.namespace}/{v_s_route_setup.vs_name}"
        vs_event_text = (
            f"VirtualServer {text_vs} was rejected with error: "
            f'spec.routes[1].path: Duplicate value: "=/exact-match$request"'
        )
        vs_src_yaml = (
            f"{TEST_DATA}"
            f"/virtual-server-route-regexp-location/standard/virtual-server-invalid-duplicate-routes.yaml"
        )
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, vs_src_yaml, v_s_route_setup.namespace
        )
        wait_before_test(2)

        vs_events = get_events(kube_apis.v1, v_s_route_setup.namespace)
        assert_vs_conf_not_exists(kube_apis, ic_pod_name, ingress_controller_prerequisites.namespace, v_s_route_setup)
        assert_event(vs_event_text, vs_events)

    def test_flow_for_invalid_vsr(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, v_s_route_setup, v_s_route_app_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        text_vs = f"{v_s_route_setup.namespace}/{v_s_route_setup.vs_name}"
        text_vsr_s = f"{v_s_route_setup.route_m.namespace}/{v_s_route_setup.route_m.name}"
        vs_event_text = f"Configuration for {text_vs} was added or updated with warning(s)"
        vsr_event_text = (
            f"VirtualServerRoute {text_vsr_s} was rejected with error: "
            f'spec.subroutes[1].path: Duplicate value: "=/backends/exact-match$request"'
        )
        vs_src_yaml = f"{TEST_DATA}" f"/virtual-server-route-regexp-location/standard/virtual-server-exact.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, vs_src_yaml, v_s_route_setup.namespace
        )
        vsr_src_yaml = (
            f"{TEST_DATA}"
            f"/virtual-server-route-regexp-location/route-multiple-invalid-multiple-regexp-subroutes.yaml"
        )
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.route_m.name, vsr_src_yaml, v_s_route_setup.route_m.namespace
        )
        wait_before_test(2)

        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        ns_events = get_events(kube_apis.v1, v_s_route_setup.route_m.namespace)
        assert_event(vsr_event_text, ns_events) and assert_event(vs_event_text, ns_events)
        assert "location =/backends/exact-match$request {" not in config


class VSRRegexpSetup:
    """
    Encapsulate advanced routing VSR example details.

    Attributes:
        namespace (str):
        vs_host (str):
        vs_name (str):
    """

    def __init__(self, namespace, vs_host, vs_name):
        self.namespace = namespace
        self.vs_host = vs_host
        self.vs_name = vs_name


@pytest.fixture(scope="class")
def vsr_regexp_setup(
    request, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint, test_namespace
) -> VSRRegexpSetup:
    """
    Prepare an example app for advanced routing VSR.

    Single namespace with VS+VSR and simple app.

    :param request: internal pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint:
    :param ingress_controller_prerequisites:
    :param test_namespace:
    :return:
    """
    print("------------------------- Deploy Virtual Server -----------------------------------")
    vs_src_yaml = f"{TEST_DATA}/{request.param['example']}/additional-case/virtual-server-exact-over-all.yaml"
    vs_name = create_virtual_server_from_yaml(kube_apis.custom_objects, vs_src_yaml, test_namespace)
    vs_host = get_first_host_from_yaml(vs_src_yaml)

    print("------------------------- Deploy VSRs -----------------------------------")
    for item in ["prefix", "exact", "regexp"]:
        create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/{request.param['example']}/additional-case/route-{item}.yaml",
            test_namespace,
        )

    print("---------------------- Deploy simple app ----------------------------")
    create_example_app(kube_apis, "extended", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    return VSRRegexpSetup(test_namespace, vs_host, vs_name)


@pytest.mark.vsr
@pytest.mark.vsr_regexes
@pytest.mark.parametrize(
    "crd_ingress_controller, vsr_regexp_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-route-regexp-location"},
        )
    ],
    indirect=True,
)
class TestVSRRegexpMultipleMatches:
    def test_exact_match_overrides_all(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller,
        vsr_regexp_setup,
    ):
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}"
        ensure_response_from_backend(f"{req_url}/backends/match", vsr_regexp_setup.vs_host)
        resp = requests.get(f"{req_url}/backends/match", headers={"host": vsr_regexp_setup.vs_host})
        assert resp.status_code == 200 and "Server name: backend2-" in resp.text

    def test_regexp_overrides_prefix(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller,
        vsr_regexp_setup,
    ):
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}"
        vs_src_yaml = (
            f"{TEST_DATA}"
            f"/virtual-server-route-regexp-location/additional-case/virtual-server-regexp-over-prefix.yaml"
        )
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, vsr_regexp_setup.vs_name, vs_src_yaml, vsr_regexp_setup.namespace
        )
        wait_before_test(1)
        ensure_response_from_backend(f"{req_url}/backends/match", vsr_regexp_setup.vs_host)
        resp = requests.get(f"{req_url}/backends/match", headers={"host": vsr_regexp_setup.vs_host})
        assert resp.status_code == 200 and "Server name: backend3-" in resp.text

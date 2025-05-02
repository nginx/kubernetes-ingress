import json

import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_event_starts_with_text_and_contains_errors, wait_and_assert_status_code
from suite.utils.resources_utils import get_events, get_first_pod_name, wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    get_vs_nginx_template_conf,
    patch_v_s_route_from_yaml,
    patch_virtual_server_from_yaml,
)


@pytest.mark.vsr
@pytest.mark.vsr_error_pages
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-route-error-pages"},
        )
    ],
    indirect=True,
)
class TestVSRErrorPages:
    def test_redirect_strategy(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, v_s_route_setup
    ):
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        wait_and_assert_status_code(
            307, f"{req_url}{v_s_route_setup.route_m.paths[0]}", v_s_route_setup.vs_host, allow_redirects=False
        )
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
            allow_redirects=False,
        )
        assert f"http://{v_s_route_setup.vs_host}/error.html" in resp.next.url

    def test_return_strategy(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, v_s_route_setup
    ):
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        wait_and_assert_status_code(207, f"{req_url}{v_s_route_setup.route_m.paths[1]}", v_s_route_setup.vs_host)
        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[1]}", headers={"host": v_s_route_setup.vs_host})
        resp_content = json.loads(resp.content)
        assert (
            resp_content["status"] == "502"
            and resp_content["message"] == "Forbidden"
            and resp.headers.get("x-debug-original-status") == "502"
        )

    def test_virtual_server_after_update(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, v_s_route_setup
    ):
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            f"{TEST_DATA}/virtual-server-route-error-pages/route-multiple-updated.yaml",
            v_s_route_setup.route_m.namespace,
        )
        wait_and_assert_status_code(
            301, f"{req_url}{v_s_route_setup.route_m.paths[0]}", v_s_route_setup.vs_host, allow_redirects=False
        )
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host, "x-forwarded-proto": "http"},
            allow_redirects=False,
        )
        assert f"http://{v_s_route_setup.vs_host}/error_http.html" in resp.next.url

        wait_and_assert_status_code(
            502, f"{req_url}{v_s_route_setup.route_m.paths[1]}", v_s_route_setup.vs_host, allow_redirects=False
        )
        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[1]}", headers={"host": v_s_route_setup.vs_host})
        resp_content = resp.content.decode("utf-8")
        assert resp_content == "Hello World!\n"

    def test_validation_event_flow(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, v_s_route_setup
    ):
        invalid_fields_m = [
            "spec.subroutes[0].errorPages[0].redirect.url: Invalid value",
            "spec.subroutes[0].errorPages[0].redirect.code: Invalid value: 101",
            'spec.subroutes[1].errorPages[0].return.body: Invalid value: "status"',
            "spec.subroutes[1].errorPages[0].return.code: Invalid value: 100",
            'spec.subroutes[1].errorPages[0].return.headers[0].value: Invalid value: "schema"',
        ]
        invalid_fields_s = ["spec.subroutes[0].errorPages[0].redirect.url: Required value: must specify a url"]
        text_s = f"{v_s_route_setup.route_s.namespace}/{v_s_route_setup.route_s.name}"
        text_m = f"{v_s_route_setup.route_m.namespace}/{v_s_route_setup.route_m.name}"
        vsr_s_event_text = f"VirtualServerRoute {text_s} was rejected with error:"
        vsr_m_event_text = f"VirtualServerRoute {text_m} was rejected with error:"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_s.name,
            f"{TEST_DATA}/virtual-server-route-error-pages/route-single-invalid.yaml",
            v_s_route_setup.route_s.namespace,
        )
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            f"{TEST_DATA}/virtual-server-route-error-pages/route-multiple-invalid.yaml",
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test(2)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        vsr_s_events = get_events(kube_apis.v1, v_s_route_setup.route_s.namespace)
        vsr_m_events = get_events(kube_apis.v1, v_s_route_setup.route_m.namespace)

        assert_event_starts_with_text_and_contains_errors(vsr_s_event_text, vsr_s_events, invalid_fields_s)
        assert_event_starts_with_text_and_contains_errors(vsr_m_event_text, vsr_m_events, invalid_fields_m)
        assert "upstream" not in config

    def test_openapi_validation_flow(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, v_s_route_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config_old = get_vs_nginx_template_conf(
            kube_apis.v1,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        vsr_src = f"{TEST_DATA}/virtual-server-route-error-pages/route-multiple-invalid-openapi.yaml"
        try:
            patch_v_s_route_from_yaml(
                kube_apis.custom_objects, v_s_route_setup.route_m.name, vsr_src, v_s_route_setup.route_m.namespace
            )
        except ApiException as ex:
            assert (
                ex.status == 422
                and "codes in body must be of type" in ex.body
                and "redirect.code in body must be of type" in ex.body
                and "redirect.url in body must be of type" in ex.body
                and "return.code in body must be of type" in ex.body
                and "return.type in body must be of type" in ex.body
                and "return.body in body must be of type" in ex.body
                and "name in body must be of type" in ex.body
                and "value in body must be of type" in ex.body
            )
        except Exception as ex:
            pytest.fail(f"An unexpected exception is raised: {ex}")
        else:
            pytest.fail("Expected an exception but there was none")

        wait_before_test(1)
        config_new = get_vs_nginx_template_conf(
            kube_apis.v1,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert config_old == config_new, "Expected: config doesn't change"

    @pytest.mark.parametrize(
        "v_s_r_data",
        [
            {"src": "route-multiple-splits.yaml", "expected_code": 308},
            {"src": "route-multiple-matches.yaml", "expected_code": 307},
        ],
    )
    def test_splits_and_matches(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, v_s_route_setup, v_s_r_data
    ):
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            f"{TEST_DATA}/virtual-server-route-error-pages/{v_s_r_data['src']}",
            v_s_route_setup.route_m.namespace,
        )
        wait_and_assert_status_code(
            v_s_r_data["expected_code"],
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            allow_redirects=False,
        )
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
            allow_redirects=False,
        )
        assert f"http://{v_s_route_setup.vs_host}/error.html" in resp.next.url

    def test_vsr_overrides_vs(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, v_s_route_setup
    ):
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        vs_src = f"{TEST_DATA}/virtual-server-route-error-pages/standard/virtual-server-updated.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, vs_src, v_s_route_setup.namespace
        )
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            f"{TEST_DATA}/virtual-server-route-error-pages/route-multiple.yaml",
            v_s_route_setup.route_m.namespace,
        )
        wait_and_assert_status_code(
            307, f"{req_url}{v_s_route_setup.route_m.paths[0]}", v_s_route_setup.vs_host, allow_redirects=False
        )
        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
            allow_redirects=False,
        )
        assert f"http://{v_s_route_setup.vs_host}/error.html" in resp.next.url

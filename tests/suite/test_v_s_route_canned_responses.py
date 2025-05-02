import json

import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    assert_event_and_get_count,
    assert_event_count_increased,
    assert_event_starts_with_text_and_contains_errors,
    wait_and_assert_status_code,
)
from suite.utils.resources_utils import get_events, get_first_pod_name, wait_before_test
from suite.utils.vs_vsr_resources_utils import get_vs_nginx_template_conf, patch_v_s_route_from_yaml


@pytest.mark.vsr
@pytest.mark.vsr_canned
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-route-canned-responses"},
        )
    ],
    indirect=True,
)
class TestVSRCannedResponses:
    def test_config(self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, v_s_route_setup):
        wait_before_test(1)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "error_page 418 =407" in config and "error_page 418 =200" in config

    def test_custom_canned_response(self, kube_apis, crd_ingress_controller, v_s_route_setup):
        req_host = f"{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        req_url = f"http://{req_host}{v_s_route_setup.route_m.paths[0]}?arg1=arg"
        wait_and_assert_status_code(407, req_url, v_s_route_setup.vs_host)
        resp = requests.get(req_url, headers={"host": v_s_route_setup.vs_host})
        resp_content = json.loads(resp.content)
        assert (
            resp.headers["content-type"] == "application/json"
            and resp_content["host"] == v_s_route_setup.vs_host
            and resp_content["request_time"] != ""
            and resp_content["pid"] != ""
            and resp_content["server_protocol"] == "HTTP/1.1"
            and resp_content["connections_active"] != ""
            and resp_content["connections_writing"] != ""
            and resp_content["request_uri"] == f"{v_s_route_setup.route_m.paths[0]}?arg1=arg"
            and resp_content["remote_addr"] != ""
            and resp_content["remote_port"] != ""
            and resp_content["server_addr"] != ""
            and resp_content["request_method"] == "GET"
            and resp_content["scheme"] == "http"
            and resp_content["request_length"] != ""
            and resp_content["nginx_version"] != ""
            and resp_content["connection"] != ""
            and resp_content["time_local"] != ""
            and resp_content["server_port"] != ""
            and resp_content["server_name"] == v_s_route_setup.vs_host
            and resp_content["connections_waiting"] != ""
            and resp_content["request_body"] == ""
            and resp_content["args"] == "arg1=arg"
            and resp_content["time_iso8601"] != ""
            and resp_content["connections_reading"] != ""
        )

    def test_default_canned_response(self, kube_apis, crd_ingress_controller, v_s_route_setup):
        req_host = f"{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        req_url = f"http://{req_host}{v_s_route_setup.route_m.paths[1]}"
        wait_and_assert_status_code(200, req_url, v_s_route_setup.vs_host)
        resp = requests.get(req_url, headers={"host": v_s_route_setup.vs_host})
        resp_content = resp.content.decode("utf-8")
        assert resp.headers["content-type"] == "text/plain" and resp_content == "line1\nline2\nline3\n"

    def test_update(self, kube_apis, crd_ingress_controller, v_s_route_setup):
        req_host = f"{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        req_url_1 = f"http://{req_host}{v_s_route_setup.route_m.paths[0]}"
        req_url_2 = f"http://{req_host}{v_s_route_setup.route_m.paths[1]}"
        wait_before_test(1)
        vs_name = f"{v_s_route_setup.namespace}/{v_s_route_setup.vs_name}"
        vsr_name = f"{v_s_route_setup.namespace}/{v_s_route_setup.route_m.name}"
        vsr_event_text = f"Configuration for {vsr_name} was added or updated"
        vs_event_text = f"Configuration for {vs_name} was added or updated"
        events_ns = get_events(kube_apis.v1, v_s_route_setup.namespace)
        initial_count_vs = assert_event_and_get_count(vs_event_text, events_ns)
        initial_count_vsr = assert_event_and_get_count(vsr_event_text, events_ns)
        vsr_src = f"{TEST_DATA}/virtual-server-route-canned-responses/route-multiple-updated.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.route_m.name, vsr_src, v_s_route_setup.namespace
        )
        wait_and_assert_status_code(501, req_url_1, v_s_route_setup.vs_host)
        resp = requests.get(req_url_1, headers={"host": v_s_route_setup.vs_host})
        resp_content = resp.content.decode("utf-8")
        assert resp.headers["content-type"] == "some/type" and resp_content == "{}"

        wait_and_assert_status_code(201, req_url_2, v_s_route_setup.vs_host)
        resp = requests.get(req_url_2, headers={"host": v_s_route_setup.vs_host})
        resp_content = resp.content.decode("utf-8")
        assert (
            resp.headers["content-type"] == "user-type"
            and resp_content == "line1\nline2"
            and resp.headers["coffee-test-header"] == "espresso"
        )

        new_events_ns = get_events(kube_apis.v1, v_s_route_setup.namespace)
        assert_event_count_increased(vs_event_text, initial_count_vs, new_events_ns)
        assert_event_count_increased(vsr_event_text, initial_count_vsr, new_events_ns)

    @pytest.mark.flaky(max_runs=3)
    def test_validation_flow(self, kube_apis, crd_ingress_controller, v_s_route_setup):
        invalid_fields = ["spec.subroutes[0].action.return.code", "spec.subroutes[0].action.return.body"]
        req_host = f"{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        req_url = f"http://{req_host}{v_s_route_setup.route_s.paths[0]}"
        text = f"{v_s_route_setup.namespace}/{v_s_route_setup.route_m.name}"
        vsr_m_event_text = f"VirtualServerRoute {text} was rejected with error:"
        vsr_src = f"{TEST_DATA}/virtual-server-route-canned-responses/route-multiple-invalid.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.route_m.name, vsr_src, v_s_route_setup.namespace
        )
        wait_before_test(1)

        wait_and_assert_status_code(404, req_url, v_s_route_setup.vs_host)
        events = get_events(kube_apis.v1, v_s_route_setup.route_m.namespace)
        assert_event_starts_with_text_and_contains_errors(vsr_m_event_text, events, invalid_fields)

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
        vsr_src = f"{TEST_DATA}/virtual-server-route-canned-responses/route-multiple-invalid-openapi.yaml"
        try:
            patch_v_s_route_from_yaml(
                kube_apis.custom_objects, v_s_route_setup.route_m.name, vsr_src, v_s_route_setup.namespace
            )
        except ApiException as ex:
            assert (
                ex.status == 422
                and "action.return.type in body must be of type" in ex.body
                and "action.return.body in body must be of type" in ex.body
                and "action.return.code in body must be of type" in ex.body
                and "action.return.headers in body must be of type" in ex.body
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

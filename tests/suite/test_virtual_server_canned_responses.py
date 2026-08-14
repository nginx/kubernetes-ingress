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
from suite.utils.resources_utils import (
    get_events,
    get_first_pod_name,
    get_vs_nginx_template_conf,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import patch_virtual_server_from_yaml


@pytest.mark.vs
@pytest.mark.vs_responses
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-canned-responses", "app_type": None},
        )
    ],
    indirect=True,
)
class TestVSCannedResponse:
    def test_config(self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "error_page 418 =407" in config and "error_page 418 =200" in config

    def test_custom_canned_response(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        req_url = f"{virtual_server_setup.backend_1_url}?arg1=arg"
        wait_and_assert_status_code(407, req_url, virtual_server_setup.vs_host)
        resp = requests.get(req_url, headers={"host": virtual_server_setup.vs_host})
        resp_content = json.loads(resp.content)
        assert (
            resp.headers["content-type"] == "application/json"
            and resp_content["host"] == virtual_server_setup.vs_host
            and resp_content["request_time"] != ""
            and resp_content["pid"] != ""
            and resp_content["server_protocol"] == "HTTP/1.1"
            and resp_content["connections_active"] != ""
            and resp_content["connections_writing"] != ""
            and resp_content["request_uri"] == "/canned-response?arg1=arg"
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
            and resp_content["server_name"] == virtual_server_setup.vs_host
            and resp_content["connections_waiting"] != ""
            and resp_content["request_body"] == ""
            and resp_content["args"] == "arg1=arg"
            and resp_content["time_iso8601"] != ""
            and resp_content["connections_reading"] != ""
        )

    def test_default_canned_response(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)
        resp = requests.get(virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host})
        resp_content = resp.content.decode("utf-8")
        assert (
            resp.headers["content-type"] == "text/plain"
            and resp_content == "line1\nline2\nline3\n"
            and resp.headers["coffee-test-header"] == "espresso"
        )

    def test_update(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        wait_before_test(1)
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"Configuration for {text} was added or updated"
        events_vs = get_events(kube_apis.v1, virtual_server_setup.namespace)
        initial_count = assert_event_and_get_count(vs_event_text, events_vs)
        vs_src = f"{TEST_DATA}/virtual-server-canned-responses/virtual-server-updated.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, vs_src, virtual_server_setup.namespace
        )
        wait_and_assert_status_code(501, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        resp = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        resp_content = resp.content.decode("utf-8")
        assert resp.headers["content-type"] == "some/type" and resp_content == "{}"

        wait_and_assert_status_code(201, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)
        resp = requests.get(virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host})
        resp_content = resp.content.decode("utf-8")
        assert (
            resp.headers["content-type"] == "user-type"
            and resp_content == "line1\nline2"
            and resp.headers["coffee-test-header"] == "latte"
        )

        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_event_count_increased(vs_event_text, initial_count, vs_events)

    @pytest.mark.flaky(max_runs=3)
    def test_validation_flow(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        invalid_fields = ["spec.routes[0].action.return.code", "spec.routes[0].action.return.body"]
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"VirtualServer {text} was rejected with error:"
        vs_src = f"{TEST_DATA}/virtual-server-canned-responses/virtual-server-invalid.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, vs_src, virtual_server_setup.namespace
        )
        wait_before_test(1)

        wait_and_assert_status_code(404, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_event_starts_with_text_and_contains_errors(vs_event_text, vs_events, invalid_fields)

    def test_openapi_validation_flow(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config_old = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        vs_src = f"{TEST_DATA}/virtual-server-canned-responses/virtual-server-invalid-openapi.yaml"
        with pytest.raises(ApiException) as exc_info:
            patch_virtual_server_from_yaml(
                kube_apis.custom_objects, virtual_server_setup.vs_name, vs_src, virtual_server_setup.namespace
            )
        assert exc_info.value.status == 422
        assert "action.return.type in body must be of type" in exc_info.value.body
        assert "action.return.body in body must be of type" in exc_info.value.body
        assert "action.return.code in body must be of type" in exc_info.value.body
        assert "action.return.headers in body must be of type" in exc_info.value.body

        wait_before_test(1)
        config_new = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert config_old == config_new, "Expected: config doesn't change"

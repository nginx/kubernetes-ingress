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
@pytest.mark.vs_redirects
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-redirects", "app_type": None},
        )
    ],
    indirect=True,
)
class TestVSRedirects:
    def test_config(self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "error_page 418 =307" in config and "error_page 418 =301" in config

    def test_custom_redirect(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        req_url = f"{virtual_server_setup.backend_1_url}"
        wait_and_assert_status_code(307, req_url, virtual_server_setup.vs_host, allow_redirects=False)
        resp = requests.get(req_url, headers={"host": virtual_server_setup.vs_host}, allow_redirects=False)
        assert resp.headers["location"] == "http://example.com"

    def test_default_redirect(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        wait_and_assert_status_code(
            301, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host, allow_redirects=False
        )
        resp = requests.get(
            virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host}, allow_redirects=False
        )
        assert resp.headers["location"] == f"http://{virtual_server_setup.vs_host}/default-redirect?arg="

    def test_update(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        wait_before_test(1)
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"Configuration for {text} was added or updated"
        events_vs = get_events(kube_apis.v1, virtual_server_setup.namespace)
        initial_count = assert_event_and_get_count(vs_event_text, events_vs)
        vs_src = f"{TEST_DATA}/virtual-server-redirects/virtual-server-updated.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, vs_src, virtual_server_setup.namespace
        )
        wait_and_assert_status_code(
            301, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, allow_redirects=False
        )
        resp = requests.get(
            virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host}, allow_redirects=False
        )
        assert resp.headers["location"] == "http://demo.nginx.com"
        wait_and_assert_status_code(
            302, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host, allow_redirects=False
        )
        resp = requests.get(
            virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host}, allow_redirects=False
        )
        assert resp.headers["location"] == "http://demo.nginx.com"

        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_event_count_increased(vs_event_text, initial_count, vs_events)

    @pytest.mark.flaky(max_runs=3)
    def test_validation_flow(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        event_text = f"VirtualServer {text} was rejected with error:"
        invalid_fields = ["spec.routes[0].action.redirect.code", "spec.routes[1].action.redirect.url"]
        vs_src = f"{TEST_DATA}/virtual-server-redirects/virtual-server-invalid.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, vs_src, virtual_server_setup.namespace
        )
        wait_before_test(2)

        wait_and_assert_status_code(
            404, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, allow_redirects=False
        )
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_event_starts_with_text_and_contains_errors(event_text, vs_events, invalid_fields)

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
        vs_src = f"{TEST_DATA}/virtual-server-redirects/virtual-server-invalid-openapi.yaml"
        with pytest.raises(ApiException) as exc_info:
            patch_virtual_server_from_yaml(
                kube_apis.custom_objects, virtual_server_setup.vs_name, vs_src, virtual_server_setup.namespace
            )
        assert exc_info.value.status == 422
        assert "action.redirect.url in body must be of type" in exc_info.value.body
        assert "action.redirect.code in body must be of type" in exc_info.value.body

        wait_before_test(1)
        config_new = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert config_old == config_new, "Expected: config doesn't change"

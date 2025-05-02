import json

import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    assert_event_starts_with_text_and_contains_errors,
    assert_vs_conf_not_exists,
    wait_and_assert_status_code,
)
from suite.utils.resources_utils import get_events, get_first_pod_name, wait_before_test
from suite.utils.vs_vsr_resources_utils import get_vs_nginx_template_conf, patch_virtual_server_from_yaml


@pytest.mark.vs
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-error-pages", "app_type": None},
        )
    ],
    indirect=True,
)
class TestVSErrorPages:
    def test_redirect_strategy(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        wait_and_assert_status_code(
            307, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, allow_redirects=False
        )
        retry = 0
        while retry < 5:
            wait_before_test()
            try:
                resp = requests.get(
                    virtual_server_setup.backend_1_url,
                    headers={"host": virtual_server_setup.vs_host},
                    allow_redirects=False,
                )
                print(f"redirect to uri: {resp.next.url}")
            except AttributeError as e:
                print(f"Exception occurred: {e}")
                retry = retry + 1
                continue
            break
        assert f"http://{virtual_server_setup.vs_host}/error.html" in resp.next.url

    def test_return_strategy(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        wait_and_assert_status_code(207, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)
        resp = requests.get(virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host})
        resp_content = json.loads(resp.content)
        assert (
            resp_content["status"] == "502"
            and resp_content["message"] == "Forbidden"
            and resp.headers.get("x-debug-original-status") == "502"
        )

    def test_virtual_server_after_update(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-error-pages/virtual-server-updated.yaml",
            virtual_server_setup.namespace,
        )
        wait_and_assert_status_code(
            301, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, allow_redirects=False
        )
        resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "http"},
            allow_redirects=False,
        )
        assert f"http://{virtual_server_setup.vs_host}/error_http.html" in resp.next.url

        wait_and_assert_status_code(502, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)
        resp = requests.get(virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host})
        resp_content = resp.content.decode("utf-8")
        assert resp_content == "Hello World!\n"

    def test_validation_event_flow(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        invalid_fields = [
            "spec.routes[0].errorPages[0].redirect.url: Invalid value",
            "spec.routes[0].errorPages[0].redirect.code: Invalid value: 101",
            'spec.routes[1].errorPages[0].return.body: Invalid value: "status"',
            "spec.routes[1].errorPages[0].return.code: Invalid value: 100",
            'spec.routes[1].errorPages[0].return.headers[0].value: Invalid value: "schema"',
        ]
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"VirtualServer {text} was rejected with error:"
        vs_file = f"{TEST_DATA}/virtual-server-error-pages/virtual-server-invalid.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, vs_file, virtual_server_setup.namespace
        )
        wait_before_test(2)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)

        assert_event_starts_with_text_and_contains_errors(vs_event_text, vs_events, invalid_fields)
        assert_vs_conf_not_exists(
            kube_apis, ic_pod_name, ingress_controller_prerequisites.namespace, virtual_server_setup
        )

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
        vs_file = f"{TEST_DATA}/virtual-server-error-pages/virtual-server-invalid-openapi.yaml"
        try:
            patch_virtual_server_from_yaml(
                kube_apis.custom_objects, virtual_server_setup.vs_name, vs_file, virtual_server_setup.namespace
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
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert config_old == config_new, "Expected: config doesn't change"

    @pytest.mark.parametrize(
        "v_s_data",
        [
            {"src": "virtual-server-splits.yaml", "expected_code": 308},
            {"src": "virtual-server-matches.yaml", "expected_code": 307},
        ],
    )
    def test_splits_and_matches(self, kube_apis, crd_ingress_controller, virtual_server_setup, v_s_data):
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-error-pages/{v_s_data['src']}",
            virtual_server_setup.namespace,
        )
        wait_and_assert_status_code(
            v_s_data["expected_code"],
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            allow_redirects=False,
        )
        resp = requests.get(
            virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host}, allow_redirects=False
        )
        assert f"http://{virtual_server_setup.vs_host}/error.html" in resp.next.url

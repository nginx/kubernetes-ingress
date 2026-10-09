from unittest import mock

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import generate_item_with_upstream_options
from suite.utils.resources_utils import ensure_response_from_backend, replace_configmap, wait_before_test
from suite.utils.vs_vsr_resources_utils import patch_virtual_server, patch_virtual_server_from_yaml

resp_1 = mock.Mock()
resp_2 = mock.Mock()
resp_3 = mock.Mock()


def execute_assertions(resp_1, resp_2, resp_3):
    assert resp_1.status_code == 200
    assert "Server name: backend1-" in resp_1.text
    assert resp_2.status_code == 200
    assert "Server name: backend3-" in resp_2.text
    assert resp_3.status_code == 200
    assert "Server name: backend4-" in resp_3.text


def ensure_responses_from_backends(req_url, host) -> None:
    ensure_response_from_backend(req_url, host, {"x-version": "future"})
    ensure_response_from_backend(req_url, host, {"x-version": "deprecated"})
    ensure_response_from_backend(req_url, host, {"x-version-invalid": "deprecated"})


@pytest.mark.vs
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-advanced-routing", "app_type": "advanced-routing"},
        )
    ],
    indirect=True,
)
class TestAdvancedRouting:
    def test_flow_with_header(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        ensure_responses_from_backends(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_before_test()
        global resp_1, resp_2, resp_3
        resp_1.status_code = resp_2.status_code = resp_3.status_code = 502
        while resp_1.status_code == 502 and resp_2.status_code == 502 and resp_3.status_code == 502:
            resp_1 = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host, "x-version": "future"},
            )
            resp_2 = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host, "x-version": "deprecated"},
            )
            resp_3 = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host, "x-version-invalid": "deprecated"},
            )
        execute_assertions(resp_1, resp_2, resp_3)

    def test_flow_with_argument(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-advanced-routing/virtual-server-argument.yaml",
            virtual_server_setup.namespace,
        )
        ensure_response_from_backend(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_before_test()
        global resp_1, resp_2, resp_3
        resp_1.status_code = resp_2.status_code = resp_3.status_code = 502
        while resp_1.status_code == 502 and resp_2.status_code == 502 and resp_3.status_code == 502:
            resp_1 = requests.get(
                virtual_server_setup.backend_1_url + "?arg1=v1", headers={"host": virtual_server_setup.vs_host}
            )
            resp_2 = requests.get(
                virtual_server_setup.backend_1_url + "?arg1=v2", headers={"host": virtual_server_setup.vs_host}
            )
            resp_3 = requests.get(
                virtual_server_setup.backend_1_url + "?argument1=v1", headers={"host": virtual_server_setup.vs_host}
            )
        execute_assertions(resp_1, resp_2, resp_3)

    def test_flow_with_cookie(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-advanced-routing/virtual-server-cookie.yaml",
            virtual_server_setup.namespace,
        )
        ensure_response_from_backend(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_before_test()
        global resp_1, resp_2, resp_3
        resp_1.status_code = resp_2.status_code = resp_3.status_code = 502
        while resp_1.status_code == 502 and resp_2.status_code == 502 and resp_3.status_code == 502:
            resp_1 = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host},
                cookies={"user": "some"},
            )
            resp_2 = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host},
                cookies={"user": "bad"},
            )
            resp_3 = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host},
                cookies={"user": "anonymous"},
            )
        execute_assertions(resp_1, resp_2, resp_3)

    def test_flow_with_variable(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-advanced-routing/virtual-server-variable.yaml",
            virtual_server_setup.namespace,
        )
        ensure_response_from_backend(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_before_test()
        global resp_1, resp_2, resp_3
        resp_1.status_code = resp_2.status_code = resp_3.status_code = 502
        while resp_1.status_code == 502 and resp_2.status_code == 502 and resp_3.status_code == 502:
            resp_1 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
            resp_2 = requests.post(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
            resp_3 = requests.put(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        execute_assertions(resp_1, resp_2, resp_3)

    def test_flow_with_complex_conditions(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-advanced-routing/virtual-server-complex.yaml",
            virtual_server_setup.namespace,
        )
        ensure_response_from_backend(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_before_test()
        global resp_1, resp_2, resp_3
        resp_1.status_code = resp_2.status_code = resp_3.status_code = 502
        while resp_1.status_code == 502 and resp_2.status_code == 502 and resp_3.status_code == 502:
            resp_1 = requests.get(
                virtual_server_setup.backend_1_url + "?arg1=v1",
                headers={"host": virtual_server_setup.vs_host, "x-version": "future"},
                cookies={"user": "some"},
            )
            resp_2 = requests.post(
                virtual_server_setup.backend_1_url + "?arg1=v2",
                headers={"host": virtual_server_setup.vs_host, "x-version": "deprecated"},
                cookies={"user": "bad"},
            )
            resp_3 = requests.get(
                virtual_server_setup.backend_1_url + "?arg1=v2",
                headers={"host": virtual_server_setup.vs_host, "x-version": "deprecated"},
                cookies={"user": "bad"},
            )
        execute_assertions(resp_1, resp_2, resp_3)

    @pytest.mark.parametrize(
        "limit_source, small_body, large_body",
        [
            pytest.param("unset", 500 * 1024, 2 * 1024 * 1024, id="unset-1m-default"),
            pytest.param("vs-spec", 2 * 1024 * 1024, 4 * 1024 * 1024, id="vs-spec-3m"),
            pytest.param("nic-configmap", 2 * 1024 * 1024, 4 * 1024 * 1024, id="nic-configmap-3m"),
        ],
    )
    def test_large_body(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        restore_configmap,
        limit_source,
        small_body,
        large_body,
    ):
        """
        The body limit of the route must apply to the matches' children, whatever the size of the body.

        The default 1m must not be applied before the request reaches them, so a body larger than
        1m but smaller than the configured limit is accepted, and a body larger than the limit is not.
        The backend accepts any body, so a 413 can only come from NGINX Ingress Controller.
        """
        if limit_source == "vs-spec":
            body = generate_item_with_upstream_options(
                f"{TEST_DATA}/virtual-server-advanced-routing/standard/virtual-server.yaml",
                {"client-max-body-size": "3m"},
            )
            patch_virtual_server(
                kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace, body
            )
        else:
            # the standard VS, so that options set by the previous tests are gone
            patch_virtual_server_from_yaml(
                kube_apis.custom_objects,
                virtual_server_setup.vs_name,
                f"{TEST_DATA}/virtual-server-advanced-routing/standard/virtual-server.yaml",
                virtual_server_setup.namespace,
            )
        if limit_source == "nic-configmap":
            config_map = ingress_controller_prerequisites.config_map.copy()
            config_map["data"] = {"client-max-body-size": "3m"}
            replace_configmap(
                kube_apis.v1,
                config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                config_map,
            )
        wait_before_test()
        ensure_response_from_backend(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"x-version": "future"}
        )

        # (headers, backend expected in the response): a match and the default action
        requests_to_check = [
            ({"x-version": "future"}, "Server name: backend1-"),
            ({}, "Server name: backend4-"),
        ]
        for extra_headers, expected_backend in requests_to_check:
            headers = {"host": virtual_server_setup.vs_host, **extra_headers}

            resp = requests.post(virtual_server_setup.backend_1_url, headers=headers, data=b"x" * small_body)
            assert resp.status_code == 200, f"{small_body} bytes, headers {extra_headers}"
            assert expected_backend in resp.text

            resp = requests.post(virtual_server_setup.backend_1_url, headers=headers, data=b"x" * large_body)
            assert resp.status_code == 413, f"{large_body} bytes, headers {extra_headers}"

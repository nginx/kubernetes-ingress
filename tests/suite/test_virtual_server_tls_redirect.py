import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.resources_utils import get_first_pod_name, get_vs_nginx_template_conf, wait_before_test
from suite.utils.vs_vsr_resources_utils import patch_virtual_server_from_yaml


@pytest.mark.vs
@pytest.mark.vs_redirects
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-tls-redirect", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVirtualServerTLSRedirect:
    def test_tls_redirect_defaults(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-tls-redirect/virtual-server-default-redirect.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)

        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "proxy_set_header X-Forwarded-Proto $scheme;" in config
        resp_1 = requests.get(
            virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host}, allow_redirects=False
        )
        resp_2 = requests.get(
            virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host}, allow_redirects=False
        )
        assert resp_1.status_code == 301, "Expected: a redirect for scheme=http"
        assert resp_2.status_code == 301, "Expected: a redirect for scheme=http"

        resp_3 = requests.get(
            virtual_server_setup.backend_1_url_ssl,
            headers={"host": virtual_server_setup.vs_host},
            allow_redirects=False,
            verify=False,
        )
        resp_4 = requests.get(
            virtual_server_setup.backend_2_url_ssl,
            headers={"host": virtual_server_setup.vs_host},
            allow_redirects=False,
            verify=False,
        )
        assert resp_3.status_code == 200, "Expected: no redirect for scheme=https"
        assert resp_4.status_code == 200, "Expected: no redirect for scheme=https"

    def test_tls_redirect_based_on_header(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-tls-redirect/virtual-server-header-redirect.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)

        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;" in config
        resp_1 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "http"},
            allow_redirects=False,
        )
        resp_2 = requests.get(
            virtual_server_setup.backend_2_url,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "http"},
            allow_redirects=False,
        )
        assert resp_1.status_code == 308, "Expected: a redirect for x-forwarded-proto=http"
        assert resp_2.status_code == 308, "Expected: a redirect for x-forwarded-proto=http"

        resp_3 = requests.get(
            virtual_server_setup.backend_1_url_ssl,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "http"},
            allow_redirects=False,
            verify=False,
        )
        resp_4 = requests.get(
            virtual_server_setup.backend_2_url_ssl,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "http"},
            allow_redirects=False,
            verify=False,
        )
        assert resp_3.status_code == 308, "Expected: a redirect for x-forwarded-proto=http"
        assert resp_4.status_code == 308, "Expected: a redirect for x-forwarded-proto=http"

        resp_5 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "https"},
            allow_redirects=False,
        )
        resp_6 = requests.get(
            virtual_server_setup.backend_2_url,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "https"},
            allow_redirects=False,
        )
        assert resp_5.status_code == 200, "Expected: no redirect for x-forwarded-proto=https"
        assert resp_6.status_code == 200, "Expected: no redirect for x-forwarded-proto=https"

        resp_7 = requests.get(
            virtual_server_setup.backend_1_url_ssl,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "https"},
            allow_redirects=False,
            verify=False,
        )
        resp_8 = requests.get(
            virtual_server_setup.backend_2_url_ssl,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "https"},
            allow_redirects=False,
            verify=False,
        )
        assert resp_7.status_code == 200, "Expected: no redirect for x-forwarded-proto=https"
        assert resp_8.status_code == 200, "Expected: no redirect for x-forwarded-proto=https"

    def test_tls_redirect_based_on_scheme(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-tls-redirect/virtual-server-scheme-redirect.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)

        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "proxy_set_header X-Forwarded-Proto $scheme;" in config
        resp_1 = requests.get(
            virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host}, allow_redirects=False
        )
        resp_2 = requests.get(
            virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host}, allow_redirects=False
        )
        assert resp_1.status_code == 302, "Expected: a redirect for scheme=http"
        assert resp_2.status_code == 302, "Expected: a redirect for scheme=http"

        resp_3 = requests.get(
            virtual_server_setup.backend_1_url_ssl,
            headers={"host": virtual_server_setup.vs_host},
            allow_redirects=False,
            verify=False,
        )
        resp_4 = requests.get(
            virtual_server_setup.backend_2_url_ssl,
            headers={"host": virtual_server_setup.vs_host},
            allow_redirects=False,
            verify=False,
        )
        assert resp_3.status_code == 200, "Expected: no redirect for scheme=https"
        assert resp_4.status_code == 200, "Expected: no redirect for scheme=https"

    def test_tls_redirect_without_tls_termination(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        source_yaml = f"{TEST_DATA}/virtual-server-tls-redirect/virtual-server-no-tls-termination-redirect.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, source_yaml, virtual_server_setup.namespace
        )
        wait_before_test(1)

        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;" in config

        resp_1 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "http"},
            allow_redirects=False,
        )
        resp_2 = requests.get(
            virtual_server_setup.backend_2_url,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "http"},
            allow_redirects=False,
        )
        assert resp_1.status_code == 308, "Expected: a redirect for x-forwarded-proto=http"
        assert resp_2.status_code == 308, "Expected: a redirect for x-forwarded-proto=http"

        resp_3 = requests.get(
            virtual_server_setup.backend_1_url_ssl,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "http"},
            allow_redirects=False,
            verify=False,
        )
        resp_4 = requests.get(
            virtual_server_setup.backend_2_url_ssl,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "http"},
            allow_redirects=False,
            verify=False,
        )
        assert resp_3.status_code == 404, "Expected: 404 for x-forwarded-proto=http and scheme=https"
        assert resp_4.status_code == 404, "Expected: 404 for x-forwarded-proto=http and scheme=https"

        resp_5 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "https"},
            allow_redirects=False,
        )
        resp_6 = requests.get(
            virtual_server_setup.backend_2_url,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "https"},
            allow_redirects=False,
        )
        assert resp_5.status_code == 200, "Expected: no redirect for x-forwarded-proto=https"
        assert resp_6.status_code == 200, "Expected: no redirect for x-forwarded-proto=https"

        resp_7 = requests.get(
            virtual_server_setup.backend_1_url_ssl,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "https"},
            allow_redirects=False,
            verify=False,
        )
        resp_8 = requests.get(
            virtual_server_setup.backend_2_url_ssl,
            headers={"host": virtual_server_setup.vs_host, "x-forwarded-proto": "https"},
            allow_redirects=False,
            verify=False,
        )
        assert resp_7.status_code == 404, "Expected: no redirect for x-forwarded-proto=https and scheme=https"
        assert resp_8.status_code == 404, "Expected: no redirect for x-forwarded-proto=https and scheme=https"

    def test_tls_redirect_openapi_validation_flow(
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
        source_yaml = f"{TEST_DATA}/virtual-server-tls-redirect/virtual-server-invalid.yaml"
        with pytest.raises(ApiException) as exc_info:
            patch_virtual_server_from_yaml(
                kube_apis.custom_objects, virtual_server_setup.vs_name, source_yaml, virtual_server_setup.namespace
            )
        assert exc_info.value.status == 422
        assert "spec.tls.redirect.enable" in exc_info.value.body
        assert "spec.tls.redirect.code" in exc_info.value.body
        assert "spec.tls.redirect.basedOn" in exc_info.value.body
        assert "spec.tls.secret" in exc_info.value.body

        wait_before_test(1)
        config_new = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert config_old == config_new, "Expected: config doesn't change"

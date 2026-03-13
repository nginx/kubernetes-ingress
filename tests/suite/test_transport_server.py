import pytest
from settings import TEST_DATA
from suite.utils.custom_resources_utils import patch_ts_from_yaml
from suite.utils.resources_utils import get_ts_nginx_template_conf, wait_before_test


@pytest.mark.ts
@pytest.mark.parametrize(
    "crd_ingress_controller, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-global-configuration=nginx-ingress/nginx-configuration",
                    "-enable-leader-election=false",
                    "-enable-snippets",
                ],
            },
            {"example": "transport-server-status"},
        )
    ],
    indirect=True,
)
class TestTransportServer:
    def test_snippets(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Test snippets are present in conf when enabled
        """
        patch_src = f"{TEST_DATA}/transport-server/transport-server-snippets.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        wait_before_test()

        conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            transport_server_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        print(conf)

        std_src = f"{TEST_DATA}/transport-server-status/standard/transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            std_src,
            transport_server_setup.namespace,
        )

        conf_lines = [line.strip() for line in conf.split("\n")]
        assert "limit_conn_zone $binary_remote_addr zone=addr:10m;" in conf_lines  # stream-snippets on separate line
        assert "limit_conn addr 1;" in conf_lines  # server-snippets on separate line
        assert "# a comment is allowed in snippets" in conf_lines  # comments are allowed in server snippets
        assert 'add_header X-test-header "test-value";' in conf_lines  # new line in server-snippets on separate line

    def test_configurable_timeout_directives(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Test session and upstream configurable timeouts are present in conf
        """
        patch_src = f"{TEST_DATA}/transport-server/transport-server-configurable-timeouts.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        wait_before_test()

        conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            transport_server_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        print(conf)

        std_src = f"{TEST_DATA}/transport-server-status/standard/transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            std_src,
            transport_server_setup.namespace,
        )

        assert "proxy_timeout 2s;" in conf  # sessionParameters
        assert (
            "proxy_connect_timeout 5s;" in conf  # upstreamParameters
            and "proxy_next_upstream on;" in conf
            and "proxy_next_upstream_timeout 4s;" in conf
            and "proxy_next_upstream_tries 3;" in conf
        )

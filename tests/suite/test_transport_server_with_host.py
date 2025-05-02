import pytest
from settings import TEST_DATA
from suite.utils.custom_resources_utils import patch_ts_from_yaml, read_custom_resource
from suite.utils.resources_utils import (
    create_secret_from_yaml,
    get_events_for_object,
    get_ts_nginx_template_conf,
    wait_before_test,
)


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
class TestTransportServerWithHost:
    def test_ts_with_host(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Test TransportServer with Host field without TLS Passthrough
        """

        # TS with Host needs a secret
        secret_src = f"{TEST_DATA}/transport-server-with-host/cafe-secret.yaml"
        create_secret_from_yaml(kube_apis.v1, transport_server_setup.namespace, secret_src)

        # Update the status TS from the example with one which uses a Host
        patch_src = f"{TEST_DATA}/transport-server-with-host/transport-server-with-host.yaml"
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
        assert 'server_name "cafe.example.com";' in conf_lines

        ts_events = get_events_for_object(kube_apis.v1, transport_server_setup.namespace, transport_server_setup.name)
        ts_latest_event = ts_events[-1]
        print(ts_latest_event)
        assert ts_latest_event.reason == "AddedOrUpdated" and ts_latest_event.type == "Normal"

        ts_info = read_custom_resource(
            kube_apis.custom_objects, transport_server_setup.namespace, "transportservers", transport_server_setup.name
        )
        assert ts_info["status"] and ts_info["status"]["state"] == "Valid"

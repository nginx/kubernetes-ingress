import pytest
from settings import TEST_DATA
from suite.utils.custom_resources_utils import patch_gc_from_yaml, patch_ts_from_yaml
from suite.utils.resources_utils import get_events_for_object, get_ts_nginx_template_conf, wait_before_test


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
                ],
            },
            {"example": "transport-server-status"},
        )
    ],
    indirect=True,
)
class TestTransportServerCustomIPListener:
    def test_ts_custom_ip_listener(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Test transport server with custom IP listener
        """

        global_config_file = f"{TEST_DATA}/transport-server-custom-ip-listener/global-configuration.yaml"
        patch_gc_from_yaml(kube_apis.custom_objects, "nginx-configuration", global_config_file, "nginx-ingress")

        patch_src = f"{TEST_DATA}/transport-server-custom-ip-listener/transport-server.yaml"
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

        conf_lines = [line.strip() for line in conf.split("\n")]
        assert "listen 127.0.0.1:5353;" in conf_lines
        assert "listen [::1]:5353;" in conf_lines

        gc_events = get_events_for_object(kube_apis.v1, "nginx-ingress", "nginx-configuration")
        gc_event_latest = gc_events[-1]
        print(gc_event_latest)

        assert (
            gc_event_latest.reason == "Updated"
            and gc_event_latest.type == "Normal"
            and "GlobalConfiguration nginx-ingress/nginx-configuration was added or updated" in gc_event_latest.message
        )

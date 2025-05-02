import time

import pytest
from settings import TEST_DATA
from suite.utils.custom_resources_utils import (
    create_ts_from_yaml,
    delete_ts,
    patch_gc_from_yaml,
    read_custom_resource,
    read_ts,
)
from suite.utils.resources_utils import get_first_pod_name, get_ts_nginx_template_conf, wait_before_test
from suite.utils.vs_vsr_resources_utils import get_vs_nginx_template_conf, patch_virtual_server_from_yaml


@pytest.mark.vs
@pytest.mark.ts
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-global-configuration=nginx-ingress/nginx-configuration",
                ],
            },
            {"example": "virtual-server-status", "app_type": "simple"},
            {"example": "transport-server-status", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestUDPandHTTPListenersTogether:
    def test_udp_and_http_listeners_together(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        transport_server_setup,
    ):

        wait_before_test()
        existing_ts = read_ts(kube_apis.custom_objects, transport_server_setup.namespace, transport_server_setup.name)
        delete_ts(kube_apis.custom_objects, existing_ts, transport_server_setup.namespace)

        global_config_file = f"{TEST_DATA}/udp-http-listeners-together/global-configuration.yaml"
        transport_server_file = f"{TEST_DATA}/udp-http-listeners-together/transport-server.yaml"
        virtual_server_file = f"{TEST_DATA}/udp-http-listeners-together/virtual-server.yaml"
        gc_resource_name = "nginx-configuration"
        gc_namespace = "nginx-ingress"

        patch_gc_from_yaml(kube_apis.custom_objects, gc_resource_name, global_config_file, gc_namespace)
        create_ts_from_yaml(kube_apis.custom_objects, transport_server_file, transport_server_setup.namespace)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, "virtual-server-status", virtual_server_file, virtual_server_setup.namespace
        )
        wait_before_test()

        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        ts_config = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        vs_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "listen 5454;" in vs_config
        assert "listen 5454 udp;" in ts_config

        for _ in range(30):
            transport_server_response = read_custom_resource(
                kube_apis.custom_objects,
                transport_server_setup.namespace,
                "transportservers",
                "transport-server",
            )
            if "status" in transport_server_response and transport_server_response["status"]["state"] == "Valid":
                break
            time.sleep(1)
        else:
            pytest.fail("TransportServer status did not become 'Valid' within the timeout period")

        for _ in range(30):
            virtual_server_response = read_custom_resource(
                kube_apis.custom_objects,
                virtual_server_setup.namespace,
                "virtualservers",
                "virtual-server-status",
            )
            if "status" in virtual_server_response and virtual_server_response["status"]["state"] == "Valid":
                break
            time.sleep(1)
        else:
            pytest.fail("VirtualServer status did not become 'Valid' within the timeout period")

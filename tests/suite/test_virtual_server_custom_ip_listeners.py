from typing import List, TypedDict

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import create_gc_from_yaml, delete_gc
from suite.utils.resources_utils import (
    create_secret_from_yaml,
    delete_secret,
    get_events_for_object,
    get_first_pod_name,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import get_vs_nginx_template_conf, patch_virtual_server_from_yaml, read_vs


def make_request(url, host):
    return requests.get(
        url,
        headers={"host": host},
        allow_redirects=False,
        verify=False,
    )


def restore_default_vs(kube_apis, virtual_server_setup) -> None:
    """
    Function to revert VS deployment to valid state.
    """
    patch_src = f"{TEST_DATA}/virtual-server-status/standard/virtual-server.yaml"
    patch_virtual_server_from_yaml(
        kube_apis.custom_objects,
        virtual_server_setup.vs_name,
        patch_src,
        virtual_server_setup.namespace,
    )
    wait_before_test()


@pytest.mark.vs
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-global-configuration=nginx-ingress/nginx-configuration",
                    f"-enable-leader-election=false",
                    f"-enable-prometheus-metrics=true",
                ],
            },
            {
                "example": "virtual-server-custom-listeners",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestVirtualServerCustomListeners:
    TestSetup = TypedDict(
        "TestSetup",
        {
            "gc_yaml": str,
            "vs_yaml": str,
            "http_listener_in_config": bool,
            "https_listener_in_config": bool,
            "expected_response_codes": List[int],  # responses from requests to port 80, 443, 8085, 8445
            "expected_http_listener_ipv4ip": str,
            "expected_https_listener_ipv4ip": str,
            "expected_http_listener_ipv6ip": str,
            "expected_https_listener_ipv6ip": str,
            "expected_vs_error_msg": str,
            "expected_gc_error_msg": str,
        },
    )

    @pytest.mark.parametrize(
        "test_setup",
        [
            {
                "gc_yaml": "global-configuration-http-https-ipv4ip-http-https-ipv6ip",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": True,
                "https_listener_in_config": True,
                "expected_response_codes": [200, 200],
                "expected_http_listener_ipv4ip": "127.0.0.1",
                "expected_https_listener_ipv4ip": "127.0.0.2",
                "expected_http_listener_ipv6ip": "::1",
                "expected_https_listener_ipv6ip": "::1",
                "expected_vs_error_msg": "",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration-http-ipv4ip-https-ipv6ip",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": True,
                "https_listener_in_config": True,
                "expected_response_codes": [200, 200],
                "expected_http_listener_ipv4ip": "127.0.0.1",
                "expected_https_listener_ipv4ip": "",
                "expected_http_listener_ipv6ip": "",
                "expected_https_listener_ipv6ip": "::1",
                "expected_vs_error_msg": "",
                "expected_gc_error_msg": "",
            },
        ],
        ids=[
            "http-https-ipv4ip-http-https-ipv6ip",
            "http-ipv4ip-https-ipv6ip",
        ],
    )
    def test_custom_listeners_update(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_setup: TestSetup,
    ) -> None:
        print("\nStep 1: Create GC resource")
        secret_name = create_secret_from_yaml(
            kube_apis.v1, virtual_server_setup.namespace, f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
        )
        if test_setup["gc_yaml"]:
            global_config_file = f"{TEST_DATA}/virtual-server-custom-listeners/{test_setup['gc_yaml']}.yaml"
            gc_resource = create_gc_from_yaml(kube_apis.custom_objects, global_config_file, "nginx-ingress")

        print("\nStep 2: Create VS with custom listeners")
        vs_custom_listeners = f"{TEST_DATA}/virtual-server-custom-listeners/{test_setup['vs_yaml']}.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_custom_listeners,
            virtual_server_setup.namespace,
        )
        print("IP Listeners Detected - Waiting 30 Extra Seconds Required")
        wait_before_test(30)

        print("\nStep 3: Test generated VS configs")
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        vs_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        print(vs_config)

        if "http_listener_in_config" in test_setup and test_setup["http_listener_in_config"]:
            if "expected_http_listener_ipv4ip" in test_setup and test_setup["expected_http_listener_ipv4ip"]:
                assert f"listen {test_setup['expected_http_listener_ipv4ip']}:8085;" in vs_config
            else:
                assert "listen 8085;" in vs_config

            if "expected_http_listener_ipv6ip" in test_setup and test_setup["expected_http_listener_ipv6ip"]:
                assert f"listen [{test_setup['expected_http_listener_ipv6ip']}]:8085;" in vs_config
            else:
                assert "listen [::]:8085;" in vs_config
        else:
            assert "listen 8085;" not in vs_config
            assert "listen [::]:8085;" not in vs_config

        if "https_listener_in_config" in test_setup and test_setup["https_listener_in_config"]:
            if "expected_https_listener_ipv4ip" in test_setup and test_setup["expected_https_listener_ipv4ip"]:
                assert f"listen {test_setup['expected_https_listener_ipv4ip']}:8445 ssl;" in vs_config
            else:
                assert "listen 8445 ssl;" in vs_config

            if "expected_https_listener_ipv6ip" in test_setup and test_setup["expected_https_listener_ipv6ip"]:
                assert f"listen [{test_setup['expected_https_listener_ipv6ip']}]:8445 ssl;" in vs_config
            else:
                assert "listen [::]:8445 ssl;" in vs_config
        else:
            assert "listen 8445 ssl;" not in vs_config
            assert "listen [::]:8445 ssl;" not in vs_config

        assert "listen 80;" not in vs_config
        assert "listen [::]:80;" not in vs_config
        assert "listen 443 ssl;" not in vs_config
        assert "listen [::]:443 ssl;" not in vs_config

        print("\nStep 4: Test Kubernetes VirtualServer warning events")
        if test_setup["expected_vs_error_msg"]:
            response = read_vs(kube_apis.custom_objects, virtual_server_setup.namespace, virtual_server_setup.vs_name)
            print(response)
            assert (
                response["status"]["reason"] == "AddedOrUpdatedWithWarning"
                and response["status"]["state"] == "Warning"
                and test_setup["expected_vs_error_msg"] in response["status"]["message"]
            )

        print("\nStep 5: Test Kubernetes GlobalConfiguration warning events")
        if test_setup["gc_yaml"]:
            gc_events = get_events_for_object(kube_apis.v1, "nginx-ingress", "nginx-configuration")
            gc_event_latest = gc_events[-1]
            print(gc_event_latest)
            if test_setup["expected_gc_error_msg"]:
                assert (
                    gc_event_latest.reason == "AddedOrUpdatedWithError"
                    and gc_event_latest.type == "Warning"
                    and test_setup["expected_gc_error_msg"] in gc_event_latest.message
                )
            else:
                assert (
                    gc_event_latest.reason == "Updated"
                    and gc_event_latest.type == "Normal"
                    and "GlobalConfiguration nginx-ingress/nginx-configuration was added or updated"
                    in gc_event_latest.message
                )

        print("\nStep 6: Restore test environments")
        delete_secret(kube_apis.v1, secret_name, virtual_server_setup.namespace)
        restore_default_vs(kube_apis, virtual_server_setup)
        if test_setup["gc_yaml"]:
            delete_gc(kube_apis.custom_objects, gc_resource, "nginx-ingress")
            print(f"deleted GC : {gc_resource}")
            wait_before_test(10)

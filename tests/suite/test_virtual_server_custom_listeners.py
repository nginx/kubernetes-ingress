from typing import List, TypedDict

import pytest
import requests
from requests.exceptions import ConnectionError
from settings import TEST_DATA
from suite.utils.custom_resources_utils import create_gc_from_yaml, delete_gc, patch_gc_from_yaml
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
    Function to revert vs deployment to valid state
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
            "expected_response_codes": List[int],  # responses from requests to port 80, 433, 8085, 8445
            "expected_vs_error_msg": str,
            "expected_gc_error_msg": str,
        },
    )

    @pytest.mark.parametrize(
        "test_setup",
        [
            {
                "gc_yaml": "global-configuration",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": True,
                "https_listener_in_config": True,
                "expected_response_codes": [404, 404, 200, 200],
                "expected_vs_error_msg": "",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration-missing-http",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": False,
                "https_listener_in_config": True,
                "expected_response_codes": [404, 404, 0, 200],
                "expected_vs_error_msg": "Listener http-8085 is not defined in GlobalConfiguration",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration-missing-https",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": True,
                "https_listener_in_config": False,
                "expected_response_codes": [404, 404, 200, 0],
                "expected_vs_error_msg": "Listener https-8445 is not defined in GlobalConfiguration",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration-missing-http-https",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": False,
                "https_listener_in_config": False,
                "expected_response_codes": [404, 404, 0, 0],
                "expected_vs_error_msg": "Listeners defined, but no GlobalConfiguration is deployed",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration",
                "vs_yaml": "virtual-server-http-listener-in-https-block",
                "http_listener_in_config": False,
                "https_listener_in_config": False,
                "expected_response_codes": [404, 404, 0, 0],
                "expected_vs_error_msg": "Listener http-8085 can't be use in `listener.https` context as SSL is not "
                "enabled for that listener",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration",
                "vs_yaml": "virtual-server-https-listener-in-http-block",
                "http_listener_in_config": False,
                "https_listener_in_config": False,
                "expected_response_codes": [404, 404, 0, 0],
                "expected_vs_error_msg": "Listener https-8445 can't be use in `listener.http` context as SSL is enabled "
                "for that listener.",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration",
                "vs_yaml": "virtual-server-http-https-listeners-switched",
                "http_listener_in_config": False,
                "https_listener_in_config": False,
                "expected_response_codes": [404, 404, 0, 0],
                "expected_vs_error_msg": "Listener https-8445 can't be use in `listener.http` context as SSL is enabled "
                "for that listener.",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": False,
                "https_listener_in_config": False,
                "expected_response_codes": [404, 404, 0, 0],
                "expected_vs_error_msg": "Listeners defined, but no GlobalConfiguration is deployed",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration-repeated-http-port",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": False,
                "https_listener_in_config": True,
                "expected_response_codes": [404, 404, 0, 200],
                "expected_vs_error_msg": "Listener http-8085 is not defined in GlobalConfiguration",
                "expected_gc_error_msg": "Listener http-8085: Duplicated ip:port protocol combination 0.0.0.0:8085 HTTP",
            },
            {
                "gc_yaml": "global-configuration-forbidden-port-http",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": False,
                "https_listener_in_config": True,
                "expected_response_codes": [404, 404, 0, 200],
                "expected_vs_error_msg": "Listener http-8085 is not defined in GlobalConfiguration",
                "expected_gc_error_msg": "Listener http-8085: port 9113 is forbidden",
            },
            {
                "gc_yaml": "global-configuration-forbidden-port-preceding-udp",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": True,
                "https_listener_in_config": True,
                "expected_response_codes": [404, 404, 200, 200],
                "expected_vs_error_msg": "",
                "expected_gc_error_msg": "Listener dns-udp: port 9113 is forbidden",
            },
        ],
        ids=[
            "valid_config",
            "global_configuration_missing_http_listener",
            "global_configuration_missing_https_listener",
            "global_configuration_missing_both_http_and_https_listeners",
            "http_listener_in_https_block",
            "https_listener_in_http_block",
            "http_https_listeners_switched",
            "no_global_configuration",
            "update_gc_http_listener_repeated_port",
            "update_gc_http_listener_forbidden_port",
            "update_gc_ts_listener_forbidden_port",
        ],
    )
    def test_custom_listeners(
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
        wait_before_test()

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

        if test_setup["http_listener_in_config"]:
            assert "listen 8085;" in vs_config
            assert "listen [::]:8085;" in vs_config

        else:
            assert "listen 8085;" not in vs_config
            assert "listen [::]:8085;" not in vs_config

        if test_setup["https_listener_in_config"]:
            assert "listen 8445 ssl;" in vs_config
            assert "listen [::]:8445 ssl;" in vs_config
        else:
            assert "listen 8445 ssl;" not in vs_config
            assert "listen [::]:8445 ssl;" not in vs_config

        assert "listen 80;" not in vs_config
        assert "listen [::]:80;" not in vs_config
        assert "listen 443 ssl;" not in vs_config
        assert "listen [::]:443 ssl;" not in vs_config

        print("\nStep 4: Test HTTP responses")
        urls = [
            virtual_server_setup.backend_1_url,
            virtual_server_setup.backend_1_url_ssl,
            virtual_server_setup.backend_1_url_custom,
            virtual_server_setup.backend_1_url_custom_ssl,
        ]
        for url, expected_response in zip(urls, test_setup["expected_response_codes"]):
            if expected_response > 0:
                res = make_request(url, virtual_server_setup.vs_host)
                assert res.status_code == expected_response
            else:
                with pytest.raises(ConnectionError, match="Connection refused") as e:
                    make_request(url, virtual_server_setup.vs_host)

        print("\nStep 5: Test Kubernetes VirtualServer warning events")
        if test_setup["expected_vs_error_msg"]:
            response = read_vs(kube_apis.custom_objects, virtual_server_setup.namespace, virtual_server_setup.vs_name)
            print(response)
            assert (
                response["status"]["reason"] == "AddedOrUpdatedWithWarning"
                and response["status"]["state"] == "Warning"
                and test_setup["expected_vs_error_msg"] in response["status"]["message"]
            )

        print("\nStep 6: Test Kubernetes GlobalConfiguration warning events")
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
                    and "GlobalConfiguration nginx-ingress/nginx-configuration was added "
                    "or updated" in gc_event_latest.message
                )

        print("\nStep 7: Restore test environments")
        delete_secret(kube_apis.v1, secret_name, virtual_server_setup.namespace)
        restore_default_vs(kube_apis, virtual_server_setup)
        if test_setup["gc_yaml"]:
            delete_gc(kube_apis.custom_objects, gc_resource, "nginx-ingress")

    @pytest.mark.parametrize(
        "test_setup",
        [
            {
                "gc_yaml": "",  # delete gc if empty
                "vs_yaml": "virtual-server",
                "http_listener_in_config": False,
                "https_listener_in_config": False,
                "expected_response_codes": [404, 404, 0, 0],
                "expected_vs_error_msg": "Listeners defined, but no GlobalConfiguration is deployed",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration-https-listener-without-ssl",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": True,
                "https_listener_in_config": False,
                "expected_response_codes": [404, 404, 200, 0],
                "expected_vs_error_msg": "Listener https-8445 can't be use in `listener.https` context as SSL is not "
                "enabled for that listener.",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration-http-listener-with-ssl",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": False,
                "https_listener_in_config": True,
                "expected_response_codes": [404, 404, 0, 200],
                "expected_vs_error_msg": "Listener http-8085 can't be use in `listener.http` context as SSL is enabled",
                "expected_gc_error_msg": "",
            },
            {
                "gc_yaml": "global-configuration-repeated-http-port",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": False,
                "https_listener_in_config": True,
                "expected_response_codes": [404, 404, 0, 200],
                "expected_vs_error_msg": "Listener http-8085 is not defined in GlobalConfiguration",
                "expected_gc_error_msg": "Listener http-8085: Duplicated ip:port protocol combination 0.0.0.0:8085 HTTP",
            },
            {
                "gc_yaml": "global-configuration-forbidden-port-http",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": False,
                "https_listener_in_config": True,
                "expected_response_codes": [404, 404, 0, 200],
                "expected_vs_error_msg": "Listener http-8085 is not defined in GlobalConfiguration",
                "expected_gc_error_msg": "Listener http-8085: port 9113 is forbidden",
            },
            {
                "gc_yaml": "global-configuration-forbidden-port-preceding-udp",
                "vs_yaml": "virtual-server",
                "http_listener_in_config": True,
                "https_listener_in_config": True,
                "expected_response_codes": [404, 404, 200, 200],
                "expected_vs_error_msg": "",
                "expected_gc_error_msg": "Listener dns-udp: port 9113 is forbidden",
            },
        ],
        ids=[
            "delete_gc",
            "update_gc_https_listener_ssl_false",
            "update_gc_http_listener_ssl_true",
            "update_gc_http_listener_repeated_port",
            "update_gc_http_listener_forbidden_port",
            "update_gc_ts_listener_forbidden_port",
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
        # Deploy a working global config and virtual server, and then tests for errors after gc update
        print("\nStep 1: Create GC resource")
        secret_name = create_secret_from_yaml(
            kube_apis.v1, virtual_server_setup.namespace, f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
        )
        global_config_file = f"{TEST_DATA}/virtual-server-custom-listeners/global-configuration.yaml"
        gc_resource = create_gc_from_yaml(kube_apis.custom_objects, global_config_file, "nginx-ingress")
        vs_custom_listeners = f"{TEST_DATA}/virtual-server-custom-listeners/virtual-server.yaml"

        print("\nStep 2: Create VS with custom listener (http-8085, https-8445)")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_custom_listeners,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        urls = [
            virtual_server_setup.backend_1_url,
            virtual_server_setup.backend_1_url_ssl,
            virtual_server_setup.backend_1_url_custom,
            virtual_server_setup.backend_1_url_custom_ssl,
        ]

        for url, expected_response in zip(urls, [404, 404, 200, 200]):
            if expected_response > 0:
                res = make_request(url, virtual_server_setup.vs_host)
                assert res.status_code == expected_response
            else:
                with pytest.raises(ConnectionError, match="Connection refused"):
                    make_request(url, virtual_server_setup.vs_host)

        print("\nStep 3: Apply gc or vs update")
        if test_setup["gc_yaml"]:
            global_config_file = f"{TEST_DATA}/virtual-server-custom-listeners/{test_setup['gc_yaml']}.yaml"
            patch_gc_from_yaml(
                kube_apis.custom_objects, gc_resource["metadata"]["name"], global_config_file, "nginx-ingress"
            )
        else:
            delete_gc(kube_apis.custom_objects, gc_resource, "nginx-ingress")
        wait_before_test()

        print("\nStep 4: Test generated VS configs")
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        vs_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        print(vs_config)

        if test_setup["http_listener_in_config"]:
            assert "listen 8085;" in vs_config
            assert "listen [::]:8085;" in vs_config
        else:
            assert "listen 8085;" not in vs_config
            assert "listen [::]:8085;" not in vs_config

        if test_setup["https_listener_in_config"]:
            assert "listen 8445 ssl;" in vs_config
            assert "listen [::]:8445 ssl;" in vs_config
        else:
            assert "listen 8445 ssl;" not in vs_config
            assert "listen [::]:8445 ssl;" not in vs_config

        assert "listen 80;" not in vs_config
        assert "listen [::]:80;" not in vs_config
        assert "listen 443 ssl;" not in vs_config
        assert "listen [::]:443 ssl;" not in vs_config

        print("\nStep 5: Test HTTP responses")
        for url, expected_response in zip(urls, test_setup["expected_response_codes"]):
            if expected_response > 0:
                res = make_request(url, virtual_server_setup.vs_host)
                assert res.status_code == expected_response
            else:
                with pytest.raises(ConnectionError, match="Connection refused"):
                    make_request(url, virtual_server_setup.vs_host)

        print("\nStep 6: Test Kubernetes VirtualServer warning events")
        if test_setup["expected_vs_error_msg"]:
            response = read_vs(kube_apis.custom_objects, virtual_server_setup.namespace, virtual_server_setup.vs_name)
            print(response)
            assert (
                response["status"]["reason"] == "AddedOrUpdatedWithWarning"
                and response["status"]["state"] == "Warning"
                and test_setup["expected_vs_error_msg"] in response["status"]["message"]
            )

        print("\nStep 7: Test Kubernetes GlobalConfiguration warning events")
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
                    and "GlobalConfiguration nginx-ingress/nginx-configuration was added "
                    "or updated" in gc_event_latest.message
                )

        print("\nStep 8: Restore test environments")
        delete_secret(kube_apis.v1, secret_name, virtual_server_setup.namespace)
        restore_default_vs(kube_apis, virtual_server_setup)
        if test_setup["gc_yaml"]:
            delete_gc(kube_apis.custom_objects, gc_resource, "nginx-ingress")

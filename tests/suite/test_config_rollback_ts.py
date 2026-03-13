"""Tests for config rollback with TransportServer resources.

Note: there is no test_configmap_partial_rollback for TS because no ConfigMap key
injects into individual TS server blocks. ConfigMap server-snippets and location-snippets
only affect http server/location blocks (VS/Ingress), not stream server blocks (TS).
TS server blocks only get snippets from the TS resource's own serverSnippets field.
Stream-related ConfigMap settings (stream-snippets, stream-log-format,
stream-log-format-escaping) go into the main nginx.conf stream block, so invalid
values cause main config rollback (tested in test_configmap_main_snippet_rollback).
"""

import socket

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    assert_ts_conf_not_exists,
    assert_ts_status,
    assert_valid_ts,
    assert_valid_vs,
    wait_and_assert_status_code,
)
from suite.utils.custom_resources_utils import (
    create_gc_from_yaml,
    create_ts_from_yaml,
    delete_gc,
    delete_ts,
    patch_ts,
)
from suite.utils.resources_utils import (
    create_items_from_yaml,
    delete_items_from_yaml,
    get_events_for_object,
    get_first_pod_name,
    get_ts_nginx_template_conf,
    replace_configmap,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.ssl_utils import create_sni_session

ts_valid_tcp_src = f"{TEST_DATA}/config-rollback/transport-server/transport-server-valid-tcp.yaml"
ts_invalid_snippet_tcp_src = f"{TEST_DATA}/config-rollback/transport-server/transport-server-invalid-snippet-tcp.yaml"
ts_tls_passthrough_src = f"{TEST_DATA}/config-rollback/transport-server/transport-server-tls-passthrough.yaml"
ts_invalid_snippet_src = f"{TEST_DATA}/config-rollback/transport-server/transport-server-invalid-snippet.yaml"
gc_yaml = f"{TEST_DATA}/transport-server-tcp-load-balance/standard/global-configuration.yaml"
tcp_svc_yaml = f"{TEST_DATA}/transport-server-tcp-load-balance/standard/service_deployment.yaml"
secure_app_yaml = f"{TEST_DATA}/transport-server-tls-passthrough/standard/secure-app.yaml"
secure_app_secret_yaml = f"{TEST_DATA}/transport-server-tls-passthrough/standard/secure-app-secret.yaml"


@pytest.mark.ts
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        {
            "type": "complete",
            "extra_args": [
                "-enable-custom-resources",
                "-enable-config-rollback",
                "-enable-snippets",
                "-enable-tls-passthrough",
                "-global-configuration=nginx-ingress/nginx-configuration",
            ],
        },
    ],
    indirect=True,
)
class TestConfigRollbackTSCreate:
    """Tests that create their own TS resources — no prior config to fall back to.

    Deploys GlobalConfiguration (for the tcp-server listener) and backend apps
    (TCP service + TLS secure app) so that valid TS resources can serve traffic.
    """

    @pytest.fixture(scope="class")
    def ts_create_setup(self, kube_apis, crd_ingress_controller, test_namespace):
        """Deploy GlobalConfiguration + backend apps, clean up after class."""
        gc_resource = create_gc_from_yaml(kube_apis.custom_objects, gc_yaml, "nginx-ingress")
        create_items_from_yaml(kube_apis, tcp_svc_yaml, test_namespace)
        create_items_from_yaml(kube_apis, secure_app_secret_yaml, test_namespace)
        create_items_from_yaml(kube_apis, secure_app_yaml, test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        yield gc_resource
        delete_items_from_yaml(kube_apis, secure_app_yaml, test_namespace)
        delete_items_from_yaml(kube_apis, secure_app_secret_yaml, test_namespace)
        delete_items_from_yaml(kube_apis, tcp_svc_yaml, test_namespace)
        delete_gc(kube_apis.custom_objects, gc_resource, "nginx-ingress")

    @pytest.mark.parametrize(
        "valid_ts_yaml,invalid_ts_yaml,expected_error,traffic_port_attr,sni_hostname",
        [
            (
                ts_valid_tcp_src,
                ts_invalid_snippet_tcp_src,
                '"proxy_upload_rate" directive invalid value',
                "tcp_server_port",
                None,
            ),
            (
                ts_tls_passthrough_src,
                ts_invalid_snippet_src,
                '"proxy_upload_rate" directive invalid value',
                "port_ssl",
                "ts-invalid-snippet.example.com",
            ),
        ],
        ids=["tcp", "tls-passthrough"],
    )
    def test_create_invalid_ts(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ts_create_setup,
        test_namespace,
        valid_ts_yaml,
        invalid_ts_yaml,
        expected_error,
        traffic_port_attr,
        sni_hostname,
    ):
        """Create a valid TS first to prove traffic works, then create an invalid TS
        and verify it's rejected with no config and no traffic.

        Parametrized with TCP and TLS passthrough listener types, both using
        proxy_upload_rate (a valid stream server directive not in the TS CRD spec,
        only available via snippets) with an invalid value.
        """
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        host = ingress_controller_endpoint.public_ip
        port = getattr(ingress_controller_endpoint, traffic_port_attr)

        # --- Baseline: create a VALID TS and verify traffic works ---
        valid_ts = create_ts_from_yaml(kube_apis.custom_objects, valid_ts_yaml, test_namespace)
        wait_before_test()
        valid_ts_name = valid_ts["metadata"]["name"]

        assert_valid_ts(kube_apis, test_namespace, valid_ts_name)

        if sni_hostname:
            session = create_sni_session()
            req_url = f"https://{host.strip('[]')}:{port}"
            resp = session.get(req_url, headers={"host": "ts-tls-passthrough.example.com"}, verify=False, timeout=10)
            assert resp.status_code == 200
        else:
            host_str = host.strip("[]")
            client = socket.create_connection((host_str, port))
            client.sendall(b"connect")
            response = client.recv(4096)
            client.close()
            assert len(response) > 0

        # Clean up valid TS before creating invalid one
        delete_ts(kube_apis.custom_objects, valid_ts, test_namespace)
        wait_before_test()

        # --- Now create the INVALID TS ---
        ts_resource = create_ts_from_yaml(kube_apis.custom_objects, invalid_ts_yaml, test_namespace)
        wait_before_test()
        ts_name = ts_resource["metadata"]["name"]

        # Step 1: TS is Invalid — no previous config to fall back to
        assert_ts_status(
            kube_apis,
            test_namespace,
            ts_name,
            "Invalid",
            expected_reason="AddedOrUpdatedWithError",
            expected_messages=[
                "but was not applied",
                expected_error,
            ],
        )

        # Step 2: conf file was removed — no traffic served for this TS
        assert_ts_conf_not_exists(
            kube_apis, ic_pod, ingress_controller_prerequisites.namespace, test_namespace, ts_name
        )

        # Step 3: traffic is rejected/no response for this TS
        if sni_hostname:
            session = create_sni_session()
            req_url = f"https://{host.strip('[]')}:{port}"
            try:
                resp = session.get(req_url, headers={"host": sni_hostname}, verify=False, timeout=5)
                assert resp.status_code != 200
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                pass  # expected — host is not routed
        else:
            host_str = host.strip("[]")
            try:
                client = socket.create_connection((host_str, port))
                client.sendall(b"connect")
                client.recv(4096)
                client.close()
                pytest.fail("Expected connection to be refused, but it succeeded")
            except (ConnectionRefusedError, ConnectionResetError, socket.timeout, OSError):
                pass  # expected

        # Cleanup
        delete_ts(kube_apis.custom_objects, ts_resource, test_namespace)


@pytest.mark.ts
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-enable-config-rollback",
                    "-enable-snippets",
                    "-enable-tls-passthrough",
                    "-global-configuration=nginx-ingress/nginx-configuration",
                ],
            },
            {"example": "virtual-server", "app_type": "simple"},
            {"example": "transport-server-tcp-load-balance"},
        )
    ],
    indirect=True,
)
class TestConfigRollbackTransportServer:
    """Tests that require existing valid VS and TS with app."""

    @pytest.mark.parametrize(
        "snippet_value,expected_error",
        [
            (
                "proxy_upload_rate invalid;",
                '"proxy_upload_rate" directive invalid value',
            ),
            (
                "proxy_download_rate invalid;",
                '"proxy_download_rate" directive invalid value',
            ),
        ],
    )
    def test_ts_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        transport_server_setup,
        snippet_value,
        expected_error,
    ):
        """Patch an existing valid TS with an invalid stream snippet — config rolls back,
        traffic still works, VS unaffected.

        Uses proxy_upload_rate and proxy_download_rate — valid stream server directives
        not in the TS CRD spec, only available via snippets, and not present in the
        default template config.
        """
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        host = transport_server_setup.public_endpoint.public_ip.strip("[]")
        port = transport_server_setup.public_endpoint.tcp_server_port

        # Step 1: TS has valid config and serves traffic
        assert_valid_ts(kube_apis, transport_server_setup.namespace, transport_server_setup.name)
        client = socket.create_connection((host, port))
        client.sendall(b"connect")
        response = client.recv(4096)
        client.close()
        assert len(response) > 0

        # Step 2: patch TS with invalid server snippet
        patch_ts(
            kube_apis.custom_objects,
            transport_server_setup.namespace,
            {
                "metadata": {"name": transport_server_setup.name},
                "spec": {"serverSnippets": snippet_value},
            },
        )
        wait_before_test()

        # Step 3: TS traffic still works — invalid config was rolled back
        client = socket.create_connection((host, port))
        client.sendall(b"connect")
        response = client.recv(4096)
        client.close()
        assert len(response) > 0

        # Step 4: TS config rolled back, invalid directive absent from conf
        ts_conf_after = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert snippet_value.split(";")[0].split()[0] not in ts_conf_after

        # Step 5: TS is Invalid, status contains actual nginx error and rollback confirmation
        assert_ts_status(
            kube_apis,
            transport_server_setup.namespace,
            transport_server_setup.name,
            "Invalid",
            expected_reason="AddedOrUpdatedWithError",
            expected_messages=[
                "but was not applied",
                "rolled back to previous working config",
                expected_error,
            ],
        )

        # Step 6: VS still serves traffic — unaffected by TS rollback
        assert_valid_vs(kube_apis, virtual_server_setup.namespace, virtual_server_setup.vs_name)
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)

        # Cleanup: remove snippet from TS
        patch_ts(
            kube_apis.custom_objects,
            transport_server_setup.namespace,
            {"metadata": {"name": transport_server_setup.name}, "spec": {"serverSnippets": None}},
        )
        wait_before_test()
        assert_valid_ts(kube_apis, transport_server_setup.namespace, transport_server_setup.name)

    @pytest.mark.parametrize(
        "configmap_data,expected_log_error",
        [
            # main context: invalid value for pcre_jit (not already exposed by IC ConfigMap)
            ({"main-snippets": "pcre_jit invalid;"}, 'invalid value "invalid" in "pcre_jit" directive'),
            # stream context: upstream without a block
            ({"stream-snippets": "upstream;"}, 'directive "upstream" has no opening "{"'),
            # stream log_format with an unknown nginx variable (no $ in the error message)
            ({"stream-log-format": "$invalid_nonexistent_var"}, 'unknown "invalid_nonexistent_var" variable'),
            # stream log_format: must set stream-log-format too, otherwise escaping is never rendered
            (
                {"stream-log-format": "$remote_addr", "stream-log-format-escaping": "invalid_escape_value"},
                'unknown log format escaping "invalid_escape_value"',
            ),
        ],
    )
    def test_configmap_main_snippet_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        transport_server_setup,
        restore_configmap,
        configmap_data,
        expected_log_error,
    ):
        """Invalid ConfigMap setting causes nginx.conf to fail validation and roll back.

        VS and TS are unaffected. Parametrized across ConfigMap keys that affect the main
        nginx.conf stream/main context, each producing a distinct nginx error type:
        - main-snippets: invalid value
        - stream-snippets: missing block
        - stream-log-format: unknown variable
        - stream-log-format-escaping: unknown escape value (needs stream-log-format set too)
        All cause main config nginx -t failure → main config rollback.
        """
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        ts_host = transport_server_setup.public_endpoint.public_ip.strip("[]")
        ts_port = transport_server_setup.public_endpoint.tcp_server_port

        # Step 1: capture TS config before change, verify traffic
        ts_conf_before = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        client = socket.create_connection((ts_host, ts_port))
        client.sendall(b"connect")
        response = client.recv(4096)
        client.close()
        assert len(response) > 0

        # Step 2: VS serves traffic
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)

        # Step 3: apply ConfigMap with invalid setting
        config_map = ingress_controller_prerequisites.config_map.copy()
        config_map["data"] = configmap_data
        replace_configmap(
            kube_apis.v1,
            config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            config_map,
        )
        wait_before_test()

        # Step 4: IC logs confirm main config rollback
        # BUG: When ConfigMap changes cause nginx.conf to fail validation and roll back,
        # no error event is emitted to the ConfigMap — it still shows reason="Updated" (Normal).
        # An "UpdatedWithError" event should be emitted instead. Because of this bug we also
        # scope the log read to since_seconds=30 to avoid matching a rollback from a previous
        # parametrized test case (we cannot rely on the ConfigMap event to distinguish runs).
        cm_events = get_events_for_object(
            kube_apis.v1,
            ingress_controller_prerequisites.namespace,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
        )
        latest_cm = cm_events[-1]
        assert latest_cm.reason == "Updated"
        ic_logs = kube_apis.v1.read_namespaced_pod_log(
            ic_pod, ingress_controller_prerequisites.namespace, since_seconds=30
        )
        assert "Main config was rolled back" in ic_logs
        assert expected_log_error in ic_logs

        # Step 5: VS still serves traffic — Valid status
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        assert_valid_vs(kube_apis, virtual_server_setup.namespace, virtual_server_setup.vs_name)

        # Step 6: TS traffic still works
        client = socket.create_connection((ts_host, ts_port))
        client.sendall(b"connect")
        response = client.recv(4096)
        client.close()
        assert len(response) > 0

        # Step 7: TS config unchanged
        ts_conf_after = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert ts_conf_before == ts_conf_after
        assert_valid_ts(kube_apis, transport_server_setup.namespace, transport_server_setup.name)

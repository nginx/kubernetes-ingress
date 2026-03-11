"""Tests for config rollback with VirtualServer resources."""

import pytest
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    assert_vs_conf_removed,
    wait_and_assert_status_code,
)
from suite.utils.custom_resources_utils import (
    read_ts,
)
from suite.utils.resources_utils import (
    get_events_for_object,
    get_first_pod_name,
    get_ts_nginx_template_conf,
    replace_configmap,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_and_create_vs_from_yaml,
    delete_virtual_server,
    get_vs_nginx_template_conf,
    patch_virtual_server,
    read_vs,
)

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
vs_invalid_snippet_src = f"{TEST_DATA}/config-rollback/virtual-server/virtual-server-invalid-snippet.yaml"
vs_2_src = f"{TEST_DATA}/config-rollback/virtual-server/virtual-server-2.yaml"
vs_with_valid_snippet_src = f"{TEST_DATA}/config-rollback/virtual-server/virtual-server-with-valid-snippet.yaml"

IC_EXTRA_ARGS = [
    "-enable-custom-resources",
    "-enable-config-rollback",
    "-enable-snippets",
    "-global-configuration=nginx-ingress/nginx-configuration",
    "-enable-leader-election=false",
]


@pytest.mark.vs
@pytest.mark.parametrize(
    "crd_ingress_controller, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": IC_EXTRA_ARGS,
            },
            {"example": "transport-server-tcp-load-balance"},
        )
    ],
    indirect=True,
)
class TestConfigRollbackVSCreate:
    """Tests that create their own VS resources and do not need the virtual_server_setup fixture."""

    def test_create_invalid_vs(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ingress_controller_endpoint,
        transport_server_setup,
        test_namespace,
    ):
        """Create a VS with an invalid snippet — no prior config, conf file removed, no traffic."""
        # Step 1: create VS with invalid server-snippet baked in (sub_filter_once invalid)
        vs_name = create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            vs_invalid_snippet_src,
            test_namespace,
        )
        wait_before_test()
        # Step 2: VS is Invalid — no previous config to fall back to
        vs_info = read_vs(kube_apis.custom_objects, test_namespace, vs_name)
        assert vs_info["status"]["state"] == "Invalid"
        # Step 3: conf file was removed — no traffic served for this host
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_vs_conf_removed(kube_apis, ic_pod, ingress_controller_prerequisites.namespace, test_namespace, vs_name)
        wait_and_assert_status_code(
            404,
            f"http://{ingress_controller_endpoint.public_ip}" f":{ingress_controller_endpoint.port}/backend1",
            "config-rollback-invalid-vs.example.com",
        )
        # Step 4: event contains actual nginx error, no "rolled back" (nothing to roll back to)
        vs_events = get_events_for_object(kube_apis.v1, test_namespace, vs_name)
        latest = vs_events[-1]
        assert latest.reason == "AddedOrUpdatedWithError"
        assert "but was not applied" in latest.message
        print(latest.reason)
        # Cleanup
        delete_virtual_server(kube_apis.custom_objects, vs_name, test_namespace)


@pytest.mark.rollback
@pytest.mark.vs
@pytest.mark.vs_config_map
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": IC_EXTRA_ARGS,
            },
            {"example": "virtual-server", "app_type": "simple"},
            {"example": "transport-server-tcp-load-balance"},
        )
    ],
    indirect=True,
)
class TestConfigRollbackVirtualServer:
    """Tests that require the virtual_server_setup fixture (existing valid VS with app)."""

    def test_vs_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        transport_server_setup,
    ):
        """Patch an existing valid VS with an invalid snippet — config rolls back."""
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        # Step 1: valid VS serves traffic
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        # Step 2: apply invalid server-snippet (sub_filter_once with bad value)
        patch_virtual_server(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            virtual_server_setup.namespace,
            {
                "metadata": {"name": virtual_server_setup.vs_name},
                "spec": {"server-snippets": "sub_filter_once invalid;"},
            },
        )
        wait_before_test()
        # Step 3: traffic still works — invalid config was rolled back
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        conf = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert "sub_filter_once" not in conf
        # Step 4: VS is Invalid, event contains actual nginx error and rollback confirmation
        vs_info = read_vs(kube_apis.custom_objects, virtual_server_setup.namespace, virtual_server_setup.vs_name)
        assert vs_info["status"]["state"] == "Invalid"
        vs_events = get_events_for_object(kube_apis.v1, virtual_server_setup.namespace, virtual_server_setup.vs_name)
        latest = vs_events[-1]
        assert latest.reason == "AddedOrUpdatedWithError"
        assert "but was not applied" in latest.message
        assert "rolled back to previous working config" in latest.message
        print(latest.reason)
        # Step 5: add new VS to prove nginx -t still passes after rollback
        vs2_name = create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            vs_2_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        wait_and_assert_status_code(
            200,
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/backend1",
            "config-rollback-vs2.example.com",
        )
        # Cleanup
        delete_virtual_server(kube_apis.custom_objects, vs2_name, virtual_server_setup.namespace)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, virtual_server_setup.namespace
        )
        wait_before_test()

    def test_configmap_main_snippet_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        transport_server_setup,
        restore_configmap,
    ):
        """Invalid main-snippets in ConfigMap — nginx.conf rolls back, VS and TS not affected."""
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        # Step 1: VS serves traffic, capture TS config
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        ts_conf_before = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        # Step 2: apply ConfigMap with invalid main-snippets (pcre_jit is not in ConfigMap)
        config_map = ingress_controller_prerequisites.config_map.copy()
        config_map["data"] = {"main-snippets": "pcre_jit invalid;"}
        replace_configmap(
            kube_apis.v1,
            config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            config_map,
        )
        wait_before_test()
        # Step 3: IC logs confirm rollback with actual nginx error
        ic_logs = kube_apis.v1.read_namespaced_pod_log(ic_pod, ingress_controller_prerequisites.namespace)
        assert "Main config was rolled back" in ic_logs
        print(ic_logs)
        # Step 4: VS still responds — nginx.conf was rolled back, VS not affected
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        vs_info = read_vs(kube_apis.custom_objects, virtual_server_setup.namespace, virtual_server_setup.vs_name)
        assert vs_info["status"]["state"] == "Valid"
        # Step 5: TS config unchanged
        ts_conf_after = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert ts_conf_before == ts_conf_after
        ts_info = read_ts(kube_apis.custom_objects, transport_server_setup.namespace, transport_server_setup.name)
        assert ts_info["status"]["state"] == "Valid"

    def test_configmap_invalid_does_not_affect_other_resources(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        transport_server_setup,
        restore_configmap,
    ):
        """A validation error in one config must not abort generation of subsequent configs.

        The ingress controller processes resource configs in alphanumeric order.
        VS1 (from fixture, no route-level location-snippets) inherits the invalid
        ConfigMap location-snippet, so it fails validation and rolls back.  VS2 (has
        its own route-level location-snippets that override the ConfigMap) must still
        be generated and applied successfully.  This proves that a nginx -t failure
        for one resource does not prevent other resources from being processed.
        """
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        # Step 1: VS1 (from fixture, no location-snippets on routes) serves traffic
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        # Step 2: create VS2 (has route-level location-snippets that override ConfigMap)
        vs2_name = create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            vs_with_valid_snippet_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        wait_and_assert_status_code(
            200,
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/backend1",
            "virtual-server-with-snippet.example.com",
        )
        # Step 3: capture TS config before ConfigMap change
        ts_conf_before = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )

        # Step 4: apply ConfigMap with invalid location-snippets
        config_map = ingress_controller_prerequisites.config_map.copy()
        config_map["data"] = {"location-snippets": "add_header;"}
        replace_configmap(
            kube_apis.v1,
            config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            config_map,
        )
        wait_before_test()

        # Step 5: VS1 rolled back but still serves traffic
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)

        # Step 6: VS1 is Invalid with actual nginx error
        vs1_info = read_vs(kube_apis.custom_objects, virtual_server_setup.namespace, virtual_server_setup.vs_name)
        assert vs1_info["status"]["state"] == "Invalid"

        vs1_events = get_events_for_object(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
        )
        latest_vs1 = vs1_events[-1]
        assert latest_vs1.reason == "AddedOrUpdatedWithError"
        assert "but was not applied" in latest_vs1.message
        assert "rolled back to previous working config" in latest_vs1.message
        print(latest_vs1.reason)

        # Step 7: VS2 (own route-level location-snippets override ConfigMap) still Valid
        vs2_info = read_vs(kube_apis.custom_objects, virtual_server_setup.namespace, vs2_name)
        assert vs2_info["status"]["state"] == "Valid"
        wait_and_assert_status_code(
            200,
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/backend1",
            "virtual-server-with-snippet.example.com",
        )

        # Step 8: TS config unchanged (stream blocks not affected by location-snippets)
        ts_conf_after = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert ts_conf_before == ts_conf_after
        ts_info = read_ts(kube_apis.custom_objects, transport_server_setup.namespace, transport_server_setup.name)
        assert ts_info["status"]["state"] == "Valid"

        # Step 9: ConfigMap event reflects partial failure
        cm_events = get_events_for_object(
            kube_apis.v1,
            ingress_controller_prerequisites.namespace,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
        )
        latest_cm = cm_events[-1]
        assert latest_cm.reason == "UpdatedWithError"
        assert "some resource configs failed validation" in latest_cm.message

        # Cleanup
        delete_virtual_server(kube_apis.custom_objects, vs2_name, virtual_server_setup.namespace)

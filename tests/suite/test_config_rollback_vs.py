"""Tests for config rollback with VirtualServer resources."""

import copy

import pytest
import yaml
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    assert_valid_ts,
    assert_valid_vs,
    assert_vs_conf_not_exists,
    assert_vs_status,
    wait_and_assert_status_code,
)
from suite.utils.resources_utils import (
    get_events_for_object,
    get_first_pod_name,
    get_ts_nginx_template_conf,
    get_vs_nginx_template_conf,
    replace_configmap,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_and_create_vs_from_yaml,
    delete_virtual_server,
    patch_virtual_server,
)

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
vs_invalid_snippet_src = f"{TEST_DATA}/config-rollback/virtual-server/virtual-server-invalid-snippet.yaml"
vs_2_src = f"{TEST_DATA}/config-rollback/virtual-server/virtual-server-2.yaml"


@pytest.mark.vs
@pytest.mark.parametrize(
    "crd_ingress_controller, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-enable-config-rollback",
                    "-enable-snippets",
                    "-global-configuration=nginx-ingress/nginx-configuration",
                ],
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
        # Step 2: VS is Invalid — no previous config to fall back to, status contains actual nginx error
        assert_vs_status(
            kube_apis,
            test_namespace,
            vs_name,
            "Invalid",
            expected_reason="AddedOrUpdatedWithError",
            expected_messages=[
                "but was not applied",
                'invalid value "invalid" in "sub_filter_once" directive',
            ],
        )
        # Step 3: conf file was removed — no traffic served for this host
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_vs_conf_not_exists(
            kube_apis, ic_pod, ingress_controller_prerequisites.namespace, test_namespace, vs_name
        )
        wait_and_assert_status_code(
            404,
            f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1",
            "config-rollback-invalid-vs.example.com",
        )
        # Cleanup
        delete_virtual_server(kube_apis.custom_objects, vs_name, test_namespace)


@pytest.mark.vs
@pytest.mark.vs_config_map
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
                    "-global-configuration=nginx-ingress/nginx-configuration",
                ],
            },
            {"example": "virtual-server", "app_type": "simple"},
            {"example": "transport-server-tcp-load-balance"},
        )
    ],
    indirect=True,
)
class TestConfigRollbackVirtualServer:
    """Tests that require the virtual_server_setup fixture (existing valid VS with app)."""

    @pytest.mark.parametrize(
        "apply_patch,expected_conf_absent,expected_nginx_error",
        [
            pytest.param(
                lambda vs: vs["spec"].update({"server-snippets": "sub_filter_once invalid;"}),
                "sub_filter_once",
                'invalid value "invalid" in "sub_filter_once" directive',
                id="server-snippets",
            ),
            pytest.param(
                lambda vs: vs["spec"]["routes"][0].update({"location-snippets": "add_header;"}),
                "add_header",
                'invalid number of arguments in "add_header" directive',
                id="location-snippets",
            ),
            # buffer-size alone (default proxy_buffers = 4 4k = 16k total):
            # proxy_busy_buffers_size must be < pool minus one buffer = 12k, but 16k > 12k
            pytest.param(
                lambda vs: vs["spec"]["upstreams"][0].update({"buffer-size": "16k"}),
                "proxy_buffer_size 16k",
                '"proxy_busy_buffers_size" must be less than the size of all "proxy_buffers" minus one buffer',
                id="buffer-size",
            ),
            # both set explicitly but incompatible: pool = 2 * 4k = 8k, buffer_size = 32k > 4k
            pytest.param(
                lambda vs: vs["spec"]["upstreams"][0].update(
                    {"buffer-size": "32k", "buffers": {"number": 2, "size": "4k"}}
                ),
                "proxy_buffer_size 32k",
                '"proxy_busy_buffers_size" must be less than the size of all "proxy_buffers" minus one buffer',
                id="buffer-size-and-buffers",
            ),
        ],
    )
    def test_vs_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        transport_server_setup,
        apply_patch,
        expected_conf_absent,
        expected_nginx_error,
    ):
        """Patch an existing valid VS with an invalid spec — config rolls back.

        Parametrized across snippet fields (server-snippets, location-snippets) and
        upstream proxy buffer fields (buffer-size alone or with incompatible buffers),
        covering nginx errors from different config directive types.
        """
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        # Step 1: valid VS serves traffic
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        # Step 2: load VS YAML, apply invalid patch, send to cluster
        with open(std_vs_src) as f:
            vs_body = copy.deepcopy(yaml.safe_load(f))
        apply_patch(vs_body)
        patch_virtual_server(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            virtual_server_setup.namespace,
            vs_body,
        )
        wait_before_test()
        # Step 3: traffic still works — invalid config was rolled back
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        # Step 3a: confirm rolled-back nginx conf does NOT contain the invalid directive
        conf = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert expected_conf_absent not in conf
        # Step 4: VS is Invalid, status contains actual nginx error and rollback confirmation
        assert_vs_status(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            "Invalid",
            expected_reason="AddedOrUpdatedWithError",
            expected_messages=[
                "but was not applied",
                "rolled back to previous working config",
                expected_nginx_error,
            ],
        )
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

    @pytest.mark.parametrize(
        "configmap_data,expected_log_error",
        [
            # main context: invalid value for pcre_jit
            ({"main-snippets": "pcre_jit invalid;"}, 'invalid value "invalid" in "pcre_jit" directive'),
            # http context: upstream without a block
            ({"http-snippets": "upstream;"}, 'directive "upstream" has no opening "{"'),
            # http log_format: unknown variable (no $ in error message)
            ({"log-format": "$invalid_nonexistent_var"}, 'unknown "invalid_nonexistent_var" variable'),
            # http log_format: must set log-format too, otherwise escaping is never rendered
            (
                {"log-format": "$remote_addr", "log-format-escaping": "invalid_escape_value"},
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

        VS and TS are unaffected. Parametrized across different ConfigMap keys and nginx
        error types (invalid value, missing block, unknown variable, unknown escape value).
        Note: log-format-escaping only takes effect when log-format is also set, so the
        escaping case passes both keys together.
        """
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
        # Step 2: apply ConfigMap with invalid setting
        config_map = ingress_controller_prerequisites.config_map.copy()
        config_map["data"] = configmap_data
        replace_configmap(
            kube_apis.v1,
            config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            config_map,
        )
        wait_before_test()
        # Step 3: IC logs confirm rollback with actual nginx error
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
        # Step 4: VS still responds — nginx.conf was rolled back, VS not affected
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        assert_valid_vs(kube_apis, virtual_server_setup.namespace, virtual_server_setup.vs_name)
        # Step 5: TS config unchanged
        ts_conf_after = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert ts_conf_before == ts_conf_after
        assert_valid_ts(kube_apis, transport_server_setup.namespace, transport_server_setup.name)

    @pytest.mark.parametrize(
        "protect_vs",
        ["vs1", "vs2"],
    )
    def test_configmap_partial_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        transport_server_setup,
        restore_configmap,
        protect_vs,
    ):
        """ConfigMap location-snippets invalid: one VS is protected (has own snippet that overrides
        ConfigMap), the other is not — the unprotected VS rolls back while the protected VS and
        TS remain Valid.

        Parametrized with protect_vs=vs1/vs2 to test both orderings, so we don't rely on
        alphabetical resource processing order.
        """
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)

        # Step 1: both VSes start without own location-snippets
        # VS1 = fixture VS (virtual-server), VS2 = created from plain YAML
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        vs2_name = create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            vs_2_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        vs2_host = "config-rollback-vs2.example.com"
        vs2_url = (
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/backend1"
        )
        wait_and_assert_status_code(200, vs2_url, vs2_host)

        # Step 2: protect one VS by patching it with a valid location-snippet
        # The protected VS's own snippet overrides ConfigMap location-snippets
        valid_snippet_patch = {
            "spec": {
                "routes": [
                    {
                        "path": "/backend1",
                        "location-snippets": "sub_filter_once off;",
                        "action": {"pass": "backend1"},
                    }
                ]
            },
        }
        if protect_vs == "vs1":
            patch_virtual_server(
                kube_apis.custom_objects,
                virtual_server_setup.vs_name,
                virtual_server_setup.namespace,
                {"metadata": {"name": virtual_server_setup.vs_name}, **valid_snippet_patch},
            )
        else:
            patch_virtual_server(
                kube_apis.custom_objects,
                vs2_name,
                virtual_server_setup.namespace,
                {"metadata": {"name": vs2_name}, **valid_snippet_patch},
            )
        wait_before_test()

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

        # Step 5: the UNPROTECTED VS fails validation and rolls back (Invalid status),
        # but still serves traffic from the rolled-back config
        if protect_vs == "vs1":
            # VS2 is unprotected → Invalid
            assert_vs_status(
                kube_apis,
                virtual_server_setup.namespace,
                vs2_name,
                "Invalid",
                expected_reason="AddedOrUpdatedWithError",
                expected_messages=[
                    "but was not applied",
                    'invalid number of arguments in "add_header" directive',
                ],
            )
            # VS1 is protected → Valid (own snippet overrides ConfigMap)
            assert_valid_vs(kube_apis, virtual_server_setup.namespace, virtual_server_setup.vs_name)
            wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        else:
            # VS1 is unprotected → Invalid
            assert_vs_status(
                kube_apis,
                virtual_server_setup.namespace,
                virtual_server_setup.vs_name,
                "Invalid",
                expected_reason="AddedOrUpdatedWithError",
                expected_messages=[
                    "but was not applied",
                    'invalid number of arguments in "add_header" directive',
                ],
            )
            # VS2 is protected → Valid (own snippet overrides ConfigMap)
            assert_valid_vs(kube_apis, virtual_server_setup.namespace, vs2_name)
            wait_and_assert_status_code(200, vs2_url, vs2_host)

        # Step 6: TS config unchanged (stream blocks not affected by location-snippets)
        ts_conf_after = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert ts_conf_before == ts_conf_after
        assert_valid_ts(kube_apis, transport_server_setup.namespace, transport_server_setup.name)

        # Step 7: ConfigMap event reflects partial failure
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
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, std_vs_src, virtual_server_setup.namespace
        )
        wait_before_test()

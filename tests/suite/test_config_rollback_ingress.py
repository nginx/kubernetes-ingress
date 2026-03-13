"""Tests for config rollback with Ingress resources."""

import pytest
import yaml
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    assert_ingress_conf_not_exists,
    assert_valid_ts,
    wait_and_assert_status_code,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress_from_yaml,
    delete_common_app,
    delete_ingress,
    get_events_for_object,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    get_ts_nginx_template_conf,
    replace_configmap,
    replace_ingress,
    wait_before_test,
    wait_until_all_pods_are_ready,
)

ingress_src = f"{TEST_DATA}/config-rollback/ingress/ingress.yaml"
ingress_invalid_snippet_src = f"{TEST_DATA}/config-rollback/ingress/ingress-invalid-snippet.yaml"
ingress_2_src = f"{TEST_DATA}/config-rollback/ingress/ingress-2.yaml"


@pytest.mark.ingresses
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
class TestConfigRollbackIngressCreate:
    """Tests that create their own Ingress resources — no prior config to fall back to."""

    def test_create_invalid_ingress(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ingress_controller_endpoint,
        transport_server_setup,
        test_namespace,
    ):
        """Create an Ingress with an invalid snippet — no prior config, conf file removed, no traffic."""
        # Step 1: create Ingress with invalid server-snippet baked in
        ingress_name = create_ingress_from_yaml(
            kube_apis.networking_v1,
            test_namespace,
            ingress_invalid_snippet_src,
        )
        wait_before_test()

        # Step 2: conf file removed — no traffic served
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_ingress_conf_not_exists(
            kube_apis, ic_pod, ingress_controller_prerequisites.namespace, test_namespace, ingress_name
        )
        wait_and_assert_status_code(
            404,
            f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1",
            "config-rollback-invalid-ingress.example.com",
        )

        # Step 3: event contains actual nginx error, but no "rolled back" (nothing to roll back to)
        ing_events = get_events_for_object(kube_apis.v1, test_namespace, ingress_name)
        latest = ing_events[-1]
        assert "AddedOrUpdatedWithError" in latest.reason
        assert "but was not applied" in latest.message
        assert 'invalid value "invalid" in "sub_filter_once" directive' in latest.message

        # Cleanup
        delete_ingress(kube_apis.networking_v1, ingress_name, test_namespace)


@pytest.mark.ingresses
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
class TestConfigRollbackIngress:
    """Tests that require an existing valid Ingress with app."""

    @pytest.fixture(scope="class")
    def ingress_setup(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        transport_server_setup,
        test_namespace,
    ):
        """Create an Ingress with a backend app for the test class."""
        ingress_name = create_ingress_from_yaml(
            kube_apis.networking_v1,
            test_namespace,
            ingress_src,
        )
        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        wait_before_test()
        yield {
            "ingress_name": ingress_name,
        }
        try:
            delete_ingress(kube_apis.networking_v1, ingress_name, test_namespace)
        except Exception:
            pass
        delete_common_app(kube_apis, "simple", test_namespace)

    @pytest.mark.parametrize(
        "annotations,expected_conf_absent,expected_nginx_error",
        [
            (
                {"nginx.org/server-snippets": "sub_filter_once invalid;"},
                "sub_filter_once",
                'invalid value "invalid" in "sub_filter_once" directive',
            ),
            (
                {"nginx.org/location-snippets": "add_header;"},
                "add_header",
                'invalid number of arguments in "add_header" directive',
            ),
            # proxy-buffer-size alone (default proxy_buffers = 4 4k = 16k total):
            # proxy_busy_buffers_size must be < pool minus one buffer = 12k, but 16k > 12k
            (
                {"nginx.org/proxy-buffer-size": "16k"},
                "proxy_buffer_size 16k",
                '"proxy_busy_buffers_size" must be less than the size of all "proxy_buffers" minus one buffer',
            ),
            # both set explicitly but incompatible: pool = 2 * 4k = 8k, buffer_size = 32k > 4k
            (
                {"nginx.org/proxy-buffer-size": "32k", "nginx.org/proxy-buffers": "2 4k"},
                "proxy_buffer_size 32k",
                '"proxy_busy_buffers_size" must be less than the size of all "proxy_buffers" minus one buffer',
            ),
        ],
    )
    def test_ingress_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        transport_server_setup,
        ingress_controller_endpoint,
        ingress_setup,
        test_namespace,
        annotations,
        expected_conf_absent,
        expected_nginx_error,
    ):
        """Patch an existing valid Ingress with an invalid annotation — config rolls back."""
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        ingress_name = ingress_setup["ingress_name"]
        ingress_host = "config-rollback-ingress.example.com"
        ingress_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        # Step 1: Ingress serves traffic
        wait_and_assert_status_code(200, ingress_url, ingress_host)

        # Step 2: patch Ingress with invalid annotation(s)
        with open(ingress_src) as f:
            ingress_body = yaml.safe_load(f)
        if "annotations" not in ingress_body["metadata"]:
            ingress_body["metadata"]["annotations"] = {}
        ingress_body["metadata"]["annotations"].update(annotations)
        replace_ingress(kube_apis.networking_v1, ingress_name, test_namespace, ingress_body)
        wait_before_test()

        # Step 3: traffic still works — invalid config rolled back
        wait_and_assert_status_code(200, ingress_url, ingress_host)
        # Step 3a: confirm rolled-back nginx conf does NOT contain the invalid directive
        conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            test_namespace,
            ingress_name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert expected_conf_absent not in conf

        # Step 4: event contains actual nginx error and rollback confirmation
        ing_events = get_events_for_object(kube_apis.v1, test_namespace, ingress_name)
        latest = ing_events[-1]
        assert "AddedOrUpdatedWithError" in latest.reason
        assert "but was not applied" in latest.message
        assert "rolled back to previous working config" in latest.message
        assert expected_nginx_error in latest.message

        # Cleanup: restore original Ingress
        with open(ingress_src) as f:
            original_body = yaml.safe_load(f)
        replace_ingress(kube_apis.networking_v1, ingress_name, test_namespace, original_body)
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
        transport_server_setup,
        ingress_controller_endpoint,
        ingress_setup,
        test_namespace,
        restore_configmap,
        configmap_data,
        expected_log_error,
    ):
        """Invalid ConfigMap setting causes nginx.conf to fail validation and roll back.

        Ingress and TS are unaffected. Parametrized across different ConfigMap keys and nginx
        error types (invalid value, missing block, unknown variable, unknown escape value).
        Note: log-format-escaping only takes effect when log-format is also set, so the
        escaping case passes both keys together.
        """
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        ingress_setup["ingress_name"]
        ingress_host = "config-rollback-ingress.example.com"
        ingress_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        # Step 1: Ingress serves traffic, capture TS config
        wait_and_assert_status_code(200, ingress_url, ingress_host)
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
        ic_logs = kube_apis.v1.read_namespaced_pod_log(
            ic_pod, ingress_controller_prerequisites.namespace, since_seconds=30
        )
        assert "Main config was rolled back" in ic_logs
        assert expected_log_error in ic_logs
        cm_events = get_events_for_object(
            kube_apis.v1,
            ingress_controller_prerequisites.namespace,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
        )
        latest_cm = cm_events[-1]
        assert latest_cm.reason == "Updated"

        # Step 4: Ingress still responds
        wait_and_assert_status_code(200, ingress_url, ingress_host)

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
        "protect_ingress",
        ["ingress1", "ingress2"],
    )
    def test_configmap_partial_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        transport_server_setup,
        ingress_controller_endpoint,
        ingress_setup,
        test_namespace,
        restore_configmap,
        protect_ingress,
    ):
        """ConfigMap location-snippets invalid: one Ingress is protected (has own annotation that
        overrides ConfigMap), the other is not — the unprotected Ingress rolls back while the
        protected Ingress and TS remain Valid.

        Parametrized with protect_ingress=ingress1/ingress2 to test both orderings, so we don't
        rely on alphabetical resource processing order.
        """
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        ingress1_name = ingress_setup["ingress_name"]
        ingress1_host = "config-rollback-ingress.example.com"
        ingress1_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        # Step 1: both Ingresses start without own location-snippets annotations
        # Ingress1 = fixture Ingress, Ingress2 = created from plain YAML
        wait_and_assert_status_code(200, ingress1_url, ingress1_host)
        ingress2_name = create_ingress_from_yaml(
            kube_apis.networking_v1,
            test_namespace,
            ingress_2_src,
        )
        wait_before_test()
        ingress2_host = "config-rollback-ingress2.example.com"
        ingress2_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"
        wait_and_assert_status_code(200, ingress2_url, ingress2_host)

        # Step 2: protect one Ingress by adding a valid location-snippet annotation
        # The protected Ingress's own annotation overrides ConfigMap location-snippets
        if protect_ingress == "ingress1":
            with open(ingress_src) as f:
                body = yaml.safe_load(f)
            if "annotations" not in body["metadata"]:
                body["metadata"]["annotations"] = {}
            body["metadata"]["annotations"]["nginx.org/location-snippets"] = "sub_filter_once off;"
            replace_ingress(kube_apis.networking_v1, ingress1_name, test_namespace, body)
        else:
            with open(ingress_2_src) as f:
                body = yaml.safe_load(f)
            if "annotations" not in body["metadata"]:
                body["metadata"]["annotations"] = {}
            body["metadata"]["annotations"]["nginx.org/location-snippets"] = "sub_filter_once off;"
            replace_ingress(kube_apis.networking_v1, ingress2_name, test_namespace, body)
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

        # Step 5: the UNPROTECTED Ingress fails validation and rolls back,
        # the PROTECTED Ingress remains valid (own annotation overrides ConfigMap)
        if protect_ingress == "ingress1":
            # Ingress2 is unprotected → event shows error
            ing2_events = get_events_for_object(kube_apis.v1, test_namespace, ingress2_name)
            latest2 = ing2_events[-1]
            assert "AddedOrUpdatedWithError" in latest2.reason
            assert "but was not applied" in latest2.message
            assert 'invalid number of arguments in "add_header" directive' in latest2.message
            # Ingress1 is protected → still serves traffic
            wait_and_assert_status_code(200, ingress1_url, ingress1_host)
        else:
            # Ingress1 is unprotected → event shows error
            ing1_events = get_events_for_object(kube_apis.v1, test_namespace, ingress1_name)
            latest1 = ing1_events[-1]
            assert "AddedOrUpdatedWithError" in latest1.reason
            assert "but was not applied" in latest1.message
            assert 'invalid number of arguments in "add_header" directive' in latest1.message
            # Ingress2 is protected → still serves traffic
            wait_and_assert_status_code(200, ingress2_url, ingress2_host)

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
        delete_ingress(kube_apis.networking_v1, ingress2_name, test_namespace)
        with open(ingress_src) as f:
            original_body = yaml.safe_load(f)
        replace_ingress(kube_apis.networking_v1, ingress1_name, test_namespace, original_body)
        wait_before_test()

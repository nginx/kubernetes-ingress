"""Tests for config rollback with Ingress resources."""

import pytest
import yaml
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    assert_event,
    assert_ingress_conf_not_exists,
    assert_valid_ts,
    wait_and_assert_status_code,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress_from_yaml,
    create_items_from_yaml,
    delete_common_app,
    delete_ingress,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    get_events_for_object,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    get_ts_nginx_template_conf,
    replace_configmap,
    replace_ingress,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml, get_name_from_yaml


class IngressSetup:
    """Encapsulate ingress_setup details.

    Attributes:
        ingress_name (str): name of the created Ingress resource
        ingress_host (str): first hostname from the Ingress spec
        ingress_pod_name (str): IC pod name at fixture creation time
        namespace (str): test namespace
    """

    def __init__(self, ingress_name, ingress_host, ingress_pod_name, namespace):
        self.ingress_name = ingress_name
        self.ingress_host = ingress_host
        self.ingress_pod_name = ingress_pod_name
        self.namespace = namespace


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
                    "-enable-config-safety",
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
        assert_ingress_conf_not_exists(
            kube_apis,
            get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace),
            ingress_controller_prerequisites.namespace,
            test_namespace,
            ingress_name,
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
                    "-enable-config-safety",
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
        request,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
    ) -> IngressSetup:
        """Create an Ingress with a backend app for the test class."""
        create_items_from_yaml(kube_apis, ingress_src, test_namespace)
        ingress_name = get_name_from_yaml(ingress_src)
        ingress_host = get_first_ingress_host_from_yaml(ingress_src)
        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)

        def fin():
            if request.config.getoption("--skip-fixture-teardown") == "no":
                delete_common_app(kube_apis, "simple", test_namespace)
                delete_items_from_yaml(kube_apis, ingress_src, test_namespace)

        request.addfinalizer(fin)
        return IngressSetup(ingress_name, ingress_host, ic_pod_name, test_namespace)

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
        ingress_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        # Step 1: Ingress serves traffic
        wait_and_assert_status_code(200, ingress_url, ingress_setup.ingress_host)

        # Step 2: patch Ingress with invalid annotation(s)
        with open(ingress_src) as f:
            ingress_body = yaml.safe_load(f)
        if "annotations" not in ingress_body["metadata"]:
            ingress_body["metadata"]["annotations"] = {}
        ingress_body["metadata"]["annotations"].update(annotations)
        replace_ingress(kube_apis.networking_v1, ingress_setup.ingress_name, test_namespace, ingress_body)
        wait_before_test()

        # Step 3: traffic still works — invalid config rolled back
        wait_and_assert_status_code(200, ingress_url, ingress_setup.ingress_host)
        # Step 3a: confirm rolled-back nginx conf does NOT contain the invalid directive
        assert expected_conf_absent not in get_ingress_nginx_template_conf(
            kube_apis.v1,
            test_namespace,
            ingress_setup.ingress_name,
            ingress_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        # Step 4: event contains actual nginx error and rollback confirmation
        ing_events = get_events_for_object(kube_apis.v1, test_namespace, ingress_setup.ingress_name)
        latest = ing_events[-1]
        assert "AddedOrUpdatedWithError" in latest.reason
        assert "but was not applied" in latest.message
        assert "rolled back to previous working config" in latest.message
        assert expected_nginx_error in latest.message

        # Cleanup: restore original Ingress
        with open(ingress_src) as f:
            original_body = yaml.safe_load(f)
        replace_ingress(kube_apis.networking_v1, ingress_setup.ingress_name, test_namespace, original_body)
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
        ingress_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        # Step 1: Ingress serves traffic, capture TS config
        wait_and_assert_status_code(200, ingress_url, ingress_setup.ingress_host)
        ts_conf_before = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ingress_setup.ingress_pod_name,
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
            ingress_setup.ingress_pod_name, ingress_controller_prerequisites.namespace, since_seconds=30
        )
        assert "Main config validation failed" in ic_logs
        assert expected_log_error in ic_logs
        cm_events = get_events_for_object(
            kube_apis.v1,
            ingress_controller_prerequisites.namespace,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
        )
        latest_cm = cm_events[-1]
        assert latest_cm.reason == "Updated"

        # Step 4: Ingress still responds
        wait_and_assert_status_code(200, ingress_url, ingress_setup.ingress_host)

        # Step 5: TS config unchanged
        ts_conf_after = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ingress_setup.ingress_pod_name,
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
        ingress1_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        # Step 1: both Ingresses start without own location-snippets annotations
        # Ingress1 = fixture Ingress, Ingress2 = created from plain YAML
        wait_and_assert_status_code(200, ingress1_url, ingress_setup.ingress_host)
        ingress2_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_2_src)
        wait_before_test()
        ingress2_host = get_first_ingress_host_from_yaml(ingress_2_src)
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
            replace_ingress(kube_apis.networking_v1, ingress_setup.ingress_name, test_namespace, body)
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
            ingress_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        # Step 3a: capture initial event counts before ConfigMap change
        if protect_ingress == "ingress1":
            protected_name = ingress_setup.ingress_name
            protected_url, protected_host = ingress1_url, ingress_setup.ingress_host
            unprotected_name = ingress2_name
        else:
            protected_name = ingress2_name
            protected_url, protected_host = ingress2_url, ingress2_host
            unprotected_name = ingress_setup.ingress_name

        initial_num_protected_events = len(get_events_for_object(kube_apis.v1, test_namespace, protected_name))

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
        # Unprotected Ingress → event shows error
        unprotected_events = get_events_for_object(kube_apis.v1, test_namespace, unprotected_name)
        assert_event("but was not applied", unprotected_events)
        assert_event('invalid number of arguments in "add_header" directive', unprotected_events)

        # Protected Ingress → no new event types (Normal/AddedOrUpdated coalesced), still serves traffic
        new_protected_events = get_events_for_object(kube_apis.v1, test_namespace, protected_name)
        assert len(new_protected_events) == initial_num_protected_events, (
            f"Expected no new event objects for protected Ingress '{protected_name}', "
            f"but event count changed from {initial_num_protected_events} to {len(new_protected_events)}"
        )
        wait_and_assert_status_code(200, protected_url, protected_host)

        # Step 6: TS config unchanged (stream blocks not affected by location-snippets)
        ts_conf_after = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            ingress_setup.ingress_pod_name,
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
        replace_ingress(kube_apis.networking_v1, ingress_setup.ingress_name, test_namespace, original_body)
        wait_before_test()

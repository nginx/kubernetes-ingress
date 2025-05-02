import pytest
from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.resources_utils import (
    get_events,
    get_events_for_object,
    get_file_contents,
    get_first_pod_name,
    get_pods_amount,
    replace_configmap_from_yaml,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import get_vs_nginx_template_conf
from suite.utils.yaml_utils import get_configmap_fields_from_yaml


def assert_update_events_emitted(virtual_server_setup, new_list, previous_list, expected_amount):
    item_name = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
    text_valid = f"Configuration for {item_name} was added or updated"
    text_invalid = "but was not applied"
    new_event = new_list[len(new_list) - 1]
    assert len(new_list) - len(previous_list) == expected_amount
    assert text_valid in new_event.message and text_invalid not in new_event.message


def assert_not_applied_events_emitted(virtual_server_setup, new_list, previous_list, expected_amount):
    item_name = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
    text_invalid = f"Configuration for {item_name} was added or updated ; but was not applied"
    new_event = new_list[len(new_list) - 1]
    assert len(new_list) - len(previous_list) == expected_amount
    assert text_invalid in new_event.message


def assert_update_event_count_increased(virtual_server_setup, new_list, previous_list):
    item_name = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
    text_valid = f"Configuration for {item_name} was added or updated"
    text_invalid = "but was not applied"
    for i in range(len(previous_list) - 1, 0, -1):
        if text_valid in previous_list[i].message and text_invalid not in previous_list[i].message:
            assert new_list[i].count - previous_list[i].count == 1, "We expect the counter to increase"


def assert_keys_without_validation(config, expected_values):
    assert f"proxy_connect_timeout {expected_values['proxy-connect-timeout']};" in config
    assert f"proxy_read_timeout {expected_values['proxy-read-timeout']};" in config
    assert f"client_max_body_size {expected_values['client-max-body-size']};" in config
    assert f"proxy_buffers {expected_values['proxy-buffers']};" in config
    assert f"proxy_buffer_size {expected_values['proxy-buffer-size']};" in config
    assert f"proxy_max_temp_file_size {expected_values['proxy-max-temp-file-size']};" in config
    assert f"set_real_ip_from {expected_values['set-real-ip-from']};" in config
    assert f"real_ip_header {expected_values['real-ip-header']};" in config
    assert f"{expected_values['location-snippets']}" in config
    assert f"{expected_values['server-snippets']}" in config
    assert f"fail_timeout={expected_values['fail-timeout']}" in config
    assert f"proxy_send_timeout {expected_values['proxy-send-timeout']};" in config
    assert f" {expected_values['upstream-zone-size']};" in config


def assert_keys_with_validation(config, expected_values):
    # based on f"{TEST_DATA}/virtual-server-configmap-keys/configmap-validation-keys.yaml"
    assert "proxy_buffering off;" in config
    assert "real_ip_recursive on;" in config
    assert f"max_fails={expected_values['max-fails']}" in config
    assert f"keepalive {expected_values['keepalive']};" in config
    assert "listen 80 proxy_protocol;" in config


def assert_keys_with_validation_in_main_config(config, expected_values):
    # based on f"{TEST_DATA}/virtual-server-configmap-keys/configmap-validation-keys.yaml"
    assert f"variables_hash_bucket_size {expected_values['variables-hash-bucket-size']};" in config
    assert f"variables_hash_max_size {expected_values['variables-hash-max-size']};" in config


def assert_specific_keys_for_nginx_plus(config, expected_values):
    # based on f"{TEST_DATA}/virtual-server-configmap-keys/configmap-validation-keys.yaml"
    assert f"server_tokens \"{expected_values['server-tokens']}\";" in config
    assert "random two least_conn;" not in config and expected_values["lb-method"] in config
    assert "zone " in config and " 512k;" in config


def assert_specific_keys_for_nginx_oss(config, expected_values):
    # based on f"{TEST_DATA}/virtual-server-configmap-keys/configmap-validation-keys-oss.yaml"
    assert 'server_tokens "off"' in config
    assert "random two least_conn;" not in config and expected_values["lb-method"] in config
    assert "zone " not in config and " 256k;" not in config


def assert_defaults_of_keys_with_validation_for_nginx_plus(config, unexpected_values):
    assert_common_defaults_of_keys_with_validation(config, unexpected_values)
    assert "zone " in config and " 512k;" in config


def assert_defaults_of_keys_with_validation_for_nginx_oss(config, unexpected_values):
    assert_common_defaults_of_keys_with_validation(config, unexpected_values)
    assert "zone " in config and " 256k;" in config


def assert_common_defaults_of_keys_with_validation(config, unexpected_values):
    assert "proxy_buffering on;" in config
    assert "real_ip_recursive" not in config
    assert "max_fails=1" in config
    assert "keepalive" not in config
    assert "listen 80;" in config
    assert 'server_tokens "on"' in config
    assert "random two least_conn;" in config and unexpected_values["lb-method"] not in config
    assert f"proxy_send_timeout 60s;" in config


def assert_defaults_of_keys_with_validation_in_main_config(config, unexpected_values):
    assert "variables_hash_bucket_size 256;" in config
    assert "variables_hash_max_size 1024;" in config
    assert f"variables_hash_bucket_size {unexpected_values['variables-hash-bucket-size']};" not in config
    assert f"variables_hash_max_size {unexpected_values['variables-hash-max-size']};" not in config


def assert_ssl_keys(config):
    # based on f"{TEST_DATA}/virtual-server-configmap-keys/configmap-ssl-keys.yaml"
    assert "if ($schema = 'http') {" not in config
    assert "listen 443 ssl proxy_protocol;" in config
    assert "http2 on;" in config


def assert_defaults_of_ssl_keys(config):
    assert "if ($schema = 'http') {" not in config
    assert "listen 443 ssl;" in config
    assert "http2 on;" not in config


def assert_event(event_list, event_type, reason, message_substring):
    """
    Assert that an event with specific type, reason, and message substring exists.

    :param event_list: List of events
    :param event_type: 'Normal' or 'Warning'
    :param reason: Event reason
    :param message_substring: Substring expected in the event message
    """
    for event in event_list:
        if event.type == event_type and event.reason == reason and message_substring in event.message:
            return
    assert (
        False
    ), f"Expected event with type '{event_type}', reason '{reason}', and message containing '{message_substring}' not found."


@pytest.fixture(scope="function")
def clean_up(request, kube_apis, ingress_controller_prerequisites, test_namespace) -> None:
    """
    Return ConfigMap to the initial state after the test.

    :param request: internal pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_prerequisites:
    :param test_namespace: str
    :return:
    """

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )

    request.addfinalizer(fin)


@pytest.mark.vs
@pytest.mark.vs_config_map
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-configmap-keys", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVirtualServerConfigMapNoTls:
    def test_keys(
        self,
        cli_arguments,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        clean_up,
    ):
        ic_pods_amount = get_pods_amount(kube_apis.v1, ingress_controller_prerequisites.namespace)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        initial_list = get_events(kube_apis.v1, virtual_server_setup.namespace)

        print("Step 1: update ConfigMap with valid keys without validation rules")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/virtual-server-configmap-keys/configmap-no-validation-keys.yaml",
        )
        expected_values = get_configmap_fields_from_yaml(
            f"{TEST_DATA}/virtual-server-configmap-keys/configmap-no-validation-keys.yaml"
        )
        wait_before_test(1)
        step_1_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        step_1_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert_update_event_count_increased(virtual_server_setup, step_1_events, initial_list)
        assert_keys_without_validation(step_1_config, expected_values)

        print("Step 2: update ConfigMap with invalid keys without validation rules")
        cm_src = f"{TEST_DATA}/virtual-server-configmap-keys/configmap-no-validation-keys-invalid.yaml"
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_src,
        )
        expected_values = get_configmap_fields_from_yaml(
            f"{TEST_DATA}/virtual-server-configmap-keys/configmap-no-validation-keys-invalid.yaml"
        )
        wait_before_test(1)
        step_2_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        step_2_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert_not_applied_events_emitted(virtual_server_setup, step_2_events, step_1_events, ic_pods_amount)
        assert_keys_without_validation(step_2_config, expected_values)

        # to cover the OSS case, this will be changed in the future
        if cli_arguments["ic-type"] == "nginx-ingress":
            data_file = f"{TEST_DATA}/virtual-server-configmap-keys/configmap-validation-keys-oss.yaml"
            data_file_invalid = f"{TEST_DATA}/virtual-server-configmap-keys/configmap-validation-keys-invalid-oss.yaml"
        else:
            data_file = f"{TEST_DATA}/virtual-server-configmap-keys/configmap-validation-keys.yaml"
            data_file_invalid = f"{TEST_DATA}/virtual-server-configmap-keys/configmap-validation-keys-invalid.yaml"

        print("Step 3: update ConfigMap with valid keys with validation rules")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            data_file,
        )
        expected_values = get_configmap_fields_from_yaml(data_file)
        wait_before_test(1)
        step_3_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        step_3_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_update_event_count_increased(virtual_server_setup, step_3_events, step_2_events)
        assert_keys_with_validation(step_3_config, expected_values)
        # to cover the OSS case, this will be changed in the future
        if cli_arguments["ic-type"] == "nginx-ingress":
            assert_specific_keys_for_nginx_oss(step_3_config, expected_values)
        else:
            assert_specific_keys_for_nginx_plus(step_3_config, expected_values)

        print("Step 4: update ConfigMap with invalid keys")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            data_file_invalid,
        )
        expected_values = get_configmap_fields_from_yaml(data_file_invalid)
        wait_before_test(1)
        step_4_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        step_4_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_update_event_count_increased(virtual_server_setup, step_4_events, step_3_events)
        if cli_arguments["ic-type"] == "nginx-ingress":
            assert_defaults_of_keys_with_validation_for_nginx_oss(step_4_config, expected_values)
        else:
            assert_defaults_of_keys_with_validation_for_nginx_plus(step_4_config, expected_values)

    def test_keys_in_main_config(
        self,
        cli_arguments,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        clean_up,
    ):
        wait_before_test(1)
        ic_pods_amount = get_pods_amount(kube_apis.v1, ingress_controller_prerequisites.namespace)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        initial_list = get_events(kube_apis.v1, virtual_server_setup.namespace)
        data_file = f"{TEST_DATA}/virtual-server-configmap-keys/configmap-validation-keys.yaml"
        data_file_invalid = f"{TEST_DATA}/virtual-server-configmap-keys/configmap-validation-keys-invalid.yaml"
        config_path = "/etc/nginx/nginx.conf"

        print("Step 5: main config: update ConfigMap with valid keys with validation rules")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            data_file,
        )
        expected_values = get_configmap_fields_from_yaml(data_file)
        wait_before_test(1)
        step_5_config = get_file_contents(
            kube_apis.v1, config_path, ic_pod_name, ingress_controller_prerequisites.namespace
        )
        step_5_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_update_event_count_increased(virtual_server_setup, step_5_events, initial_list)
        assert_keys_with_validation_in_main_config(step_5_config, expected_values)

        print("Step 6: main config: update ConfigMap with invalid keys")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            data_file_invalid,
        )
        unexpected_values = get_configmap_fields_from_yaml(data_file_invalid)
        wait_before_test(1)
        step_6_config = get_file_contents(
            kube_apis.v1, config_path, ic_pod_name, ingress_controller_prerequisites.namespace
        )
        step_6_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_update_event_count_increased(virtual_server_setup, step_6_events, step_5_events)
        assert_defaults_of_keys_with_validation_in_main_config(step_6_config, unexpected_values)

        print("Step 7: main config: special case for hash variables")
        data_file = f"{TEST_DATA}/virtual-server-configmap-keys/configmap-global-variables.yaml"
        expected_values = get_configmap_fields_from_yaml(data_file)
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            data_file,
        )
        wait_before_test(1)
        step_7_config = get_file_contents(
            kube_apis.v1, config_path, ic_pod_name, ingress_controller_prerequisites.namespace
        )
        step_7_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_not_applied_events_emitted(virtual_server_setup, step_7_events, step_6_events, ic_pods_amount)
        assert_keys_with_validation_in_main_config(step_7_config, expected_values)


@pytest.mark.vs
@pytest.mark.vs_config_map
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-tls", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVirtualServerConfigMapWithTls:
    def test_ssl_keys(
        self,
        cli_arguments,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        clean_up,
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        initial_list = get_events(kube_apis.v1, virtual_server_setup.namespace)

        print("Step 1: update ConfigMap with valid ssl keys")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/virtual-server-configmap-keys/configmap-ssl-keys.yaml",
        )
        wait_before_test(1)
        step_1_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        step_1_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert_update_event_count_increased(virtual_server_setup, step_1_events, initial_list)
        assert_ssl_keys(step_1_config)

        print("Step 2: update ConfigMap with invalid ssl keys")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/virtual-server-configmap-keys/configmap-ssl-keys-invalid.yaml",
        )
        wait_before_test(1)
        step_2_events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        step_2_config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert_update_event_count_increased(virtual_server_setup, step_2_events, step_1_events)
        assert_defaults_of_ssl_keys(step_2_config)

    def test_configmap_events(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        clean_up,
    ):
        ingress_controller_prerequisites.namespace
        configmap_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
        configmap_namespace = ingress_controller_prerequisites.config_map["metadata"]["namespace"]

        # Step 1: Update ConfigMap with valid parameters
        print("Updating ConfigMap with valid parameters")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            configmap_namespace,
            f"{TEST_DATA}/virtual-server-configmap-keys/configmap-valid.yaml",
        )
        wait_before_test(1)

        # Get events for the ConfigMap
        events = get_events_for_object(
            kube_apis.v1,
            configmap_namespace,
            configmap_name,
        )

        assert len(events) >= 1

        # Assert that the 'updated without error' event is present
        assert_event(
            events,
            "Normal",
            "Updated",
            f"ConfigMap {configmap_namespace}/{configmap_name} updated without error",
        )

        # Step 2: Update ConfigMap with invalid parameters
        print("Updating ConfigMap with invalid parameters")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            configmap_namespace,
            f"{TEST_DATA}/virtual-server-configmap-keys/configmap-invalid.yaml",
        )
        wait_before_test(1)

        # Get events for the ConfigMap
        events = get_events_for_object(
            kube_apis.v1,
            configmap_namespace,
            configmap_name,
        )

        assert len(events) >= 1

        # Assert that the 'updated with errors' event is present
        assert_event(
            events,
            "Warning",
            "UpdatedWithError",
            f"ConfigMap {configmap_namespace}/{configmap_name} updated with errors. Ignoring invalid values",
        )

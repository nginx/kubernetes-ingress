import pytest
from settings import TEST_DATA
from suite.utils.resources_utils import (
    get_events_for_object,
    get_nginx_template_conf,
    replace_configmap_from_yaml,
    wait_before_test,
)

WAIT_TIME = 1


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


def assert_zonesync_enabled(nginx_config, resolver_valid="5s", port="12345"):
    """
    Assert that zone_sync exists in nginx.conf

    :param nginx_config: NGINX config file `nginx.config`
    """
    assert f"listen {port};" in nginx_config
    assert f"listen [::]:{port};" in nginx_config
    assert f"resolver kube-dns.kube-system.svc.cluster.local valid={resolver_valid};" in nginx_config
    assert "zone_sync;" in nginx_config
    assert "zone_sync_server" in nginx_config
    assert f"svc.cluster.local:{port} resolve;" in nginx_config


def assert_zonesync_disabled(nginx_config):
    """
    Assert that zone_sync doesn't exist in nginx.conf

    :param nginx_config: NGINX config file `nginx.config`
    """
    assert "zone_sync;" not in nginx_config
    assert "zone_sync_server" not in nginx_config


@pytest.mark.zonesync
@pytest.mark.skip_for_nginx_oss
@pytest.mark.ingresses
@pytest.mark.smoke
class TestZoneSyncLifecycle:
    def test_nic_starts_without_zonesync(
        self,
        cli_arguments,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
        ingress_controller_endpoint,
    ):
        """
        Test:
        1. NIC starts without zone-sync configured in the `nginx-config`
        2. Apply config map with zone-sync disabled - no zone sync created, no headless service created.
        """
        configmap_name = "nginx-config"

        print("Step 0: apply default nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )

        # Verify zone_sync not present in nginx.conf
        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_zonesync_disabled(nginx_config)

        print("Step 1: update the ConfigMap nginx-config - set zone-sync: false")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-disabled.yaml",
        )

        wait_before_test(WAIT_TIME)

        print("Step 2: check pod for ConfigMap updated event")
        config_events = get_events_for_object(kube_apis.v1, ingress_controller_prerequisites.namespace, configmap_name)

        assert_event(
            config_events,
            "Normal",
            "Updated",
            f"ConfigMap {ingress_controller_prerequisites.namespace}/{configmap_name} updated without error",
        )

        wait_before_test(WAIT_TIME)

        print("Step 3: verify zone_sync not present in nginx.conf")
        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_zonesync_disabled(nginx_config)

        print("Step 4: cleanup: apply default nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )

    def test_apply_minimal_default_zonesync_config(
        self,
        cli_arguments,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
        ingress_controller_endpoint,
    ):
        """
        Test:
        1. NIC starts with zone-sync not configured in the `nginx-config`.
        2. Apply the minimal `zone-sync` config.
        3. Verify zone-sync, headless service, and nginx.config zone_sync entry created.
        """
        configmap_name = "nginx-config"

        print("Step 0: apply default nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )

        # Verify zone_sync not present in nginx.conf
        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_zonesync_disabled(nginx_config)

        print("Step 1: update the ConfigMap nginx-config - set zone-sync minimal configuration")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-minimal.yaml",
        )

        wait_before_test(WAIT_TIME)

        print("Step 2: check pod for ConfigMap updated event")
        config_events = get_events_for_object(kube_apis.v1, ingress_controller_prerequisites.namespace, configmap_name)

        assert_event(
            config_events,
            "Normal",
            "Updated",
            f"ConfigMap {ingress_controller_prerequisites.namespace}/{configmap_name} updated without error",
        )

        wait_before_test(WAIT_TIME)
        print("Step 3: check zone_sync present in nginx.conf")
        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_zonesync_enabled(nginx_config)

        print("Step 4: cleanup:  apply default nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )

    def test_enable_customized_zonesync_resolver_valid(
        self,
        cli_arguments,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
        ingress_controller_endpoint,
    ):
        """
        Test:
        1. NIC starts with zone-sync not configured in the `nginx-config`
        2. Apply zone-sync config enabled, custom port, and resolver time
        3. Verify zone-sync, headless service, and nginx.config zone_sync entry created.
        """
        configmap_name = "nginx-config"

        print("Step 0: apply default nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )

        # Verify zone_sync not present in nginx.conf
        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_zonesync_disabled(nginx_config)

        print("Step 1: update the ConfigMap nginx-config - set zone-sync with custom resolver valid")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-resolver-valid.yaml",
        )

        wait_before_test(WAIT_TIME)

        print("Step 2: check pod for ConfigMap updated event")
        config_events = get_events_for_object(kube_apis.v1, ingress_controller_prerequisites.namespace, configmap_name)

        assert_event(
            config_events,
            "Normal",
            "Updated",
            f"ConfigMap {ingress_controller_prerequisites.namespace}/{configmap_name} updated without error",
        )

        wait_before_test(WAIT_TIME)

        print("Step 3: check zone_sync present in nginx.conf")
        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_zonesync_enabled(nginx_config, resolver_valid="10s")

        print("Step 4: cleanup: apply default nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )

    def test_update_zonesync_port(
        self,
        cli_arguments,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
        ingress_controller_endpoint,
    ):
        """
        Test:
        1. NIC starts with zone-sync not configured in the `nginx-config`
        2. Apply zone-sync config enabled and custom port
        3. Verify zone-sync, headless service, and nginx.config zone_sync entry created.
        4. Apply default minimal zone-sync config
        5. Verify zone-sync, headless service, and nginx.config zone_sync entry is updated.
        """
        configmap_name = "nginx-config"
        print("Step 1: apply minimal zone_sync nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-minimal.yaml",
        )

        wait_before_test(WAIT_TIME)

        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_zonesync_enabled(nginx_config, port="12345")

        wait_before_test(WAIT_TIME)

        print("Step 2: update the ConfigMap nginx-config - set zone-sync-port to custom value")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-minimal-changed-port.yaml",
        )

        wait_before_test(WAIT_TIME)

        print("Step 3: check pod for ConfigMap updated event")
        config_events = get_events_for_object(kube_apis.v1, ingress_controller_prerequisites.namespace, configmap_name)

        assert_event(
            config_events,
            "Normal",
            "Updated",
            f"ConfigMap {ingress_controller_prerequisites.namespace}/{configmap_name} updated without error",
        )

        wait_before_test(WAIT_TIME)

        print("Step 4: check if zone_syn port is updated")
        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_zonesync_enabled(nginx_config, port="34100")

        print("Step 5: cleanup:  apply default nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )

    def test_zonesync_enabled_and_disabled(
        self,
        cli_arguments,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
        ingress_controller_endpoint,
    ):
        """
        Test:
        1. NIC starts without zone-sync configured in the `nginx-config`
        2. Apply config map with zone-sync disabled - no zone sync created, no headless service created.
        """
        configmap_name = "nginx-config"

        print("Step 1: apply minimal zone_sync nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-minimal.yaml",
        )

        wait_before_test(WAIT_TIME)

        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_zonesync_enabled(nginx_config, port="12345")

        wait_before_test(WAIT_TIME)

        print("Step 2: update the ConfigMap nginx-config - set zone-sync disabled")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/configmap-with-zonesync-disabled.yaml",
        )

        print("Step 3: check pod for ConfigMap updated event")
        config_events = get_events_for_object(kube_apis.v1, ingress_controller_prerequisites.namespace, configmap_name)

        assert_event(
            config_events,
            "Normal",
            "Updated",
            f"ConfigMap {ingress_controller_prerequisites.namespace}/{configmap_name} updated without error",
        )

        print("Step 5: verify zone_sync disabled - not present in nginx.conf")
        nginx_config = get_nginx_template_conf(kube_apis.v1, ingress_controller_prerequisites.namespace)
        assert_zonesync_disabled(nginx_config)

        print("Step 6: cleanup:  apply default nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/zone-sync/default-configmap.yaml",
        )

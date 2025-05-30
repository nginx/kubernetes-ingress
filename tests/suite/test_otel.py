import pytest
from settings import TEST_DATA
from suite.utils.resources_utils import (
    extract_block,
    get_nginx_template_conf,
    replace_configmap_from_yaml,
    wait_before_test,
)

WAIT_TIME = 1
cm_default = f"{TEST_DATA}/otel/default-configmap.yaml"
cm_endpoint = f"{TEST_DATA}/otel/configmap-with-endpoint.yaml"
cm_header = f"{TEST_DATA}/otel/configmap-with-header.yaml"
cm_header_only_name = f"{TEST_DATA}/otel/configmap-with-only-header-name.yaml"
cm_header_only_value = f"{TEST_DATA}/otel/configmap-with-only-header-value.yaml"
cm_service_name = f"{TEST_DATA}/otel/configmap-with-service-name.yaml"
cm_otel_trace = f"{TEST_DATA}/otel/configmap-with-otel-trace.yaml"
cm_all = f"{TEST_DATA}/otel/configmap-with-all.yaml"
cm_all_except_endpoint = f"{TEST_DATA}/otel/configmap-with-all-except-endpoint.yaml"
otel_module = "modules/ngx_otel_module.so"
exporter = "otel.example.com:4317"
otel_exporter_header_name = "x-otel-header"
otel_exporter_header_value = "otel-header-value"
otel_service_name = "nginx-ingress-controller:nginx"
configmap_name = "nginx-config"


@pytest.mark.otel
class TestOtel:

    def test_otel_not_enabled(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
    ):
        """
        Test:
        1. NIC starts without otel configured in the `nginx-config`
        2. Ensure that the otel is not enabled in the nginx.conf
        """

        print("Step 1: apply default nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_default,
        )

        # Verify otel not present in nginx.conf
        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, print_log=False
        )
        assert "otel" not in (nginx_config)

    def test_otel_endpoint(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
    ):
        """
        Test:
        1. NIC starts with otel endpoint configured in the `nginx-config`
        2. Ensure that the `ngx_otel_module.so` is loaded in the nginx.conf
        3. Ensure that the `otel_exporter` is enabled in the nginx.conf
        4. Ensure that the `endpoint` is enabled in the `otel_exporter` block.
        5. Ensure that `otel_trace` is not configured
        """
        configmap_name = "nginx-config"

        print("Step 1: apply nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_endpoint,
        )

        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, print_log=False
        )

        print("Step 2: Ensure that the otel module is loaded")
        assert otel_module in (nginx_config)

        exporter_block = extract_block(nginx_config, "otel_exporter")

        print("Step 3: Ensure that the otel_exporter is enabled")
        assert "otel_exporter" in (exporter_block)

        print("Step 4: Ensure that the endpoint is correctly configured")
        assert f"endpoint {exporter};" in (exporter_block)

        print("Step 5: Ensure that otel_trace is not configured")
        assert "otel_trace" not in (nginx_config)

        print("Step 6: reset the configmap to default")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_default,
        )

    def test_otel_header(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
    ):
        """
        Test:
        1. NIC starts with otel endpoint configured in the `nginx-config`
        2. Ensure that the `ngx_otel_module.so` is loaded in the nginx.conf
        3. Ensure that the `otel_exporter` is enabled in the nginx.conf
        4. Ensure that the `header` is enabled in the `otel_exporter` block.
        5. Ensure that `otel_trace` is not configured
        """
        configmap_name = "nginx-config"

        print("Step 1: apply nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_header,
        )

        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, print_log=False
        )

        print("Step 2: Ensure that the otel module is loaded")
        assert otel_module in (nginx_config)

        exporter_block = extract_block(nginx_config, "otel_exporter")

        print("Step 3: Ensure that the otel_exporter is enabled")
        assert "otel_exporter" in (exporter_block)

        print("Step 4: Ensure that the header is correctly configured")
        assert f'header {otel_exporter_header_name} "{otel_exporter_header_value}";' in (exporter_block)

        print("Step 5: Ensure that otel_trace is not configured")
        assert "otel_trace" not in (nginx_config)

        print("Step 6: reset the configmap to default")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_default,
        )
        wait_before_test(WAIT_TIME)

    def test_otel_header_name_only(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
    ):
        """
        Test:
        1. NIC starts with otel endpoint configured in the `nginx-config`
        2. Ensure that the `ngx_otel_module.so` is loaded in the nginx.conf
        3. Ensure that the `otel_exporter` is enabled in the nginx.conf
        4. Ensure that the `header` is not in the `otel_exporter` block.
        5. Ensure that `otel_trace` is not configured
        """
        configmap_name = "nginx-config"

        print("Step 1: apply nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_header_only_name,
        )

        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, print_log=False
        )

        print("Step 2: Ensure that the otel module is loaded")
        assert otel_module in (nginx_config)

        exporter_block = extract_block(nginx_config, "otel_exporter")

        print("Step 3: Ensure that the otel_exporter is enabled")
        assert "otel_exporter" in (exporter_block)

        print("Step 4: Ensure that the header is not configured")
        assert f"header" not in (exporter_block)

        print("Step 5: Ensure that otel_trace is not configured")
        assert "otel_trace" not in (nginx_config)

        print("Step 6: reset the configmap to default")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_default,
        )
        wait_before_test(WAIT_TIME)

    def test_otel_header_value_only(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
    ):
        """
        Test:
        1. NIC starts with otel endpoint configured in the `nginx-config`
        2. Ensure that the `ngx_otel_module.so` is loaded in the nginx.conf
        3. Ensure that the `otel_exporter` is enabled in the nginx.conf
        4. Ensure that the `header` is not in the `otel_exporter` block.
        5. Ensure that `otel_trace` is not configured
        """
        configmap_name = "nginx-config"

        print("Step 1: apply nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_header_only_value,
        )

        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, print_log=False
        )

        print("Step 2: Ensure that the otel module is loaded")
        assert otel_module in (nginx_config)

        exporter_block = extract_block(nginx_config, "otel_exporter")

        print("Step 3: Ensure that the otel_exporter is enabled")
        assert "otel_exporter" in (exporter_block)

        print("Step 4: Ensure that the header is not configured")
        assert f"header" not in (exporter_block)

        print("Step 5: Ensure that otel_trace is not configured")
        assert "otel_trace" not in (nginx_config)

        print("Step 6: reset the configmap to default")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_default,
        )
        wait_before_test(WAIT_TIME)

    def test_otel_service_name(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
    ):
        """
        Test:
        1. NIC starts with otel endpoint configured in the `nginx-config`
        2. Ensure that the `ngx_otel_module.so` is loaded in the nginx.conf
        3. Ensure that the `otel_exporter` is enabled in the nginx.conf
        4. Ensure that the `service-name` is enabled in the nginx.conf
        5. Ensure that `otel_trace` is not configured
        """
        configmap_name = "nginx-config"

        print("Step 1: apply nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_service_name,
        )

        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, print_log=False
        )

        print("Step 2: Ensure that the otel module is loaded")
        assert otel_module in (nginx_config)

        exporter_block = extract_block(nginx_config, "otel_exporter")

        print("Step 3: Ensure that the otel_exporter is enabled")
        assert "otel_exporter" in (exporter_block)

        print("Step 4: Ensure that the service-name is correctly configured")
        assert f"otel_service_name {otel_service_name}" in (nginx_config)

        print("Step 5: Ensure that otel_trace is not configured")
        assert "otel_trace" not in (nginx_config)

        print("Step 6: reset the configmap to default")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_default,
        )
        wait_before_test(WAIT_TIME)

    def test_otel_trace(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
    ):
        """
        Test:
        1. NIC starts with otel endpoint configured in the `nginx-config`
        2. Ensure that the `ngx_otel_module.so` is loaded in the nginx.conf
        3. Ensure that the `otel_exporter` is enabled in the nginx.conf
        4. Ensure that `otel_trace` is configured in the nginx.conf
        """
        configmap_name = "nginx-config"

        print("Step 1: apply nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_otel_trace,
        )

        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, print_log=False
        )

        print("Step 2: Ensure that the otel module is loaded")
        assert otel_module in (nginx_config)

        exporter_block = extract_block(nginx_config, "otel_exporter")

        print("Step 3: Ensure that the otel_exporter is enabled")
        assert "otel_exporter" in (exporter_block)

        print("Step 4: Ensure that otel_trace is configured")
        assert "otel_trace on;" in (nginx_config)

        print("Step 5: reset the configmap to default")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_default,
        )
        wait_before_test(WAIT_TIME)

    def test_otel_all(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
    ):
        """
        Test:
        1. NIC starts with otel endpoint configured in the `nginx-config`
        2. Ensure that the `ngx_otel_module.so` is loaded in the nginx.conf
        3. Ensure that the `otel_exporter` is enabled in the nginx.conf
        4. Ensure that the `endpoint` is enabled in the `otel_exporter` block.
        5. Ensure that the `header` is enabled in the `otel_exporter` block.
        6. Ensure that the `service-name` is enabled in the nginx.conf
        7. Ensure that `otel_trace` is configured in the nginx.conf
        """
        configmap_name = "nginx-config"

        print("Step 1: apply nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_all,
        )

        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, print_log=False
        )

        print("Step 2: Ensure that the otel module is loaded")
        assert otel_module in (nginx_config)

        exporter_block = extract_block(nginx_config, "otel_exporter")

        print("Step 3: Ensure that the otel_exporter is enabled")
        assert "otel_exporter" in (exporter_block)

        print("Step 4: Ensure that the endpoint is correctly configured")
        assert f"endpoint {exporter};" in (exporter_block)

        print("Step 5: Ensure that the header is correctly configured")
        assert f'header {otel_exporter_header_name} "{otel_exporter_header_value}";' in (exporter_block)

        print("Step 6: Ensure that the service-name is correctly configured")
        assert f"otel_service_name {otel_service_name}" in (nginx_config)

        print("Step 7: Ensure that otel_trace is configured")
        assert "otel_trace on;" in (nginx_config)

        print("Step 8: reset the configmap to default")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_default,
        )
        wait_before_test(WAIT_TIME)

    def test_otel_all_except_endpoint(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
    ):
        """
        Test:
        1. NIC starts with all otel configuration except endpoint configured in the `nginx-config`
        2. Ensure that the `ngx_otel_module.so` is not in the nginx.conf
        3. Ensure that the `otel_exporter` is not in the nginx.conf
        4. Ensure that the `service-name` is not in the nginx.conf
        5. Ensure that `otel_trace` is not in the nginx.conf
        """
        configmap_name = "nginx-config"

        print("Step 1: apply nginx-config map")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_all_except_endpoint,
        )

        wait_before_test(WAIT_TIME)
        nginx_config = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, print_log=False
        )

        print("Step 2: Ensure that the otel module is not loaded")
        assert otel_module not in (nginx_config)

        print("Step 3: Ensure that the otel_exporter is not enabled")
        assert "otel_exporter" not in (nginx_config)

        print("Step 4: Ensure that the service-name is not correctly configured")
        assert f"otel_service_name {otel_service_name}" not in (nginx_config)

        print("Step 5: Ensure that otel_trace is not configured")
        assert "otel_trace on;" not in (nginx_config)

        print("Step 6: reset the configmap to default")
        replace_configmap_from_yaml(
            kube_apis.v1,
            configmap_name,
            ingress_controller_prerequisites.namespace,
            cm_default,
        )
        wait_before_test(WAIT_TIME)

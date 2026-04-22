import copy

import pytest
import yaml
from settings import TEST_DATA
from suite.utils.ap_resources_utils import (
    create_ap_logconf_from_yaml,
    create_ap_policy_from_yaml,
    delete_ap_logconf,
    delete_ap_policy,
)
from suite.utils.custom_resources_utils import (
    create_gc_from_yaml,
    create_ts_from_yaml,
    delete_gc,
    delete_ts,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_ingress,
    delete_items_from_yaml,
    delete_secret,
    ensure_connection_to_public_endpoint,
    get_config_version,
    get_first_pod_name,
    get_last_reload_status,
    get_pods_amount,
    get_total_ingresses,
    get_total_vs,
    get_total_vsr,
    scale_deployment,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route,
    create_virtual_server,
    delete_v_s_route,
    delete_virtual_server,
)

GC_YAML = f"{TEST_DATA}/transport-server-tcp-load-balance/standard/global-configuration.yaml"
TCP_SVC_YAML = f"{TEST_DATA}/transport-server-tcp-load-balance/standard/service_deployment.yaml"
TS_YAML = f"{TEST_DATA}/transport-server-tcp-load-balance/standard/transport-server.yaml"
INGRESS_YAML = f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml"
SMOKE_SECRET_YAML = f"{TEST_DATA}/smoke/smoke-secret.yaml"
VS_YAML = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
VSR_YAML = f"{TEST_DATA}/startup/virtual-server-routes/route.yaml"
VSR_VS_YAML = f"{TEST_DATA}/startup/virtual-server-routes/virtual-server.yaml"
AP_SECRET_YAML = f"{TEST_DATA}/appprotect/appprotect-secret.yaml"
AP_LOGCONF_YAML = f"{TEST_DATA}/appprotect/logconf.yaml"
AP_POLICY_YAML = f"{TEST_DATA}/appprotect/dataguard-alarm.yaml"
AP_INGRESS_YAML = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"


@pytest.fixture(scope="class")
def mixed_resources_setup(
    request,
    kube_apis,
    ingress_controller_endpoint,
    ingress_controller_prerequisites,
    crd_ingress_controller,
    test_namespace,
) -> None:
    """
    Deploy a mix of resources: Ingresses (HTTP + HTTPS), VirtualServers,
    VirtualServerRoutes, TransportServer, and GlobalConfiguration.
    """
    # Backend app
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    # TLS secret for HTTPS ingresses
    secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, SMOKE_SECRET_YAML)

    # TCP backend for TransportServer
    create_items_from_yaml(kube_apis, TCP_SVC_YAML, test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    # GlobalConfiguration for TS listeners
    gc_resource = create_gc_from_yaml(kube_apis.custom_objects, GC_YAML, ingress_controller_prerequisites.namespace)

    # --- Create Ingresses (5 HTTP + 5 HTTPS) ---
    created_ingresses = []
    for i in range(5):
        with open(INGRESS_YAML) as f:
            doc = yaml.safe_load(f)
            doc["metadata"]["name"] = f"http-ingress-{i}"
            doc["spec"]["rules"][0]["host"] = f"http-{i}.example.com"
            # Remove TLS for HTTP ingresses
            doc["spec"].pop("tls", None)
            create_ingress(kube_apis.networking_v1, test_namespace, doc)
            created_ingresses.append(doc["metadata"]["name"])

    for i in range(5):
        with open(INGRESS_YAML) as f:
            doc = yaml.safe_load(f)
            doc["metadata"]["name"] = f"https-ingress-{i}"
            doc["spec"]["rules"][0]["host"] = f"https-{i}.example.com"
            doc["spec"]["tls"] = [{"hosts": [f"https-{i}.example.com"], "secretName": "tls-secret"}]
            create_ingress(kube_apis.networking_v1, test_namespace, doc)
            created_ingresses.append(doc["metadata"]["name"])

    # --- Create VirtualServers (5) ---
    created_vs = []
    for i in range(5):
        with open(VS_YAML) as f:
            doc = yaml.safe_load(f)
            doc["metadata"]["name"] = f"vs-{i}"
            doc["spec"]["host"] = f"vs-{i}.example.com"
            created_vs.append(create_virtual_server(kube_apis.custom_objects, doc, test_namespace))

    # --- Create VirtualServerRoutes (3) with parent VS ---
    created_vsr = []
    with open(VSR_YAML) as f:
        vsr_template = yaml.safe_load(f)

    for i in range(3):
        vsr_doc = copy.deepcopy(vsr_template)
        vsr_doc["metadata"]["name"] = f"vsr-{i}"
        vsr_doc["spec"]["host"] = "vsr-parent.example.com"
        vsr_doc["spec"]["subroutes"][0]["path"] = f"/route-{i}"
        create_v_s_route(kube_apis.custom_objects, vsr_doc, test_namespace)
        created_vsr.append(vsr_doc["metadata"]["name"])

    # Parent VS for the VSRs
    with open(VSR_VS_YAML) as f:
        vs_doc = yaml.safe_load(f)
    vs_doc["metadata"]["name"] = "vsr-parent"
    vs_doc["spec"]["host"] = "vsr-parent.example.com"
    vs_doc["spec"]["routes"] = [{"path": f"/route-{i}", "route": f"vsr-{i}"} for i in range(3)]
    create_virtual_server(kube_apis.custom_objects, vs_doc, test_namespace)
    created_vs.append("vsr-parent")

    # --- Create TransportServer (1 TCP) ---
    ts_resource = create_ts_from_yaml(kube_apis.custom_objects, TS_YAML, test_namespace)

    wait_before_test()
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Cleaning up config-safety startup test resources")
            for name in created_ingresses:
                delete_ingress(kube_apis.networking_v1, name, test_namespace)
            for name in created_vs:
                delete_virtual_server(kube_apis.custom_objects, name, test_namespace)
            for name in created_vsr:
                delete_v_s_route(kube_apis.custom_objects, name, test_namespace)
            delete_ts(kube_apis.custom_objects, ts_resource, test_namespace)
            delete_gc(kube_apis.custom_objects, gc_resource, ingress_controller_prerequisites.namespace)
            delete_items_from_yaml(kube_apis, TCP_SVC_YAML, test_namespace)
            delete_secret(kube_apis.v1, secret_name, test_namespace)
            delete_common_app(kube_apis, "simple", test_namespace)

    request.addfinalizer(fin)


@pytest.mark.vs
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        {
            "type": "complete",
            "extra_args": [
                "-enable-custom-resources",
                "-enable-config-safety",
                "-enable-snippets",
                "-enable-prometheus-metrics",
                "-global-configuration=nginx-ingress/nginx-configuration",
            ],
        },
    ],
    indirect=True,
)
class TestConfigSafetyStartupMixed:
    """Verify configVersion == 1 after startup with config-safety enabled and mixed resources."""

    def test_startup_config_version_is_1(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ingress_controller_endpoint,
        mixed_resources_setup,
    ):
        """
        With config-safety enabled and a mix of Ingress, VS, VSR, TS resources,
        restart the IC pod and verify:
        - configVersion == 1 (exactly one reload, no per-resource nginx -t during startup)
        - All resources are registered
        - Last reload was successful
        """
        # Scale to 0 and wait for pod to be gone
        scale_deployment(
            kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ingress_controller_prerequisites.namespace, 0
        )
        while get_pods_amount(kube_apis.v1, ingress_controller_prerequisites.namespace) != 0:
            print("Number of replicas not 0, retrying...")
            wait_before_test()

        # Scale back to 1 — cold start with all resources pre-existing
        assert (
            scale_deployment(
                kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ingress_controller_prerequisites.namespace, 1
            )
            is None
        )

        # Wait for metrics to be available (pod must be ready)
        wait_before_test(10)
        metrics_url = (
            f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
        )

        # Verify configVersion == 1
        assert (
            get_config_version(
                kube_apis.v1,
                get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace),
                ingress_controller_prerequisites.namespace,
            )
            == 1
        )

        # Verify all resources registered and reload was successful
        assert get_last_reload_status(metrics_url, "nginx") == "1", "Last reload was not successful"
        assert get_total_ingresses(metrics_url, "nginx") == "10", "Expected 10 Ingresses (5 HTTP + 5 HTTPS)"
        assert get_total_vs(metrics_url, "nginx") == "6", "Expected 6 VirtualServers (5 standalone + 1 VSR parent)"
        assert get_total_vsr(metrics_url, "nginx") == "3", "Expected 3 VirtualServerRoutes"


##############################################################################################################


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect
@pytest.mark.appprotect_batch
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
    [
        {
            "extra_args": [
                "-enable-custom-resources",
                "-enable-config-safety",
                "-enable-app-protect",
                "-enable-prometheus-metrics",
            ],
        },
    ],
    indirect=True,
)
class TestConfigSafetyStartupAppProtect:
    """Verify configVersion == 1 after startup with config-safety + AppProtect enabled."""

    @pytest.fixture(scope="class")
    def app_protect_startup_setup(
        self,
        request,
        kube_apis,
        crd_ingress_controller_with_ap,
        test_namespace,
    ) -> None:
        """Deploy AP policy, logconf, secret, backend, and N AP-annotated Ingresses."""
        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

        create_items_from_yaml(kube_apis, AP_SECRET_YAML, test_namespace)

        log_name = create_ap_logconf_from_yaml(kube_apis.custom_objects, AP_LOGCONF_YAML, test_namespace)

        pol_name = create_ap_policy_from_yaml(kube_apis.custom_objects, AP_POLICY_YAML, test_namespace)

        # Create 10 AP-annotated Ingresses
        created_ingresses = []
        for i in range(10):
            with open(AP_INGRESS_YAML) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"ap-ingress-{i}"
                doc["spec"]["rules"][0]["host"] = f"ap-{i}.example.com"
                doc["spec"]["tls"][0]["hosts"] = [f"ap-{i}.example.com"]
                doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-policy"] = f"{test_namespace}/{pol_name}"
                doc["metadata"]["annotations"][
                    "appprotect.f5.com/app-protect-security-log"
                ] = f"{test_namespace}/{log_name}"
                doc["metadata"]["annotations"][
                    "appprotect.f5.com/app-protect-security-log-destination"
                ] = "syslog:server=127.0.0.1:514"
                create_ingress(kube_apis.networking_v1, test_namespace, doc)
                created_ingresses.append(doc["metadata"]["name"])

        wait_before_test()

        def fin():
            if request.config.getoption("--skip-fixture-teardown") == "no":
                print("Cleaning up AP config-safety startup test resources")
                for name in created_ingresses:
                    delete_ingress(kube_apis.networking_v1, name, test_namespace)
                delete_ap_policy(kube_apis.custom_objects, pol_name, test_namespace)
                delete_ap_logconf(kube_apis.custom_objects, log_name, test_namespace)
                delete_items_from_yaml(kube_apis, AP_SECRET_YAML, test_namespace)
                delete_common_app(kube_apis, "simple", test_namespace)

        request.addfinalizer(fin)

    def test_ap_startup_config_version_is_1(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_ap,
        ingress_controller_endpoint,
        app_protect_startup_setup,
    ):
        """
        With config-safety + AppProtect enabled and 10 AP Ingresses,
        restart the IC pod and verify configVersion == 1.
        """
        scale_deployment(
            kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ingress_controller_prerequisites.namespace, 0
        )
        while get_pods_amount(kube_apis.v1, ingress_controller_prerequisites.namespace) != 0:
            print("Number of replicas not 0, retrying...")
            wait_before_test()

        assert (
            scale_deployment(
                kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ingress_controller_prerequisites.namespace, 1
            )
            is None
        )

        # AP needs extra time to initialize
        wait_before_test(30)
        metrics_url = (
            f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
        )

        assert (
            get_config_version(
                kube_apis.v1,
                get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace),
                ingress_controller_prerequisites.namespace,
            )
            == 1
        )

        assert get_last_reload_status(metrics_url, "nginx") == "1", "Last reload was not successful"
        assert get_total_ingresses(metrics_url, "nginx") == "10", "Expected 10 AP Ingresses"

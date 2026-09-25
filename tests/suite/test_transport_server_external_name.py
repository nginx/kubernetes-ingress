import pytest
from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.custom_assertions import assert_event
from suite.utils.resources_utils import (
    create_items_from_yaml,
    create_namespace_with_name_from_yaml,
    create_service_from_yaml,
    delete_namespace,
    delete_service,
    get_e2e_run_selector,
    get_events,
    get_file_contents,
    get_first_pod_name,
    replace_configmap_from_yaml,
    wait_before_test,
)


class ExternalNameSetup:
    """Encapsulate ExternalName example details.

    Attributes:
        ic_pod_name:
        external_host: external service host
    """

    def __init__(self, ic_pod_name, external_svc, external_host):
        self.ic_pod_name = ic_pod_name
        self.external_svc = external_svc
        self.external_host = external_host


@pytest.fixture(scope="class")
def ts_externalname_setup(
    request, kube_apis, ingress_controller_prerequisites, transport_server_setup
) -> ExternalNameSetup:
    print(
        "------------------------- Deploy external namespace with backend, configmap and service -----------------------------------"
    )
    external_app_src = f"{TEST_DATA}/transport-server-externalname/external-svc-deployment.yaml"
    external_ns = create_namespace_with_name_from_yaml(kube_apis.v1, "external-ns", f"{TEST_DATA}/common/ns.yaml")
    create_items_from_yaml(kube_apis, external_app_src, external_ns)

    print("------------------------- ExternalName service Setup -----------------------------------")
    config_map_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
    replace_configmap_from_yaml(
        kube_apis.v1,
        config_map_name,
        ingress_controller_prerequisites.namespace,
        f"{TEST_DATA}/transport-server-externalname/nginx-config.yaml",
    )
    external_svc_src = f"{TEST_DATA}/transport-server-externalname/externalname-svc.yaml"
    external_host = f"core-dns-external-backend-svc.external-ns.svc.cluster.local"

    external_svc = create_service_from_yaml(kube_apis.v1, transport_server_setup.namespace, external_svc_src)
    wait_before_test()
    ic_pod_name = get_first_pod_name(
        kube_apis.v1,
        ingress_controller_prerequisites.namespace,
        get_e2e_run_selector(ingress_controller_prerequisites.e2e_run_id),
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up ExternalName Setup:")
            delete_service(kube_apis.v1, external_svc, transport_server_setup.namespace)
            delete_namespace(kube_apis.v1, external_ns)
            replace_configmap_from_yaml(
                kube_apis.v1,
                config_map_name,
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )

    request.addfinalizer(fin)

    return ExternalNameSetup(ic_pod_name, external_svc, external_host)


@pytest.mark.ts
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-global-configuration=nginx-ingress/nginx-configuration",
                    "-enable-leader-election=false",
                ],
            },
            {"example": "transport-server-externalname", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestTransportServerStatus:
    def test_template_config(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        transport_server_setup,
        ts_externalname_setup,
    ):
        wait_before_test()
        nginx_file_path = f"/etc/nginx/nginx.conf"
        nginx_conf = ""
        nginx_conf = get_file_contents(
            kube_apis.v1, nginx_file_path, ts_externalname_setup.ic_pod_name, ingress_controller_prerequisites.namespace
        )
        resolver_count = nginx_conf.count("resolver kube-dns.kube-system.svc.cluster.local;")

        ts_file_path = (
            f"/etc/nginx/stream-conf.d/ts_{transport_server_setup.namespace}_{transport_server_setup.name}.conf"
        )
        ts_conf = ""
        retry = 0
        while f"{ts_externalname_setup.external_host}:5353" not in ts_conf and retry < 5:
            wait_before_test()
            ts_conf = get_file_contents(
                kube_apis.v1,
                ts_file_path,
                ts_externalname_setup.ic_pod_name,
                ingress_controller_prerequisites.namespace,
            )
            retry = retry + 1

        assert resolver_count == 2  # one for http and other for stream context
        assert (
            f"server {ts_externalname_setup.external_host}:5353 max_fails=1 fail_timeout=10s max_conns=0 resolve;"
            in ts_conf
        )

    @pytest.mark.flaky(max_runs=3)
    def test_event_warning(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        transport_server_setup,
        ts_externalname_setup,
    ):
        text = f"{transport_server_setup.namespace}/{transport_server_setup.name}"
        event_text = f"Configuration for {text} was added or updated with warning(s): Type ExternalName service {ts_externalname_setup.external_svc} in upstream dns-app will be ignored. To use ExternalName services, a resolver must be configured in the ConfigMap"
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{DEPLOYMENTS}/common/nginx-config.yaml",
        )
        wait_before_test(5)
        events = get_events(kube_apis.v1, transport_server_setup.namespace)
        assert_event(event_text, events)

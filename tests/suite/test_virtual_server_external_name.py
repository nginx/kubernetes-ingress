import pytest
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    assert_event_and_count,
    assert_event_and_get_count,
    assert_event_with_full_equality_and_count,
    wait_and_assert_status_code,
    wait_for_event_count_increases,
)
from suite.utils.resources_utils import (
    create_deployment_with_name,
    create_namespace_with_name_from_yaml,
    create_service_from_yaml,
    create_service_with_name,
    delete_namespace,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    get_events,
    get_first_pod_name,
    read_service,
    replace_configmap,
    replace_configmap_from_yaml,
    replace_service,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import get_vs_nginx_template_conf


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
def vs_externalname_setup(
    request, kube_apis, ingress_controller_prerequisites, virtual_server_setup
) -> ExternalNameSetup:
    print("------------------------- Deploy External-Backend -----------------------------------")
    external_ns = create_namespace_with_name_from_yaml(kube_apis.v1, "external-ns", f"{TEST_DATA}/common/ns.yaml")
    external_svc_name = create_service_with_name(kube_apis.v1, external_ns, "external-backend-svc")
    create_deployment_with_name(kube_apis.apps_v1_api, external_ns, "external-backend")
    print("------------------------- Prepare ExternalName Setup -----------------------------------")
    external_svc_src = f"{TEST_DATA}/virtual-server-externalname/externalname-svc.yaml"
    external_svc_host = f"{external_svc_name}.{external_ns}.svc.cluster.local"
    config_map_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
    replace_configmap_from_yaml(
        kube_apis.v1,
        config_map_name,
        ingress_controller_prerequisites.namespace,
        f"{TEST_DATA}/virtual-server-externalname/nginx-config.yaml",
    )
    external_svc = create_service_from_yaml(kube_apis.v1, virtual_server_setup.namespace, external_svc_src)
    wait_before_test(2)
    ensure_connection_to_public_endpoint(
        virtual_server_setup.public_endpoint.public_ip,
        virtual_server_setup.public_endpoint.port,
        virtual_server_setup.public_endpoint.port_ssl,
    )
    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
    ensure_response_from_backend(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up ExternalName Setup:")
            delete_namespace(kube_apis.v1, external_ns)
            replace_configmap(
                kube_apis.v1,
                config_map_name,
                ingress_controller_prerequisites.namespace,
                ingress_controller_prerequisites.config_map,
            )

    request.addfinalizer(fin)

    return ExternalNameSetup(ic_pod_name, external_svc, external_svc_host)


@pytest.mark.vs
@pytest.mark.vs_externalname
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources", "-log-level=debug"]},
            {"example": "virtual-server-externalname", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVSWithExternalNameService:
    def test_response(self, kube_apis, crd_ingress_controller, virtual_server_setup, vs_externalname_setup):
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)

    def test_template_config(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        vs_externalname_setup,
    ):
        result_conf = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            vs_externalname_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        line = f"zone vs_{virtual_server_setup.namespace}_{virtual_server_setup.vs_name}_backend1 512k;"
        assert line in result_conf
        assert "random two least_conn;" in result_conf
        assert (
            f"server {vs_externalname_setup.external_host}:80 max_fails=1 fail_timeout=10s max_conns=0 resolve;"
            in result_conf
        )

    def test_events_flows(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        vs_externalname_setup,
    ):
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"Configuration for {text} was added or updated"
        wait_before_test(10)
        events_vs = get_events(kube_apis.v1, virtual_server_setup.namespace)
        initial_count = assert_event_and_get_count(vs_event_text, events_vs)

        print("Step 1: Update external host in externalName service")
        external_svc = read_service(kube_apis.v1, vs_externalname_setup.external_svc, virtual_server_setup.namespace)
        external_svc.spec.external_name = "demo.nginx.com"
        replace_service(kube_apis.v1, vs_externalname_setup.external_svc, virtual_server_setup.namespace, external_svc)
        wait_before_test(10)

        wait_for_event_count_increases(kube_apis, vs_event_text, initial_count, virtual_server_setup.namespace)
        events_step_1 = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_event_and_count(vs_event_text, initial_count + 1, events_step_1)

        print("Step 2: Remove resolver from ConfigMap to trigger an error")
        config_map_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
        vs_event_warning_text = f"Configuration for {text} was added or updated ; with warning(s):"
        replace_configmap(
            kube_apis.v1,
            config_map_name,
            ingress_controller_prerequisites.namespace,
            ingress_controller_prerequisites.config_map,
        )
        wait_before_test(10)

        events_step_2 = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_event_and_count(vs_event_warning_text, 1, events_step_2)
        assert_event_with_full_equality_and_count(vs_event_text, initial_count + 1, events_step_2)

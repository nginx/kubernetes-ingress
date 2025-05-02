import pytest
from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.custom_assertions import (
    assert_event_starts_with_text_and_contains_errors,
    assert_grpc_entries_exist,
    assert_proxy_entries_do_not_exist,
    assert_proxy_entries_exist,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_secret_from_yaml,
    delete_common_app,
    get_events,
    get_first_pod_name,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import get_vs_nginx_template_conf, patch_v_s_route_from_yaml


@pytest.fixture(scope="function")
def backend_setup(request, kube_apis, ingress_controller_prerequisites, test_namespace):
    """
    Replace the ConfigMap and deploy the secret.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param test_namespace:
    """
    app_name = request.param.get("app_type")
    try:
        print("------------------------- Replace ConfigMap with HTTP2 -------------------------")
        cm_source = f"{TEST_DATA}/virtual-server-route-grpc/nginx-config.yaml"
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_source,
        )
        print("------------------------- Deploy App -----------------------------")
        app_name = request.param.get("app_type")
        create_example_app(kube_apis, app_name, test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    except Exception:
        print("Failed to complete setup, cleaning up..")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{DEPLOYMENTS}/common/nginx-config.yaml",
        )
        delete_common_app(kube_apis, app_name, test_namespace)
        pytest.fail(f"VSR GRPC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )
            delete_common_app(kube_apis, app_name, test_namespace)

    request.addfinalizer(fin)


@pytest.mark.vsr
@pytest.mark.vsr_grpc
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [({"type": "complete", "extra_args": [f"-enable-custom-resources"]}, {"example": "virtual-server-route-grpc"})],
    indirect=True,
)
class TestVirtualServerRouteGrpc:
    def patch_valid_vs_route(self, kube_apis, v_s_route_setup) -> None:
        """
        Function to revert vs deployment to valid state
        """
        patch_src = f"{TEST_DATA}/virtual-server-route-grpc/route-multiple.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            patch_src,
            v_s_route_setup.route_m.namespace,
        )

    def deploy_tls_secrets(self, kube_apis, v_s_route_setup) -> None:
        """
        Function to deploy secrets to the vs route namespaces.
        """
        print("------------------------- Deploy Secrets -----------------------------")
        src_sec_yaml = f"{TEST_DATA}/virtual-server-route-grpc/tls-secret.yaml"
        create_secret_from_yaml(kube_apis.v1, v_s_route_setup.route_m.namespace, src_sec_yaml)
        create_secret_from_yaml(kube_apis.v1, v_s_route_setup.route_s.namespace, src_sec_yaml)
        wait_before_test(1)

    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_config_after_setup(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, v_s_route_setup
    ):
        self.deploy_tls_secrets(kube_apis, v_s_route_setup)
        print("\nStep 1: assert config")
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert_proxy_entries_do_not_exist(config)
        assert_grpc_entries_exist(config)

    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_config_after_enable_tls(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, v_s_route_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            f"{TEST_DATA}/virtual-server-route-grpc/route-updated.yaml",
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert "grpc_pass grpcs://" in config

    @pytest.mark.flaky(max_runs=3)
    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs"}], indirect=True)
    def test_validation_flow(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, v_s_route_setup
    ):
        print("\nTest 1: Wrong type")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            f"{TEST_DATA}/virtual-server-route-grpc/route-invalid-type.yaml",
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        text_m = f"{v_s_route_setup.route_m.namespace}/{v_s_route_setup.route_m.name}"
        vsr_m_event_text = f"VirtualServerRoute {text_m} was rejected with error:"
        invalid_fields_m = ["spec.upstreams[0].type", "spec.upstreams[1].type"]
        vsr_m_events = get_events(kube_apis.v1, v_s_route_setup.route_m.namespace)
        assert_event_starts_with_text_and_contains_errors(vsr_m_event_text, vsr_m_events, invalid_fields_m)

        self.patch_valid_vs_route(kube_apis, v_s_route_setup)
        wait_before_test()

    @pytest.mark.parametrize("backend_setup", [{"app_type": "grpc-vs-mixed"}], indirect=True)
    def test_mixed_config(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, backend_setup, v_s_route_setup
    ):
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            f"{TEST_DATA}/virtual-server-route-grpc/route-multiple-mixed.yaml",
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            v_s_route_setup.namespace,
            v_s_route_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert_proxy_entries_exist(config)
        assert_grpc_entries_exist(config)

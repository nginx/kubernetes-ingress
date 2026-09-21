import pytest
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    assert_valid_vs,
    assert_vs_status,
    assert_vsr_status,
    wait_and_assert_status_code,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_namespace_with_name_from_yaml,
    delete_common_app,
    delete_namespace,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route_from_yaml,
    create_virtual_server_from_yaml,
    delete_v_s_route,
    delete_virtual_server,
)


class ForeignNamespaceSetup:
    def __init__(self, namespace):
        self.namespace = namespace


@pytest.mark.vsr
@pytest.mark.vsr_hostless
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        {
            "type": "complete",
            "extra_args": [f"-enable-custom-resources", f"-enable-leader-election=false"],
        }
    ],
    indirect=True,
)
class TestVirtualServerRouteHostless:

    @pytest.fixture(scope="class")
    def simple_app_setup(self, request, kube_apis, foreign_namespace_setup):
        create_example_app(kube_apis, "simple", foreign_namespace_setup.namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, foreign_namespace_setup.namespace)

        def fin():
            if request.config.getoption("--skip-fixture-teardown") == "no":
                delete_common_app(kube_apis, "simple", foreign_namespace_setup.namespace)

        request.addfinalizer(fin)

    @pytest.fixture(scope="class")
    def foreign_namespace_setup(self, request, kube_apis):
        namespace = create_namespace_with_name_from_yaml(kube_apis.v1, "foreign-vs", f"{TEST_DATA}/common/ns.yaml")

        def fin():
            if request.config.getoption("--skip-fixture-teardown") == "no":
                delete_namespace(kube_apis.v1, namespace)

        request.addfinalizer(fin)
        return ForeignNamespaceSetup(namespace)

    @pytest.fixture(scope="function")
    def vs_vsr_cleanup(self, request, kube_apis, test_namespace, foreign_namespace_setup):
        def fin():
            namespaces = (test_namespace, foreign_namespace_setup.namespace)
            for namespace in namespaces:
                vses = kube_apis.custom_objects.list_namespaced_custom_object(
                    "k8s.nginx.org", "v1", namespace, "virtualservers"
                )["items"]
                for vs in vses:
                    delete_virtual_server(kube_apis.custom_objects, vs["metadata"]["name"], namespace)

                vsrs = kube_apis.custom_objects.list_namespaced_custom_object(
                    "k8s.nginx.org", "v1", namespace, "virtualserverroutes"
                )["items"]
                for vsr in vsrs:
                    delete_v_s_route(kube_apis.custom_objects, vsr["metadata"]["name"], namespace)

        request.addfinalizer(fin)

    def test_status_valid_two_vs_route(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
        foreign_namespace_setup,
        simple_app_setup,
        vs_vsr_cleanup,
    ):
        vsr_name = create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/route-single.yaml",
            foreign_namespace_setup.namespace,
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects, f"{TEST_DATA}/virtual-server-route-hostless/virtual-server.yaml", test_namespace
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server-2.yaml",
            foreign_namespace_setup.namespace,
        )

        assert_valid_vs(kube_apis, test_namespace, "virtual-server-route")
        assert_valid_vs(kube_apis, foreign_namespace_setup.namespace, "virtual-server-route-2")
        assert_vsr_status(
            kube_apis,
            foreign_namespace_setup.namespace,
            vsr_name,
            "Valid",
            expected_reason="AddedOrUpdated",
            **{"referencedBy": (f"foreign-vs/virtual-server-route-2, " f"{test_namespace}/virtual-server-route")},
        )

        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"
        wait_and_assert_status_code(200, req_url, "virtual-server-route.example.com")
        wait_and_assert_status_code(200, req_url, "virtual-server-route-2.example.com")

    def test_status_valid_two_vs_route_selector(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
        foreign_namespace_setup,
        simple_app_setup,
        vs_vsr_cleanup,
    ):
        vsr_name = create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/route-single.yaml",
            foreign_namespace_setup.namespace,
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server-selector.yaml",
            test_namespace,
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server-selector-2.yaml",
            foreign_namespace_setup.namespace,
        )

        assert_valid_vs(kube_apis, test_namespace, "virtual-server-route")
        assert_valid_vs(kube_apis, foreign_namespace_setup.namespace, "virtual-server-route-2")
        assert_vsr_status(
            kube_apis,
            foreign_namespace_setup.namespace,
            vsr_name,
            "Valid",
            expected_reason="AddedOrUpdated",
            **{"referencedBy": (f"foreign-vs/virtual-server-route-2, " f"{test_namespace}/virtual-server-route")},
        )

        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"
        wait_and_assert_status_code(200, req_url, "virtual-server-route.example.com")
        wait_and_assert_status_code(200, req_url, "virtual-server-route-2.example.com")

    def test_status_referenced_by_add_vs(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        foreign_namespace_setup,
        simple_app_setup,
        vs_vsr_cleanup,
    ):
        vsr_name = create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/route-single.yaml",
            foreign_namespace_setup.namespace,
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server.yaml",
            test_namespace,
        )
        assert_valid_vs(kube_apis, test_namespace, "virtual-server-route")
        assert_vsr_status(
            kube_apis,
            foreign_namespace_setup.namespace,
            vsr_name,
            "Valid",
            expected_reason="AddedOrUpdated",
            **{"referencedBy": f"{test_namespace}/virtual-server-route"},
        )

        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server-2.yaml",
            foreign_namespace_setup.namespace,
        )
        assert_valid_vs(kube_apis, foreign_namespace_setup.namespace, "virtual-server-route-2")
        assert_vsr_status(
            kube_apis,
            foreign_namespace_setup.namespace,
            vsr_name,
            "Valid",
            expected_reason="AddedOrUpdated",
            **{"referencedBy": (f"foreign-vs/virtual-server-route-2, " f"{test_namespace}/virtual-server-route")},
        )

    def test_status_remove_vs(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        foreign_namespace_setup,
        simple_app_setup,
        vs_vsr_cleanup,
    ):
        vsr_name = create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/route-single.yaml",
            foreign_namespace_setup.namespace,
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server.yaml",
            test_namespace,
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server-2.yaml",
            foreign_namespace_setup.namespace,
        )
        assert_valid_vs(kube_apis, test_namespace, "virtual-server-route")
        assert_valid_vs(kube_apis, foreign_namespace_setup.namespace, "virtual-server-route-2")
        assert_vsr_status(
            kube_apis,
            foreign_namespace_setup.namespace,
            vsr_name,
            "Valid",
            expected_reason="AddedOrUpdated",
            **{"referencedBy": (f"foreign-vs/virtual-server-route-2, " f"{test_namespace}/virtual-server-route")},
        )

        delete_virtual_server(kube_apis.custom_objects, "virtual-server-route-2", foreign_namespace_setup.namespace)
        assert_valid_vs(kube_apis, test_namespace, "virtual-server-route")
        assert_vsr_status(
            kube_apis,
            foreign_namespace_setup.namespace,
            vsr_name,
            "Valid",
            expected_reason="AddedOrUpdated",
            **{"referencedBy": f"{test_namespace}/virtual-server-route"},
        )

    def test_status_remove_vs_route_selector(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        foreign_namespace_setup,
        simple_app_setup,
        vs_vsr_cleanup,
    ):
        vsr_name = create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/route-single.yaml",
            foreign_namespace_setup.namespace,
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server-selector.yaml",
            test_namespace,
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server-selector-2.yaml",
            foreign_namespace_setup.namespace,
        )
        assert_valid_vs(kube_apis, test_namespace, "virtual-server-route")
        assert_valid_vs(kube_apis, foreign_namespace_setup.namespace, "virtual-server-route-2")
        assert_vsr_status(
            kube_apis,
            foreign_namespace_setup.namespace,
            vsr_name,
            "Valid",
            expected_reason="AddedOrUpdated",
            **{"referencedBy": (f"foreign-vs/virtual-server-route-2, " f"{test_namespace}/virtual-server-route")},
        )

        delete_virtual_server(kube_apis.custom_objects, "virtual-server-route-2", foreign_namespace_setup.namespace)
        assert_valid_vs(kube_apis, test_namespace, "virtual-server-route")
        assert_vsr_status(
            kube_apis,
            foreign_namespace_setup.namespace,
            vsr_name,
            "Valid",
            expected_reason="AddedOrUpdated",
            **{"referencedBy": f"{test_namespace}/virtual-server-route"},
        )

    def test_status_invalid_after_vsr_removed(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        foreign_namespace_setup,
        simple_app_setup,
        vs_vsr_cleanup,
    ):
        vsr_name = create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/route-single.yaml",
            foreign_namespace_setup.namespace,
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server.yaml",
            test_namespace,
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-route-hostless/virtual-server-selector-2.yaml",
            foreign_namespace_setup.namespace,
        )
        assert_valid_vs(kube_apis, test_namespace, "virtual-server-route")
        assert_valid_vs(kube_apis, foreign_namespace_setup.namespace, "virtual-server-route-2")
        assert_vsr_status(
            kube_apis,
            foreign_namespace_setup.namespace,
            vsr_name,
            "Valid",
            expected_reason="AddedOrUpdated",
            **{"referencedBy": (f"foreign-vs/virtual-server-route-2, " f"{test_namespace}/virtual-server-route")},
        )

        delete_v_s_route(kube_apis.custom_objects, vsr_name, foreign_namespace_setup.namespace)
        assert_vs_status(
            kube_apis,
            test_namespace,
            "virtual-server-route",
            "Warning",
            expected_reason="AddedOrUpdatedWithWarning",
            expected_messages=["doesn't exist or invalid"],
        )
        assert_valid_vs(kube_apis, foreign_namespace_setup.namespace, "virtual-server-route-2")

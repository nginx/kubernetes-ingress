import pytest
from settings import TEST_DATA
from suite.fixtures.custom_resource_fixtures import VirtualServerSetup
from suite.utils.custom_assertions import wait_and_assert_status_code
from suite.utils.resources_utils import (
    create_items_from_yaml,
    create_namespace_with_name_from_yaml,
    delete_items_from_yaml,
    delete_namespace,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route_from_yaml,
    create_virtual_server_from_yaml,
    delete_v_s_route,
    delete_virtual_server,
    patch_virtual_server_from_yaml,
)
from suite.utils.yaml_utils import (
    get_first_host_from_yaml,
    get_paths_from_vs_yaml,
    get_upstream_namespace_from_vs_yaml,
)


@pytest.fixture(scope="class")
def virtual_server_foreign_upstream_app_setup(
    request, kube_apis, ingress_controller_endpoint, test_namespace
) -> VirtualServerSetup:
    """
    Prepare Virtual Server Example with backends in foreign namespaces:

    1st namespace with backend1-svc and deployment in the same namespace as VS,
    and 2nd namespace with backend2-svc and deployment in another namespace.

    :param request: internal pytest fixture to parametrize this method:
        {example: virtual-server|virtual-server-tls|..., app_type: simple|split|...}
        'example' is a directory name in TEST_DATA,
        'app_type' is a directory name in TEST_DATA/common/app
     :param kube_apis: client apis
    :param crd_ingress_controller:
    :param ingress_controller_endpoint:
    :param test_namespace:
    :return: VirtualServerSetup
    """
    print("------------------------- Deploy Virtual Server Example -----------------------------------")
    vs_source = f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml"
    vs_name = create_virtual_server_from_yaml(kube_apis.custom_objects, vs_source, test_namespace)
    vs_host = get_first_host_from_yaml(vs_source)
    vs_paths = get_paths_from_vs_yaml(vs_source)
    upstream_namespaces = get_upstream_namespace_from_vs_yaml(vs_source, test_namespace)
    print(f"Upstream namespaces detected in the VS yaml: {upstream_namespaces}")
    ns_1 = (
        create_namespace_with_name_from_yaml(kube_apis.v1, upstream_namespaces[0], f"{TEST_DATA}/common/ns.yaml")
        if upstream_namespaces[0] != test_namespace
        else test_namespace
    )
    ns_2 = (
        create_namespace_with_name_from_yaml(kube_apis.v1, upstream_namespaces[1], f"{TEST_DATA}/common/ns.yaml")
        if upstream_namespaces[1] != test_namespace
        else test_namespace
    )
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/common/app/{request.param['app_type']}/backend1.yaml", ns_1)
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/common/app/{request.param['app_type']}/backend2.yaml", ns_2)

    wait_until_all_pods_are_ready(kube_apis.v1, ns_1)
    wait_until_all_pods_are_ready(kube_apis.v1, ns_2)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up Virtual Server Example:")
            delete_virtual_server(kube_apis.custom_objects, vs_name, test_namespace)
            print("Clean up the Application:")
            if request.param.get("app_type"):
                delete_items_from_yaml(
                    kube_apis, f"{TEST_DATA}/common/app/{request.param["app_type"]}/backend1.yaml", ns_1
                )
                delete_items_from_yaml(
                    kube_apis, f"{TEST_DATA}/common/app/{request.param["app_type"]}/backend2.yaml", ns_2
                )

                try:
                    delete_namespace(kube_apis.v1, ns_1)
                    delete_namespace(kube_apis.v1, ns_2)

                except Exception as ex:
                    print(f"Exception during teardown: {ex}")

    request.addfinalizer(fin)

    return VirtualServerSetup(ingress_controller_endpoint, test_namespace, vs_host, vs_name, vs_paths)


@pytest.mark.vs
@pytest.mark.vs_responses
@pytest.mark.smoke
@pytest.mark.skip(reason="Flaky test - needs investigation")
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_foreign_upstream_app_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-foreign-upstream", "app_type": "simple-namespaced-upstream"},
        ),
    ],
    indirect=True,
)
class TestVirtualServerForeignUpstream:
    def test_responses_after_setup(self, kube_apis, crd_ingress_controller, virtual_server_foreign_upstream_app_setup):
        print(f"\nStep 1: initial check")
        wait_before_test()
        wait_and_assert_status_code(
            200,
            virtual_server_foreign_upstream_app_setup.backend_1_url,
            virtual_server_foreign_upstream_app_setup.vs_host,
        )
        wait_and_assert_status_code(
            200,
            virtual_server_foreign_upstream_app_setup.backend_2_url,
            virtual_server_foreign_upstream_app_setup.vs_host,
        )

    def test_responses_regex_path(self, kube_apis, crd_ingress_controller, virtual_server_foreign_upstream_app_setup):
        print(f"\nStep 2: patch VS with regex path and check")
        vs_source = f"{TEST_DATA}/virtual-server-foreign-upstream/standard/virtual-server-regex.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_foreign_upstream_app_setup.vs_name,
            vs_source,
            virtual_server_foreign_upstream_app_setup.namespace,
        )

        new_host = get_first_host_from_yaml(
            f"{TEST_DATA}/virtual-server-foreign-upstream/standard/virtual-server-regex.yaml"
        )

        wait_before_test()
        wait_and_assert_status_code(
            404,
            virtual_server_foreign_upstream_app_setup.backend_1_url,
            virtual_server_foreign_upstream_app_setup.vs_host,
        )
        wait_and_assert_status_code(
            404,
            virtual_server_foreign_upstream_app_setup.backend_2_url,
            virtual_server_foreign_upstream_app_setup.vs_host,
        )

        wait_and_assert_status_code(200, virtual_server_foreign_upstream_app_setup.backend_1_url, new_host)
        wait_and_assert_status_code(200, virtual_server_foreign_upstream_app_setup.backend_2_url, new_host)

        print("\nStep 3: restore VS and check")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_foreign_upstream_app_setup.vs_name,
            f"{TEST_DATA}/virtual-server-foreign-upstream/standard/virtual-server.yaml",
            virtual_server_foreign_upstream_app_setup.namespace,
        )
        wait_before_test()

        wait_and_assert_status_code(404, virtual_server_foreign_upstream_app_setup.backend_1_url, new_host)
        wait_and_assert_status_code(404, virtual_server_foreign_upstream_app_setup.backend_2_url, new_host)

        wait_and_assert_status_code(
            200,
            virtual_server_foreign_upstream_app_setup.backend_1_url,
            virtual_server_foreign_upstream_app_setup.vs_host,
        )
        wait_and_assert_status_code(
            200,
            virtual_server_foreign_upstream_app_setup.backend_2_url,
            virtual_server_foreign_upstream_app_setup.vs_host,
        )

    def test_responses_vsr_foreign_upstream(
        self, kube_apis, crd_ingress_controller, virtual_server_foreign_upstream_app_setup
    ):
        print(f"\nStep 4: create VS Route in the same namespace and check")
        vs_source = f"{TEST_DATA}/virtual-server-foreign-upstream/standard/virtual-server-vsr.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_foreign_upstream_app_setup.vs_name,
            vs_source,
            virtual_server_foreign_upstream_app_setup.namespace,
        )

        vs_route = create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-foreign-upstream/route-backend2.yaml",
            virtual_server_foreign_upstream_app_setup.namespace,
        )

        new_host = get_first_host_from_yaml(
            f"{TEST_DATA}/virtual-server-foreign-upstream/standard/virtual-server-vsr.yaml"
        )

        wait_before_test()

        wait_and_assert_status_code(
            404,
            virtual_server_foreign_upstream_app_setup.backend_1_url,
            virtual_server_foreign_upstream_app_setup.vs_host,
        )
        wait_and_assert_status_code(
            404,
            virtual_server_foreign_upstream_app_setup.backend_2_url,
            virtual_server_foreign_upstream_app_setup.vs_host,
        )

        wait_and_assert_status_code(200, virtual_server_foreign_upstream_app_setup.backend_1_url, new_host)
        wait_and_assert_status_code(200, virtual_server_foreign_upstream_app_setup.backend_2_url, new_host)

        print("\nStep 5: remove VSR, restore VS and check")
        delete_v_s_route(kube_apis.custom_objects, vs_route, virtual_server_foreign_upstream_app_setup.namespace)

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_foreign_upstream_app_setup.vs_name,
            f"{TEST_DATA}/virtual-server-foreign-upstream/standard/virtual-server.yaml",
            virtual_server_foreign_upstream_app_setup.namespace,
        )
        wait_before_test()

        wait_and_assert_status_code(404, virtual_server_foreign_upstream_app_setup.backend_1_url, new_host)
        wait_and_assert_status_code(404, virtual_server_foreign_upstream_app_setup.backend_2_url, new_host)

        wait_and_assert_status_code(
            200,
            virtual_server_foreign_upstream_app_setup.backend_1_url,
            virtual_server_foreign_upstream_app_setup.vs_host,
        )
        wait_and_assert_status_code(
            200,
            virtual_server_foreign_upstream_app_setup.backend_2_url,
            virtual_server_foreign_upstream_app_setup.vs_host,
        )

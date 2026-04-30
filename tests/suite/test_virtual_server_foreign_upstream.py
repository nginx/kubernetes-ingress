import re

import pytest
from settings import TEST_DATA
from suite.fixtures.custom_resource_fixtures import VirtualServerSetup
from suite.utils.custom_assertions import assert_pods_scaled_to_count, wait_and_assert_status_code
from suite.utils.resources_utils import (
    create_items_from_yaml,
    create_namespace_with_name_from_yaml,
    delete_items_from_yaml,
    delete_namespace,
    extract_block,
    get_first_pod_name,
    get_vs_nginx_template_conf,
    scale_deployment,
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
    vs_source = f"{TEST_DATA}/{request.param['example']}/standard/virtual-server.yaml"
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
    print("------------------------- Deploy Virtual Server Example -----------------------------------")
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/common/app/{request.param['app_type']}/backend1.yaml", ns_1)
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/common/app/{request.param['app_type']}/backend2.yaml", ns_2)

    wait_until_all_pods_are_ready(kube_apis.v1, ns_1)
    wait_until_all_pods_are_ready(kube_apis.v1, ns_2)

    vs_name = create_virtual_server_from_yaml(kube_apis.custom_objects, vs_source, test_namespace)
    vs_host = get_first_host_from_yaml(vs_source)
    vs_paths = get_paths_from_vs_yaml(vs_source)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up Virtual Server Example:")
            delete_virtual_server(kube_apis.custom_objects, vs_name, test_namespace)
            print("Clean up the Application:")
            if request.param.get("app_type"):
                delete_items_from_yaml(
                    kube_apis, f"{TEST_DATA}/common/app/{request.param['app_type']}/backend1.yaml", ns_1
                )
                delete_items_from_yaml(
                    kube_apis, f"{TEST_DATA}/common/app/{request.param['app_type']}/backend2.yaml", ns_2
                )

                try:
                    delete_namespace(kube_apis.v1, ns_1)
                    delete_namespace(kube_apis.v1, ns_2)

                except Exception as ex:
                    print(f"Exception during teardown: {ex}")

    request.addfinalizer(fin)

    return VirtualServerSetup(
        ingress_controller_endpoint,
        test_namespace,
        vs_host,
        vs_name,
        vs_paths,
        backend_1_namespace=ns_1,
        backend_2_namespace=ns_2,
        backend_1_name="backend1",
        backend_2_name="backend2",
    )


@pytest.mark.vs
@pytest.mark.vs_responses
@pytest.mark.smoke
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

        new_host = get_first_host_from_yaml(vs_source)

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

        new_host = get_first_host_from_yaml(vs_source)

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

    def test_cross_namespace_vs_upstream_updates_on_scale(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_foreign_upstream_app_setup,
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        upstream_name = f"upstream vs_{virtual_server_foreign_upstream_app_setup.namespace}_{virtual_server_foreign_upstream_app_setup.vs_name}_backend2"
        original_server_count = 1
        scaled_server_count = 3
        num_servers = 0
        retry = 0

        while num_servers != original_server_count and retry <= 30:
            result_conf = get_vs_nginx_template_conf(
                kube_apis.v1,
                virtual_server_foreign_upstream_app_setup.namespace,
                virtual_server_foreign_upstream_app_setup.vs_name,
                ic_pod_name,
                ingress_controller_prerequisites.namespace,
            )
            upstream_block = extract_block(result_conf, upstream_name)
            num_servers = len(re.findall("server .*;", upstream_block))
            retry += 1
            wait_before_test(1)

        assert num_servers == original_server_count

        print("\nStep 1: scale foreign backend up and verify VS upstream endpoints")
        scale_deployment(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            virtual_server_foreign_upstream_app_setup.backend_2_name,
            virtual_server_foreign_upstream_app_setup.backend_2_namespace,
            scaled_server_count,
        )
        assert_pods_scaled_to_count(
            kube_apis.apps_v1_api,
            kube_apis.v1,
            virtual_server_foreign_upstream_app_setup.backend_2_name,
            virtual_server_foreign_upstream_app_setup.backend_2_namespace,
            scaled_server_count,
        )
        retry = 0
        while num_servers != scaled_server_count and retry <= 30:
            result_conf = get_vs_nginx_template_conf(
                kube_apis.v1,
                virtual_server_foreign_upstream_app_setup.namespace,
                virtual_server_foreign_upstream_app_setup.vs_name,
                ic_pod_name,
                ingress_controller_prerequisites.namespace,
            )
            upstream_block = extract_block(result_conf, upstream_name)
            num_servers = len(re.findall("server .*;", upstream_block))
            retry += 1
            wait_before_test(1)

        assert num_servers == scaled_server_count

        print("\nStep 2: scale foreign backend down and verify VS upstream endpoints")
        scale_deployment(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            virtual_server_foreign_upstream_app_setup.backend_2_name,
            virtual_server_foreign_upstream_app_setup.backend_2_namespace,
            original_server_count,
        )
        assert_pods_scaled_to_count(
            kube_apis.apps_v1_api,
            kube_apis.v1,
            virtual_server_foreign_upstream_app_setup.backend_2_name,
            virtual_server_foreign_upstream_app_setup.backend_2_namespace,
            original_server_count,
        )
        retry = 0
        while num_servers != original_server_count and retry <= 30:
            result_conf = get_vs_nginx_template_conf(
                kube_apis.v1,
                virtual_server_foreign_upstream_app_setup.namespace,
                virtual_server_foreign_upstream_app_setup.vs_name,
                ic_pod_name,
                ingress_controller_prerequisites.namespace,
            )
            upstream_block = extract_block(result_conf, upstream_name)
            num_servers = len(re.findall("server .*;", upstream_block))
            retry += 1
            wait_before_test(1)

        assert num_servers == original_server_count

    def test_cross_namespace_vsr_upstream_updates_on_scale(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_foreign_upstream_app_setup,
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        vs_source = f"{TEST_DATA}/virtual-server-foreign-upstream/standard/virtual-server-vsr.yaml"
        original_server_count = 1
        scaled_server_count = 3
        num_servers = 0

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
        vsr_host = get_first_host_from_yaml(vs_source)
        upstream_name = (
            f"upstream vs_{virtual_server_foreign_upstream_app_setup.namespace}_"
            f"{virtual_server_foreign_upstream_app_setup.vs_name}_vsr_"
            f"{virtual_server_foreign_upstream_app_setup.namespace}_{vs_route}_backend2"
        )

        wait_before_test(1)
        result_conf = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_foreign_upstream_app_setup.namespace,
            virtual_server_foreign_upstream_app_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert vsr_host in result_conf

        retry = 0
        while num_servers != original_server_count and retry <= 30:
            result_conf = get_vs_nginx_template_conf(
                kube_apis.v1,
                virtual_server_foreign_upstream_app_setup.namespace,
                virtual_server_foreign_upstream_app_setup.vs_name,
                ic_pod_name,
                ingress_controller_prerequisites.namespace,
            )
            upstream_block = extract_block(result_conf, upstream_name)
            num_servers = len(re.findall("server .*;", upstream_block))
            retry += 1
            wait_before_test(1)

        assert num_servers == original_server_count

        print("\nStep 1: scale foreign backend up and verify VSR upstream endpoints")
        scale_deployment(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            virtual_server_foreign_upstream_app_setup.backend_2_name,
            virtual_server_foreign_upstream_app_setup.backend_2_namespace,
            scaled_server_count,
        )
        assert_pods_scaled_to_count(
            kube_apis.apps_v1_api,
            kube_apis.v1,
            virtual_server_foreign_upstream_app_setup.backend_2_name,
            virtual_server_foreign_upstream_app_setup.backend_2_namespace,
            scaled_server_count,
        )
        retry = 0
        while num_servers != scaled_server_count and retry <= 30:
            result_conf = get_vs_nginx_template_conf(
                kube_apis.v1,
                virtual_server_foreign_upstream_app_setup.namespace,
                virtual_server_foreign_upstream_app_setup.vs_name,
                ic_pod_name,
                ingress_controller_prerequisites.namespace,
            )
            upstream_block = extract_block(result_conf, upstream_name)
            num_servers = len(re.findall("server .*;", upstream_block))
            retry += 1
            wait_before_test(1)

        assert num_servers == scaled_server_count

        print("\nStep 2: scale foreign backend down and verify VSR upstream endpoints")
        scale_deployment(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            virtual_server_foreign_upstream_app_setup.backend_2_name,
            virtual_server_foreign_upstream_app_setup.backend_2_namespace,
            original_server_count,
        )
        assert_pods_scaled_to_count(
            kube_apis.apps_v1_api,
            kube_apis.v1,
            virtual_server_foreign_upstream_app_setup.backend_2_name,
            virtual_server_foreign_upstream_app_setup.backend_2_namespace,
            original_server_count,
        )
        retry = 0
        while num_servers != original_server_count and retry <= 30:
            result_conf = get_vs_nginx_template_conf(
                kube_apis.v1,
                virtual_server_foreign_upstream_app_setup.namespace,
                virtual_server_foreign_upstream_app_setup.vs_name,
                ic_pod_name,
                ingress_controller_prerequisites.namespace,
            )
            upstream_block = extract_block(result_conf, upstream_name)
            num_servers = len(re.findall("server .*;", upstream_block))
            retry += 1
            wait_before_test(1)

        assert num_servers == original_server_count

        delete_v_s_route(kube_apis.custom_objects, vs_route, virtual_server_foreign_upstream_app_setup.namespace)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_foreign_upstream_app_setup.vs_name,
            f"{TEST_DATA}/virtual-server-foreign-upstream/standard/virtual-server.yaml",
            virtual_server_foreign_upstream_app_setup.namespace,
        )

import pytest
from settings import CRDS, DEPLOYMENTS, TEST_DATA
from suite.utils.custom_assertions import wait_and_assert_status_code
from suite.utils.custom_resources_utils import create_crd_from_yaml, delete_crd
from suite.utils.resources_utils import (
    create_service_from_yaml,
    delete_service,
    get_first_pod_name,
    get_vs_nginx_template_conf,
    patch_rbac,
    read_service,
    replace_service,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
    patch_virtual_server_from_yaml,
)
from suite.utils.yaml_utils import get_first_host_from_yaml, get_name_from_yaml, get_paths_from_vs_yaml


@pytest.mark.vs
@pytest.mark.vs_responses
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVirtualServer:
    def test_responses_after_setup(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        print("\nStep 1: initial check")
        wait_before_test(1)
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

    def test_responses_after_virtual_server_update(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        print("Step 2: update host and paths in the VS and check")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server/standard/virtual-server-updated.yaml",
            virtual_server_setup.namespace,
        )
        new_paths = get_paths_from_vs_yaml(f"{TEST_DATA}/virtual-server/standard/virtual-server-updated.yaml")
        new_backend_1_url = (
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/{new_paths[0]}"
        )
        new_backend_2_url = (
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/{new_paths[1]}"
        )
        new_host = get_first_host_from_yaml(f"{TEST_DATA}/virtual-server/standard/virtual-server-updated.yaml")
        wait_before_test(1)

        wait_and_assert_status_code(404, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(404, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

        wait_and_assert_status_code(200, new_backend_1_url, new_host)
        wait_and_assert_status_code(200, new_backend_2_url, new_host)

        print("Step 3: restore VS and check")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)

        wait_and_assert_status_code(404, new_backend_1_url, new_host)
        wait_and_assert_status_code(404, new_backend_2_url, new_host)

        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

    def test_responses_after_backend_update(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        print("Step 4: update one backend service port and check")
        the_service = read_service(kube_apis.v1, "backend1-svc", virtual_server_setup.namespace)
        the_service.spec.ports[0].port = 8080
        replace_service(kube_apis.v1, "backend1-svc", virtual_server_setup.namespace, the_service)
        wait_before_test(1)

        wait_and_assert_status_code(502, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

        print("Step 5: restore BE and check")
        the_service = read_service(kube_apis.v1, "backend1-svc", virtual_server_setup.namespace)
        the_service.spec.ports[0].port = 80
        replace_service(kube_apis.v1, "backend1-svc", virtual_server_setup.namespace, the_service)
        wait_before_test(1)

        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

    def test_responses_after_virtual_server_removal(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        print("\nStep 6: delete VS and check")
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace)
        wait_before_test(1)

        wait_and_assert_status_code(404, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(404, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

        print("Step 7: restore VS and check")
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)

        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

    def test_responses_after_backend_service_removal(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        print("\nStep 8: remove one backend service and check")
        delete_service(kube_apis.v1, "backend1-svc", virtual_server_setup.namespace)
        wait_before_test(1)

        wait_and_assert_status_code(502, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

        print("\nStep 9: restore backend service and check")
        create_service_from_yaml(kube_apis.v1, virtual_server_setup.namespace, f"{TEST_DATA}/common/backend1-svc.yaml")
        wait_before_test(1)

        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

    def test_responses_after_rbac_misconfiguration_on_the_fly(
        self, kube_apis, crd_ingress_controller, virtual_server_setup
    ):
        print("Step 10: remove virtualservers from the ClusterRole and check")
        patch_rbac(kube_apis.rbac_v1, f"{TEST_DATA}/virtual-server/rbac-without-vs.yaml")
        wait_before_test(1)
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

        print("Step 11: restore ClusterRole and check")
        patch_rbac(kube_apis.rbac_v1, f"{DEPLOYMENTS}/rbac/rbac.yaml")
        wait_before_test(1)
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

    def test_responses_after_crd_removal_on_the_fly(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        print("\nStep 12: remove CRD and check")
        crd_name = get_name_from_yaml(f"{CRDS}/k8s.nginx.org_virtualservers.yaml")
        delete_crd(kube_apis.api_extensions_v1, crd_name)
        wait_and_assert_status_code(404, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(404, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

        print("Step 13: restore CRD and VS and check")
        create_crd_from_yaml(kube_apis.api_extensions_v1, crd_name, f"{CRDS}/k8s.nginx.org_virtualservers.yaml")
        wait_before_test(1)
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml",
            virtual_server_setup.namespace,
        )
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

    def test_responses_after_virtual_server_update_with_gunzip(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        print("Step 1: update gunzip in the VS and check")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server/virtual-server-gunzip.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

        print("Step 2: verify gunzip directive is present")

        pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)

        confFile = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert "gunzip on;" in confFile

        print("Step 3: restore VS and check")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)


@pytest.mark.vs
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "rbac-without-vs", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVirtualServerInitialRBACMisconfiguration:
    @pytest.mark.skip(reason="issues with ingressClass")
    def test_responses_after_rbac_misconfiguration(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        print("\nStep 1: rbac misconfiguration from the very start")
        wait_and_assert_status_code(404, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(404, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

        print("Step 2: configure RBAC and check")
        patch_rbac(kube_apis.rbac_v1, f"{DEPLOYMENTS}/rbac/rbac.yaml")
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)

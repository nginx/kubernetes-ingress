import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
    patch_v_s_route_from_yaml,
    patch_virtual_server_from_yaml,
)


@pytest.fixture(scope="class")
def waf_setup(kube_apis, test_namespace) -> None:
    waf = f"{TEST_DATA}/ap-waf-v5/policies/waf.yaml"
    create_policy_from_yaml(kube_apis.custom_objects, waf, test_namespace)
    wait_before_test()


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect_waf_v5
@pytest.mark.parametrize(
    "crd_ingress_controller_with_waf_v5, virtual_server_setup",
    [
        (
            {
                "type": "rorfs",
                "extra_args": [
                    f"-enable-app-protect",
                ],
            },
            {
                "example": "ap-waf-v5",
                "app_type": "simple",
            },
        ),
    ],
    indirect=True,
)
class TestAppProtectWAFv5IntegrationVSrorfs:
    def restore_default_vs(self, kube_apis, virtual_server_setup) -> None:
        """
        Restore VirtualServer without policy spec
        """
        std_vs_src = f"{TEST_DATA}/ap-waf-v5/standard/virtual-server.yaml"
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace)
        create_virtual_server_from_yaml(kube_apis.custom_objects, std_vs_src, virtual_server_setup.namespace)
        wait_before_test()

    @pytest.mark.parametrize(
        "vs_src",
        [f"{TEST_DATA}/ap-waf-v5/virtual-server-waf-spec.yaml"],
    )
    def test_ap_waf_v5_policy_block_vs(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_waf_v5,
        test_namespace,
        virtual_server_setup,
        waf_setup,
        vs_src,
    ):
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_src,
            virtual_server_setup.namespace,
        )

        print("----------------------- Send request with embedded malicious script----------------------")
        count = 0
        response = requests.get(
            virtual_server_setup.backend_1_url + "</script>",
            headers={"host": virtual_server_setup.vs_host},
        )
        while count < 5 and "Request Rejected" not in response.text:
            response = requests.get(
                virtual_server_setup.backend_1_url + "</script>",
                headers={"host": virtual_server_setup.vs_host},
            )
            wait_before_test()
            count += 1
        self.restore_default_vs(kube_apis, virtual_server_setup)
        assert response.status_code == 200
        assert "The requested URL was rejected. Please consult with your administrator." in response.text


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect_waf_v5
@pytest.mark.parametrize(
    "crd_ingress_controller_with_waf_v5, v_s_route_setup",
    [
        (
            {
                "type": "rorfs",
                "extra_args": [
                    f"-enable-app-protect",
                ],
            },
            {
                "example": "virtual-server-route",
            },
        )
    ],
    indirect=True,
)
class TestAppProtectWAFv5IntegrationVSRrorfs:

    def restore_default_vsr(self, kube_apis, v_s_route_setup) -> None:
        """
        Function to revert vsr deployments to standard state
        """
        patch_src_m = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            patch_src_m,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

    def test_ap_waf_v5_policy_block_vsr(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_waf_v5,
        test_namespace,
        v_s_route_setup,
    ):
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        waf_subroute_vsr_src = f"{TEST_DATA}/ap-waf-v5/virtual-server-route-waf-subroute.yaml"
        pol = create_policy_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/ap-waf-v5/policies/waf.yaml",
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            waf_subroute_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        print("----------------------- Send request with embedded malicious script----------------------")
        count = 0
        response = requests.get(
            f'{req_url}{v_s_route_setup.route_m.paths[0]}+"</script>"',
            headers={"host": v_s_route_setup.vs_host},
        )
        while count < 5 and "Request Rejected" not in response.text:
            response = requests.get(
                f'{req_url}{v_s_route_setup.route_m.paths[0]}+"</script>"',
                headers={"host": v_s_route_setup.vs_host},
            )
            wait_before_test()
            count += 1
        self.restore_default_vsr(kube_apis, v_s_route_setup)
        delete_policy(kube_apis.custom_objects, pol, v_s_route_setup.route_m.namespace)
        assert response.status_code == 200
        assert "The requested URL was rejected. Please consult with your administrator." in response.text

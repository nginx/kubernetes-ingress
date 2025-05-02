import pytest
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.resources_utils import wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
    patch_v_s_route_from_yaml,
    patch_virtual_server_from_yaml,
)


@pytest.mark.vsr
@pytest.mark.vsr_status
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [f"-enable-custom-resources", f"-enable-leader-election=false"],
            },
            {"example": "virtual-server-route-status"},
        )
    ],
    indirect=True,
)
class TestVirtualServerRouteStatus:
    def patch_valid_vsr(self, kube_apis, v_s_route_setup) -> None:
        """
        Function to revert vsr deployments to valid state
        """
        patch_src_m = f"{TEST_DATA}/virtual-server-route-status/route-multiple.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            patch_src_m,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        patch_src_s = f"{TEST_DATA}/virtual-server-route-status/route-single.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_s.name,
            patch_src_s,
            v_s_route_setup.route_s.namespace,
        )
        wait_before_test()

    def patch_valid_vs(self, kube_apis, v_s_route_setup) -> None:
        """
        Function to revert vs deployment to valid state
        """
        patch_src = f"{TEST_DATA}/virtual-server-route-status/standard/virtual-server.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            patch_src,
            v_s_route_setup.namespace,
        )
        wait_before_test()

    @pytest.mark.smoke
    def test_status_valid(self, kube_apis, crd_ingress_controller, v_s_route_setup, v_s_route_app_setup):
        """
        Test VirtualServerRoute status with a valid fields in yaml
        """
        response_m = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        response_s = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_s.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_s.name,
        )
        assert (
            response_m["status"]
            and response_m["status"]["reason"] == "AddedOrUpdated"
            and response_m["status"]["referencedBy"]
            and response_m["status"]["state"] == "Valid"
        )

        assert (
            response_s["status"]
            and response_s["status"]["reason"] == "AddedOrUpdated"
            and response_s["status"]["referencedBy"]
            and response_s["status"]["state"] == "Valid"
        )

    def test_status_invalid(self, kube_apis, crd_ingress_controller, v_s_route_setup, v_s_route_app_setup):
        """
        Test VirtualServerRoute status with a invalid paths in vsr yaml
        """
        patch_src_m = f"{TEST_DATA}/virtual-server-route-status/route-multiple-invalid.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            patch_src_m,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        patch_src_s = f"{TEST_DATA}/virtual-server-route-status/route-single-invalid.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_s.name,
            patch_src_s,
            v_s_route_setup.route_s.namespace,
        )
        wait_before_test()

        response_m = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        response_s = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_s.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_s.name,
        )

        self.patch_valid_vsr(kube_apis, v_s_route_setup)
        assert (
            response_m["status"]
            and response_m["status"]["reason"] == "Rejected"
            and not response_m["status"]["referencedBy"]
            and response_m["status"]["state"] == "Invalid"
        )

        assert (
            response_s["status"]
            and response_s["status"]["reason"] == "Rejected"
            and not response_s["status"]["referencedBy"]
            and response_s["status"]["state"] == "Invalid"
        )

    def test_status_invalid_prefix(self, kube_apis, crd_ingress_controller, v_s_route_setup, v_s_route_app_setup):
        """
        Test VirtualServerRoute status with a invalid path /prefix in vsr yaml
        i.e. referring to non-existing path
        """
        patch_src_m = f"{TEST_DATA}/virtual-server-route-status/route-multiple-invalid-prefixed-path.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            patch_src_m,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        patch_src_s = f"{TEST_DATA}/virtual-server-route-status/route-single-invalid-prefixed-path.yaml"
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_s.name,
            patch_src_s,
            v_s_route_setup.route_s.namespace,
        )
        wait_before_test()

        response_m = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        response_s = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_s.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_s.name,
        )

        self.patch_valid_vsr(kube_apis, v_s_route_setup)
        assert (
            response_m["status"]
            and response_m["status"]["reason"] == "AddedOrUpdated"
            and response_m["status"]["referencedBy"]
            and response_m["status"]["state"] == "Valid"
        )

        assert (
            response_s["status"]
            and response_s["status"]["reason"] == "Ignored"
            and not response_s["status"]["referencedBy"]
            and response_s["status"]["state"] == "Warning"
        )

    def test_status_invalid_vsr_in_vs(self, kube_apis, crd_ingress_controller, v_s_route_setup, v_s_route_app_setup):
        """
        Test VirtualServerRoute status with invalid vsr reference in vs yaml
        """

        patch_src = f"{TEST_DATA}/virtual-server-route-status/virtual-server-invalid.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            patch_src,
            v_s_route_setup.namespace,
        )
        wait_before_test()

        response_m = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        response_s = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_s.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_s.name,
        )
        self.patch_valid_vs(kube_apis, v_s_route_setup)
        assert (
            response_m["status"]
            and response_m["status"]["reason"] == "Ignored"
            and not response_m["status"]["referencedBy"]
            and response_m["status"]["state"] == "Warning"
        )

        assert (
            response_s["status"]
            and response_s["status"]["reason"] == "Ignored"
            and not response_s["status"]["referencedBy"]
            and response_s["status"]["state"] == "Warning"
        )

    def test_status_remove_vs(self, kube_apis, crd_ingress_controller, v_s_route_setup, v_s_route_app_setup):
        """
        Test VirtualServerRoute status after deleting referenced VirtualServer
        """
        delete_virtual_server(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            v_s_route_setup.namespace,
        )

        response_m = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        response_s = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_s.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_s.name,
        )

        vs_src = f"{TEST_DATA}/virtual-server-route-status/standard/virtual-server.yaml"
        create_virtual_server_from_yaml(kube_apis.custom_objects, vs_src, v_s_route_setup.namespace)

        assert (
            response_m["status"]
            and response_m["status"]["reason"] == "NoVirtualServerFound"
            and not response_m["status"]["referencedBy"]
            and response_m["status"]["state"] == "Warning"
        )

        assert (
            response_s["status"]
            and response_s["status"]["reason"] == "NoVirtualServerFound"
            and not response_s["status"]["referencedBy"]
            and response_s["status"]["state"] == "Warning"
        )

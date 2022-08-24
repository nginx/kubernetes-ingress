import pytest
import requests
from settings import TEST_DATA
from suite.custom_assertions import wait_and_assert_status_code
from suite.custom_resources_utils import read_custom_resource
from suite.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
)
from suite.resources_utils import wait_before_test

@pytest.mark.vs
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
class TestVirtualServerWildcard:

    def test_vs_status(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)
        wait_and_assert_status_code(404, virtual_server_setup.backend_1_url, "test.example.com")
        wait_and_assert_status_code(404, virtual_server_setup.backend_2_url, "test.example.com")

        # create virtual server with wildcard hostname
        manifest_vs_wc = f"{TEST_DATA}/virtual-server-wildcard/virtual-server-wildcard.yaml"
        vs_wc_name = create_virtual_server_from_yaml(kube_apis.custom_objects, manifest_vs_wc, virtual_server_setup.namespace)
        wait_before_test()
        response = read_custom_resource(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            "virtualservers",
            vs_wc_name,
        )
        assert (
            response["status"]
            and response["status"]["reason"] == "AddedOrUpdated"
            and response["status"]["state"] == "Valid"
        )
        wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, "test.example.com")
        wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, "test.example.com")
        wait_and_assert_status_code(404, virtual_server_setup.backend_1_url, "test.xexample.com")
        wait_and_assert_status_code(404, virtual_server_setup.backend_2_url, "test.xexample.com")

        delete_virtual_server(kube_apis.custom_objects, vs_wc_name, virtual_server_setup.namespace)
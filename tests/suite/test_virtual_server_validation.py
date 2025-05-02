import pytest
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_vs_conf_exists, assert_vs_conf_not_exists, wait_and_assert_status_code
from suite.utils.resources_utils import get_events, get_first_pod_name, wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
    patch_virtual_server_from_yaml,
)


def assert_reject_events_emitted(virtual_server_setup, new_list, previous_list, expected_amount):
    item_name = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
    text_invalid = f"VirtualServer {item_name} was rejected with error"
    new_event = new_list[len(new_list) - 1]
    assert len(new_list) - len(previous_list) == expected_amount
    assert text_invalid in new_event.message


def assert_event_count_increased_in_list(virtual_server_setup, new_list, previous_list):
    item_name = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
    text_valid = f"Configuration for {item_name} was added or updated"
    for i in range(len(previous_list) - 1, 0, -1):
        if text_valid in previous_list[i].message:
            assert new_list[i].count - previous_list[i].count == 1, "We expect the counter to increase"


def assert_response_200(virtual_server_setup):
    wait_and_assert_status_code(200, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
    wait_and_assert_status_code(200, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)


def assert_response_404(virtual_server_setup):
    wait_and_assert_status_code(404, virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
    wait_and_assert_status_code(404, virtual_server_setup.backend_2_url, virtual_server_setup.vs_host)


@pytest.mark.vs
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-validation", "app_type": "advanced-routing"},
        )
    ],
    indirect=True,
)
class TestVirtualServerValidation:
    def test_virtual_server_behavior(
        self, kube_apis, cli_arguments, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)

        print("Step 1: initial check")
        assert_vs_conf_exists(kube_apis, ic_pod_name, ingress_controller_prerequisites.namespace, virtual_server_setup)
        assert_response_200(virtual_server_setup)

        print("Step 2: make a valid VirtualServer invalid and check")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-validation/virtual-server-invalid-cookie.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)
        assert_vs_conf_not_exists(
            kube_apis, ic_pod_name, ingress_controller_prerequisites.namespace, virtual_server_setup
        )
        assert_response_404(virtual_server_setup)

        print("Step 3: update an invalid VirtualServer with another invalid and check")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-validation/virtual-server-no-default-action.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)
        step_3_list = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_vs_conf_not_exists(
            kube_apis, ic_pod_name, ingress_controller_prerequisites.namespace, virtual_server_setup
        )
        assert_response_404(virtual_server_setup)

        print("Step 4: make an invalid VirtualServer valid and check")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-validation/standard/virtual-server.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)
        step_4_list = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_vs_conf_exists(kube_apis, ic_pod_name, ingress_controller_prerequisites.namespace, virtual_server_setup)
        assert_event_count_increased_in_list(virtual_server_setup, step_4_list, step_3_list)
        assert_response_200(virtual_server_setup)

        print("Step 5: delete VS and then create an invalid and check")
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace)
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/virtual-server-validation/virtual-server-invalid-cookie.yaml",
            virtual_server_setup.namespace,
        )
        wait_before_test(1)
        assert_vs_conf_not_exists(
            kube_apis, ic_pod_name, ingress_controller_prerequisites.namespace, virtual_server_setup
        )
        assert_response_404(virtual_server_setup)

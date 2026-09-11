import pytest
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_event, assert_event_not_present
from suite.utils.custom_resources_utils import is_dnsendpoint_present, read_custom_resource
from suite.utils.resources_utils import (
    get_events,
    patch_namespace_with_label,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import patch_virtual_server_from_yaml
from suite.utils.yaml_utils import get_name_from_yaml, get_namespace_from_yaml

VS_YAML = f"{TEST_DATA}/virtual-server-external-dns/standard/virtual-server.yaml"


@pytest.mark.vs
@pytest.mark.vs_externaldns
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ed, create_externaldns, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources", f"-enable-external-dns"]},
            {},
            {"example": "virtual-server-external-dns", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestExternalDNSVirtualServer:
    def test_responses_after_setup(
        self, kube_apis, crd_ingress_controller_with_ed, create_externaldns, virtual_server_setup
    ):
        print("\nStep 1: Verify DNSEndpoint exists")
        dns_ep_name = get_name_from_yaml(VS_YAML)
        retry = 0
        dep = is_dnsendpoint_present(kube_apis.custom_objects, dns_ep_name, virtual_server_setup.namespace)
        while dep == False and retry <= 60:
            dep = is_dnsendpoint_present(kube_apis.custom_objects, dns_ep_name, virtual_server_setup.namespace)
            retry += 1
            wait_before_test(1)
            print(f"DNSEndpoint not created, retrying... #{retry}")
        assert dep is True
        print("\nStep 2: Verify external-dns picked up the record")
        pod_ns = get_namespace_from_yaml(f"{TEST_DATA}/virtual-server-external-dns/external-dns.yaml")
        pod_name = kube_apis.v1.list_namespaced_pod(pod_ns).items[0].metadata.name
        log_contents = kube_apis.v1.read_namespaced_pod_log(pod_name, pod_ns)
        wanted_string = "CREATE: virtual-server.example.com 0 IN A"
        retry = 0
        while wanted_string not in log_contents and retry <= 60:
            log_contents = kube_apis.v1.read_namespaced_pod_log(pod_name, pod_ns)
            retry += 1
            wait_before_test(1)
            print(f"External DNS not updated, retrying... #{retry}")
        assert wanted_string in log_contents
        print("\nStep 3: Verify VS status is Valid and no bad config events occurred")
        events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        vs_bad_config_event = "Error creating DNSEndpoint for VirtualServer resource"
        assert_event_not_present(vs_bad_config_event, events)
        response = read_custom_resource(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            "virtualservers",
            virtual_server_setup.vs_name,
        )
        assert (
            response["status"]
            and response["status"]["reason"] == "AddedOrUpdated"
            and response["status"]["state"] == "Valid"
        )

    def test_update_to_ed_in_vs(
        self, kube_apis, crd_ingress_controller_with_ed, create_externaldns, virtual_server_setup
    ):
        print("\nStep 1: Update VirtualServer")
        patch_src = f"{TEST_DATA}/virtual-server-external-dns/virtual-server-updated.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            patch_src,
            virtual_server_setup.namespace,
        )
        print("\nStep 2: Verify the DNSEndpoint was updated")
        vs_event_update_text = "Successfully updated DNSEndpoint"
        wait_before_test(5)
        events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        assert_event(vs_event_update_text, events)
        print("\nStep 3: Verify VS status is Valid")
        response = read_custom_resource(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            "virtualservers",
            virtual_server_setup.vs_name,
        )
        assert (
            response["status"]
            and response["status"]["reason"] == "AddedOrUpdated"
            and response["status"]["state"] == "Valid"
        )


@pytest.mark.vs
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ed, create_externaldns, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-external-dns",
                    f"-watch-namespace-label=app=watch",
                ],
            },
            {},
            {"example": "virtual-server-external-dns", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestExternalDNSVirtualServerWatchLabel:
    def test_responses_after_setup(
        self, kube_apis, crd_ingress_controller_with_ed, create_externaldns, virtual_server_setup, test_namespace
    ):
        dns_ep_name = get_name_from_yaml(VS_YAML)
        print("\nStep 0: Verify DNSEndpoint is not created without watched label")
        retry = 0
        dep = is_dnsendpoint_present(kube_apis.custom_objects, dns_ep_name, virtual_server_setup.namespace)
        # add a wait to avoid a false negative
        wait_before_test(30)
        dep = is_dnsendpoint_present(kube_apis.custom_objects, dns_ep_name, virtual_server_setup.namespace)
        assert dep is False
        print("\nStep 1: Verify DNSEndpoint exists after label is added to namespace")
        patch_namespace_with_label(kube_apis.v1, test_namespace, "watch", f"{TEST_DATA}/common/ns-patch.yaml")
        wait_before_test()
        retry = 0
        dep = is_dnsendpoint_present(kube_apis.custom_objects, dns_ep_name, virtual_server_setup.namespace)
        while dep == False and retry <= 60:
            dep = is_dnsendpoint_present(kube_apis.custom_objects, dns_ep_name, virtual_server_setup.namespace)
            retry += 1
            wait_before_test(1)
            print(f"DNSEndpoint not created, retrying... #{retry}")
        assert dep is True
        print("\nStep 2: Verify external-dns picked up the record")
        pod_ns = get_namespace_from_yaml(f"{TEST_DATA}/virtual-server-external-dns/external-dns.yaml")
        pod_name = kube_apis.v1.list_namespaced_pod(pod_ns).items[0].metadata.name
        log_contents = kube_apis.v1.read_namespaced_pod_log(pod_name, pod_ns)
        wanted_string = "CREATE: virtual-server.example.com 0 IN A"
        retry = 0
        while wanted_string not in log_contents and retry <= 60:
            log_contents = kube_apis.v1.read_namespaced_pod_log(pod_name, pod_ns)
            retry += 1
            wait_before_test(1)
            print(f"External DNS not updated, retrying... #{retry}")
        assert wanted_string in log_contents
        print("\nStep 3: Verify VS status is Valid and no bad config events occurred")
        events = get_events(kube_apis.v1, virtual_server_setup.namespace)
        vs_bad_config_event = "Error creating DNSEndpoint for VirtualServer resource"
        assert_event_not_present(vs_bad_config_event, events)
        response = read_custom_resource(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            "virtualservers",
            virtual_server_setup.vs_name,
        )
        assert (
            response["status"]
            and response["status"]["reason"] == "AddedOrUpdated"
            and response["status"]["state"] == "Valid"
        )

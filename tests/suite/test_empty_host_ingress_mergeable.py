import pytest
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_event, wait_and_assert_status_code
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress_from_yaml,
    delete_common_app,
    delete_ingress,
    get_default_server_conf,
    get_events_for_object,
    get_first_pod_name,
    wait_before_test,
    wait_until_all_pods_are_ready,
)

mergeable_test_data_path = f"{TEST_DATA}/empty-host-ingress-mergeable"
master_ingress_src = f"{mergeable_test_data_path}/empty-host-master-ingress.yaml"
minion1_ingress_src = f"{mergeable_test_data_path}/empty-host-minion1-ingress.yaml"
minion2_ingress_src = f"{mergeable_test_data_path}/empty-host-minion2-ingress.yaml"


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller",
    [pytest.param({"extra_args": ["-allow-empty-ingress-host"]}, id="empty-host-ingress")],
    indirect=True,
)
class TestEmptyHostIngressMergeable:
    def test_empty_host_minion_requires_master_sequence(
        self,
        kube_apis,
        ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        request_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}"
        host = "anything.example.com"

        print("Step 1: empty-host minion is rejected until an empty-host master exists")
        minion1_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, minion1_ingress_src)
        wait_before_test()

        # A minion alone is not enough to own _default-server.conf. Without a master, NIC rejects it
        # and the synthetic default server continues returning 404.
        assert_event(
            "Ingress master is invalid or doesn't exist",
            get_events_for_object(kube_apis.v1, test_namespace, minion1_name),
        )
        conf = get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)
        assert "backend1-svc" not in conf
        wait_and_assert_status_code(404, f"{request_url}/backend1", host, verify=False)

        print("Step 2: creating an empty-host master activates the existing minion")
        master_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, master_ingress_src)
        wait_before_test()

        # Once the master exists, the minion contributes routes into the shared default-server owner.
        conf = get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)
        assert "backend1-svc" in conf
        wait_and_assert_status_code(200, f"{request_url}/backend1", host, verify=False)

        print("Step 3: additional empty-host minions are accepted while the empty-host master exists")
        minion2_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, minion2_ingress_src)
        wait_before_test()

        # Additional minions extend the same default-server owner, so both backend paths are present.
        conf = get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)
        assert "backend1-svc" in conf
        assert "backend2-svc" in conf
        wait_and_assert_status_code(200, f"{request_url}/backend2", host, verify=False)

        delete_ingress(kube_apis.networking_v1, master_name, test_namespace)
        delete_ingress(kube_apis.networking_v1, minion1_name, test_namespace)
        delete_ingress(kube_apis.networking_v1, minion2_name, test_namespace)
        delete_common_app(kube_apis, "simple", test_namespace)

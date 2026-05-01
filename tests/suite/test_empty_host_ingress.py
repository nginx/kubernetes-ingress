import pytest
import yaml
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_event, assert_ingress_conf_not_exists, wait_and_assert_status_code
from suite.utils.resources_utils import (
    create_ingress_from_yaml,
    create_items_from_yaml,
    delete_ingress,
    delete_items_from_yaml,
    get_default_server_conf,
    get_events_for_object,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    replace_ingress,
    wait_before_test,
    wait_until_all_pods_are_ready,
)

empty_host_test_data_path = f"{TEST_DATA}/empty-host-ingress"
cafe_app_src = f"{empty_host_test_data_path}/cafe-app.yaml"
cafe_ingress_src = f"{empty_host_test_data_path}/cafe-ingress.yaml"
empty_host_app_src = f"{empty_host_test_data_path}/empty-host-app.yaml"
empty_host_ingress_src = f"{empty_host_test_data_path}/empty-host-ingress.yaml"
rejected_listen_ports_ingress_src = f"{empty_host_test_data_path}/empty-host-ingress-rejected-listen-ports.yaml"


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller",
    [pytest.param({"extra_args": ["-allow-empty-ingress-host", "-health-status"]}, id="empty-host-ingress")],
    indirect=True,
)
class TestEmptyHostIngressCollisionResolution:
    @pytest.fixture(scope="class")
    def empty_host_apps_setup(
        self,
        request,
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller,
        test_namespace,
    ):
        create_items_from_yaml(kube_apis, cafe_app_src, test_namespace)
        create_items_from_yaml(kube_apis, empty_host_app_src, test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        wait_and_assert_status_code(
            404,
            f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/",
            verify=False,
        )

        def fin():
            if request.config.getoption("--skip-fixture-teardown") == "no":
                delete_items_from_yaml(kube_apis, cafe_app_src, test_namespace)
                delete_items_from_yaml(kube_apis, empty_host_app_src, test_namespace)

        request.addfinalizer(fin)

    def test_empty_host_ingress_collision_resolution(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        empty_host_apps_setup,
        test_namespace,
    ):
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        request_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}"
        health_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}"

        print("Step 1: create named-host cafe-ingress; the synthetic default server still owns bare requests")
        cafe = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, cafe_ingress_src)
        wait_before_test()

        # The synthetic default server still handles requests without a Host match.
        assert "return 404" in get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)
        # The named ingress gets its own dedicated config file.
        assert get_ingress_nginx_template_conf(
            kube_apis.v1,
            test_namespace,
            cafe,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        ) is not None
        assert "coffee-svc" in get_ingress_nginx_template_conf(
            kube_apis.v1,
            test_namespace,
            cafe,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        # Bare requests still hit the synthetic default server.
        wait_and_assert_status_code(404, f"{request_url}/", verify=False)
        # Host-specific traffic routes through cafe-ingress as usual.
        wait_and_assert_status_code(200, f"{health_url}/coffee", "cafe.example.com")
        wait_and_assert_status_code(404, f"{request_url}/coffee", verify=False)

        print("Step 2: create empty-host-ingress; it takes over _default-server.conf for bare requests")
        empty_host_ingress = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, empty_host_ingress_src)
        wait_before_test()

        conf = get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)
        # The empty-host ingress now owns _default-server.conf, so bare requests go to its backend.
        assert "empty-host-svc" in conf
        assert "return 404" not in conf
        wait_and_assert_status_code(200, f"{request_url}/", verify=False)
        wait_and_assert_status_code(200, f"{request_url}/", "anything.example.com", verify=False)
        # Named-host routing for cafe.example.com is preserved while default-server ownership changes.
        wait_and_assert_status_code(200, f"{health_url}/coffee", "cafe.example.com")

        print(
            "Step 3: patch cafe-ingress to empty-host; now two empty-host ingresses collide and older cafe-ingress wins"
        )
        with open(cafe_ingress_src) as f:
            body = yaml.safe_load(f)
        del body["spec"]["rules"][0]["host"]
        replace_ingress(kube_apis.networking_v1, cafe, test_namespace, body)
        wait_before_test()

        conf = get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)
        # After cafe becomes empty-host too, the older claimant wins default-server ownership.
        assert "coffee-svc" in conf
        assert "empty-host-svc" not in conf
        # Because cafe now owns the default server, it no longer has a named ingress config file.
        assert_ingress_conf_not_exists(
            kube_apis, ic_pod, ingress_controller_prerequisites.namespace, test_namespace, cafe
        )
        # Bare /coffee requests now resolve through cafe's empty-host ownership.
        wait_and_assert_status_code(200, f"{request_url}/coffee", verify=False)
        wait_and_assert_status_code(404, f"{request_url}/", verify=False)
        # The newer empty-host ingress stays present in Kubernetes but is not applied.
        assert_event(
            "All hosts are taken by other resources",
            get_events_for_object(kube_apis.v1, test_namespace, empty_host_ingress),
        )

        print("Step 4: patch empty-host-ingress back to a named host; cafe-ingress stays the empty-host owner")
        with open(empty_host_ingress_src) as f:
            body = yaml.safe_load(f)
        body["spec"]["rules"][0]["host"] = "empty-host.example.com"
        replace_ingress(kube_apis.networking_v1, empty_host_ingress, test_namespace, body)
        wait_before_test()

        # Once it becomes named again, it gets its own config file instead of owning default-server.
        assert get_ingress_nginx_template_conf(
            kube_apis.v1,
            test_namespace,
            empty_host_ingress,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        ) is not None
        assert "empty-host-svc" in get_ingress_nginx_template_conf(
            kube_apis.v1,
            test_namespace,
            empty_host_ingress,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        # cafe still owns default-server, while the renamed ingress serves only its explicit host.
        wait_and_assert_status_code(200, f"{request_url}/coffee", verify=False)
        wait_and_assert_status_code(200, f"{health_url}/", "empty-host.example.com")

        delete_ingress(kube_apis.networking_v1, empty_host_ingress, test_namespace)
        delete_ingress(kube_apis.networking_v1, cafe, test_namespace)
        wait_before_test()

        print("Step 5: delete both ingresses; the synthetic default server is restored")

        conf = get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)
        # With no empty-host ingress left, NIC restores the synthetic 404 fallback server.
        assert "return 404" in conf
        wait_and_assert_status_code(404, f"{request_url}/", verify=False)
        wait_and_assert_status_code(200, f"{health_url}/nginx-health")


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller",
    [pytest.param({"extra_args": ["-allow-empty-ingress-host", "-health-status"]}, id="empty-host-ingress")],
    indirect=True,
)
class TestEmptyHostIngressValidation:
    @pytest.fixture(scope="class")
    def empty_host_app_setup(
        self,
        request,
        kube_apis,
        ingress_controller,
        test_namespace,
    ):
        create_items_from_yaml(kube_apis, empty_host_app_src, test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

        def fin():
            if request.config.getoption("--skip-fixture-teardown") == "no":
                delete_items_from_yaml(kube_apis, empty_host_app_src, test_namespace)

        request.addfinalizer(fin)

    def test_forbidden_annotation_rejected_for_empty_host_ingress(
        self,
        kube_apis,
        empty_host_app_setup,
        test_namespace,
    ):
        # listen-ports is rejected during validation for empty-host ingresses, so this
        # resource never becomes the default-server owner.
        ingress_name = create_ingress_from_yaml(
            kube_apis.networking_v1, test_namespace, rejected_listen_ports_ingress_src
        )
        wait_before_test()

        assert_event(
            "annotation is not supported for hostless Ingress",
            get_events_for_object(kube_apis.v1, test_namespace, ingress_name),
        )

        delete_ingress(kube_apis.networking_v1, ingress_name, test_namespace)
        wait_before_test()

"""Tests for config safety during controller startup."""

import pytest
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_event, assert_ingress_conf_not_exists, wait_and_assert_status_code
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress_from_yaml,
    delete_common_app,
    delete_ingress,
    ensure_connection_to_public_endpoint,
    get_default_server_conf,
    get_events_for_object,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

ingress_src = f"{TEST_DATA}/config-rollback/ingress/ingress.yaml"
ingress_2_src = f"{TEST_DATA}/config-rollback/ingress/ingress-2.yaml"
ingress_invalid_snippet_src = f"{TEST_DATA}/config-rollback/ingress/ingress-invalid-snippet.yaml"


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller",
    [{"extra_args": ["-enable-config-safety", "-enable-snippets"]}],
    indirect=True,
)
class TestConfigRollbackStartup:
    @pytest.fixture(scope="class")
    def simple_app_setup(self, request, kube_apis, test_namespace):
        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

        def fin():
            if request.config.getoption("--skip-fixture-teardown") == "no":
                delete_common_app(kube_apis, "simple", test_namespace)

        request.addfinalizer(fin)

    def test_startup_ingress_partial_exclusion(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
        simple_app_setup,
    ):
        ic_namespace = ingress_controller_prerequisites.namespace

        print("Step 1: create startup resources before the controller restart")
        valid_ingress_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_src)
        invalid_ingress_name = create_ingress_from_yaml(
            kube_apis.networking_v1, test_namespace, ingress_invalid_snippet_src
        )

        print("Step 2: kill the ingress controller pod and wait for the new pod to come up")
        old_ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        kube_apis.v1.delete_namespaced_pod(old_ic_pod_name, ic_namespace)
        wait_before_test()
        ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        assert ic_pod_name != old_ic_pod_name, "Pod was not restarted — batch startup path did not engage"
        wait_until_all_pods_are_ready(kube_apis.v1, ic_namespace)
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

        request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        print("Step 3: valid ingress serves traffic and invalid ingress is excluded")
        wait_and_assert_status_code(200, request_url, get_first_ingress_host_from_yaml(ingress_src))
        assert_ingress_conf_not_exists(
            kube_apis,
            ic_pod_name,
            ic_namespace,
            test_namespace,
            invalid_ingress_name,
        )

        print("Step 4: excluded ingress gets an error event, valid ingress does not, and the exclusion is logged")
        invalid_events = get_events_for_object(kube_apis.v1, test_namespace, invalid_ingress_name)
        assert invalid_events[-1].reason == "AddedOrUpdatedWithError"
        assert_event("but was not applied", invalid_events)
        assert_event('invalid value "invalid" in "sub_filter_once" directive', invalid_events)
        valid_events = get_events_for_object(kube_apis.v1, test_namespace, valid_ingress_name)
        assert all(event.reason != "AddedOrUpdatedWithError" for event in valid_events)
        ic_logs = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ic_namespace)
        assert "Config safety: startup batch excluded 1 resource(s)" in ic_logs

        print("Step 5: clean up the excluded ingress")
        delete_ingress(kube_apis.networking_v1, invalid_ingress_name, test_namespace)
        wait_before_test()

        print("Step 6: clean up the remaining startup resources")
        delete_ingress(kube_apis.networking_v1, valid_ingress_name, test_namespace)

    def test_startup_ingress_all_valid(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
        simple_app_setup,
    ):
        ic_namespace = ingress_controller_prerequisites.namespace

        print("Step 1: create valid startup resources before the controller restart")

        ingress_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_src)
        ingress_2_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_2_src)

        print("Step 2: kill the ingress controller pod and wait for the new pod to come up")
        old_ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        kube_apis.v1.delete_namespaced_pod(old_ic_pod_name, ic_namespace)
        wait_before_test()
        ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        assert ic_pod_name != old_ic_pod_name, "Pod was not restarted — batch startup path did not engage"
        wait_until_all_pods_are_ready(kube_apis.v1, ic_namespace)
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

        request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        print("Step 3: controller becomes Ready, both ingresses serve traffic, and no exclusions are logged")
        ic_logs = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ic_namespace)
        assert "startup batch excluded" not in ic_logs
        wait_and_assert_status_code(200, request_url, get_first_ingress_host_from_yaml(ingress_src))
        wait_and_assert_status_code(200, request_url, get_first_ingress_host_from_yaml(ingress_2_src))

        print("Step 4: valid ingresses keep their active config files and never get error events")
        for current_ingress_name in [ingress_name, ingress_2_name]:
            conf = get_ingress_nginx_template_conf(
                kube_apis.v1, test_namespace, current_ingress_name, ic_pod_name, ic_namespace
            )
            assert "server_name" in conf
            current_events = get_events_for_object(kube_apis.v1, test_namespace, current_ingress_name)
            assert all(event.reason != "AddedOrUpdatedWithError" for event in current_events)

        print("Step 5: clean up the startup ingresses")
        delete_ingress(kube_apis.networking_v1, ingress_name, test_namespace)
        delete_ingress(kube_apis.networking_v1, ingress_2_name, test_namespace)

    def test_startup_ingress_total_exclusion(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
        test_namespace,
    ):
        ic_namespace = ingress_controller_prerequisites.namespace

        print("Step 1: create the invalid ingress")
        invalid_ingress_name = create_ingress_from_yaml(
            kube_apis.networking_v1, test_namespace, ingress_invalid_snippet_src
        )

        print("Step 2: kill the ingress controller pod and inspect the latest pod state")
        old_ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        kube_apis.v1.delete_namespaced_pod(old_ic_pod_name, ic_namespace)
        wait_before_test()
        ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        assert ic_pod_name != old_ic_pod_name
        pod = kube_apis.v1.read_namespaced_pod(ic_pod_name, ic_namespace)

        print("Step 3: pod stays Running but not Ready, and default server is preserved")
        assert pod.status.phase == "Running"
        ready_condition = next(
            (condition for condition in (pod.status.conditions or []) if condition.type == "Ready"), None
        )
        assert ready_condition is not None
        assert ready_condition.status == "False"
        default_server_conf = get_default_server_conf(kube_apis.v1, ic_pod_name, ic_namespace)
        assert "server_name _" in default_server_conf
        assert "sub_filter_once invalid" not in default_server_conf
        assert_ingress_conf_not_exists(kube_apis, ic_pod_name, ic_namespace, test_namespace, invalid_ingress_name)

        print("Step 4: excluded ingress reports the error and all-excluded startup is logged")
        invalid_events = get_events_for_object(kube_apis.v1, test_namespace, invalid_ingress_name)
        assert invalid_events[-1].reason == "AddedOrUpdatedWithError"
        assert_event("but was not applied", invalid_events)
        assert_event('invalid value "invalid" in "sub_filter_once" directive', invalid_events)
        ic_logs = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ic_namespace)
        assert "Config safety: ALL 1 resource(s) excluded at startup" in ic_logs
        assert "Config safety: startup batch excluded 1 resource(s)" in ic_logs

        print("Step 5: clean up the excluded ingress")
        delete_ingress(kube_apis.networking_v1, invalid_ingress_name, test_namespace)
        wait_before_test()

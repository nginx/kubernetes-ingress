"""Startup-time config-safety tests.

These cover what happens when the Ingress Controller pod starts and immediately
faces resources whose NGINX config renders to something invalid, for example,
an Ingress with a bad snippet annotation.

The safety behaviour under test is:

* A single broken resource must not stop the controller from serving the rest.
* If EVERY user resource is broken, the pod must stay Not Ready so Kubernetes
  keeps the previous replicas alive (rolling updates don't cascade into an
  outage).
* Once the operator fixes the offending input, the pod recovers automatically
 , no manual pod restart required.
"""

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
    """Startup-path behaviour of ``-enable-config-safety``.

    Each test creates or modifies resources first, then restarts the Ingress
    Controller pod so the startup code path runs against the prepared state.
    """

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
        """One valid Ingress alongside one Ingress with a bad snippet: the
        controller isolates the broken one, becomes Ready, and serves the good
        one. The broken Ingress gets a Kubernetes ``Warning`` event describing
        the NGINX validation error; the valid Ingress gets no error event.
        """
        ic_namespace = ingress_controller_prerequisites.namespace

        print("Step 1: create one valid and one invalid Ingress")
        valid_ingress_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_src)
        invalid_ingress_name = create_ingress_from_yaml(
            kube_apis.networking_v1, test_namespace, ingress_invalid_snippet_src
        )

        print("Step 2: restart the controller pod so the startup path runs against both Ingresses")
        old_ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        kube_apis.v1.delete_namespaced_pod(old_ic_pod_name, ic_namespace)
        wait_before_test()
        ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        assert ic_pod_name != old_ic_pod_name, "new pod did not start"
        wait_until_all_pods_are_ready(kube_apis.v1, ic_namespace)
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

        request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        print("Step 3: valid Ingress serves 200; the invalid Ingress has no config on disk")
        wait_and_assert_status_code(200, request_url, get_first_ingress_host_from_yaml(ingress_src))
        assert_ingress_conf_not_exists(
            kube_apis,
            ic_pod_name,
            ic_namespace,
            test_namespace,
            invalid_ingress_name,
        )

        print("Step 4: only the invalid Ingress gets an error event; the log names it as excluded")
        invalid_events = get_events_for_object(kube_apis.v1, test_namespace, invalid_ingress_name)
        assert invalid_events[-1].reason == "AddedOrUpdatedWithError"
        assert_event("but was not applied", invalid_events)
        assert_event('invalid value "invalid" in "sub_filter_once" directive', invalid_events)
        valid_events = get_events_for_object(kube_apis.v1, test_namespace, valid_ingress_name)
        assert all(event.reason != "AddedOrUpdatedWithError" for event in valid_events)
        ic_logs = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ic_namespace)
        assert "Config safety: startup batch excluded 1 resource(s)" in ic_logs

        print("Step 5: clean up the excluded Ingress")
        delete_ingress(kube_apis.networking_v1, invalid_ingress_name, test_namespace)
        wait_before_test()

        print("Step 6: clean up the remaining startup Ingresses")
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
        """Baseline: two valid Ingresses give a clean startup — pod becomes
        Ready, both hosts serve 200, no exclusion messages appear anywhere.
        """
        ic_namespace = ingress_controller_prerequisites.namespace

        print("Step 1: create two valid Ingresses")

        ingress_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_src)
        ingress_2_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_2_src)

        print("Step 2: restart the controller pod")
        old_ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        kube_apis.v1.delete_namespaced_pod(old_ic_pod_name, ic_namespace)
        wait_before_test()
        ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        assert ic_pod_name != old_ic_pod_name, "new pod did not start"
        wait_until_all_pods_are_ready(kube_apis.v1, ic_namespace)
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )

        request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

        print("Step 3: pod is Ready, both Ingresses serve 200, no exclusion log line")
        ic_logs = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ic_namespace)
        assert "startup batch excluded" not in ic_logs
        wait_and_assert_status_code(200, request_url, get_first_ingress_host_from_yaml(ingress_src))
        wait_and_assert_status_code(200, request_url, get_first_ingress_host_from_yaml(ingress_2_src))

        print("Step 4: both Ingresses have their generated config on disk and no error events")
        for current_ingress_name in [ingress_name, ingress_2_name]:
            conf = get_ingress_nginx_template_conf(
                kube_apis.v1, test_namespace, current_ingress_name, ic_pod_name, ic_namespace
            )
            assert "server_name" in conf
            current_events = get_events_for_object(kube_apis.v1, test_namespace, current_ingress_name)
            assert all(event.reason != "AddedOrUpdatedWithError" for event in current_events)

        print("Step 5: clean up the Ingresses")
        delete_ingress(kube_apis.networking_v1, ingress_name, test_namespace)
        delete_ingress(kube_apis.networking_v1, ingress_2_name, test_namespace)

    def test_startup_ingress_total_exclusion(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
        test_namespace,
    ):
        """Every user Ingress is invalid, so the pod is deliberately held Not
        Ready, a rolling update in that state would otherwise terminate the
        last working replica and cause a full outage. The default server keeps
        answering 404 for unmatched hosts so port 80 still responds.

        Then the invalid Ingress is deleted (this is the "operator fixed the
        shared input" step). The controller reconciles, sees that nothing is
        broken anymore, marks the pod Ready and emits an INFO line saying the
        pod recovered — no manual pod restart is required.
        """
        ic_namespace = ingress_controller_prerequisites.namespace

        print("Step 1: create the only Ingress, and make it invalid")
        invalid_ingress_name = create_ingress_from_yaml(
            kube_apis.networking_v1, test_namespace, ingress_invalid_snippet_src
        )

        print("Step 2: restart the controller pod against the invalid Ingress")
        old_ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        kube_apis.v1.delete_namespaced_pod(old_ic_pod_name, ic_namespace)
        wait_before_test()
        ic_pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
        assert ic_pod_name != old_ic_pod_name
        pod = kube_apis.v1.read_namespaced_pod(ic_pod_name, ic_namespace)

        print("Step 3: pod is Running but held Not Ready; the default server is preserved")
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

        print("Step 4: the invalid Ingress carries the actual NGINX error; log shows the all-excluded startup")
        invalid_events = get_events_for_object(kube_apis.v1, test_namespace, invalid_ingress_name)
        assert invalid_events[-1].reason == "AddedOrUpdatedWithError"
        assert_event("but was not applied", invalid_events)
        assert_event('invalid value "invalid" in "sub_filter_once" directive', invalid_events)
        ic_logs = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ic_namespace)
        assert "Config safety: ALL 1 resource(s) excluded at startup" in ic_logs
        assert "Config safety: startup batch excluded 1 resource(s)" in ic_logs

        print("Step 5: delete the invalid Ingress to simulate the operator fixing the shared input")
        delete_ingress(kube_apis.networking_v1, invalid_ingress_name, test_namespace)
        wait_before_test()

        print("Step 6: pod recovers to Ready on its own; recovery log line is emitted")
        wait_until_all_pods_are_ready(kube_apis.v1, ic_namespace)
        recovered_pod = kube_apis.v1.read_namespaced_pod(ic_pod_name, ic_namespace)
        recovered_ready = next(
            (condition for condition in (recovered_pod.status.conditions or []) if condition.type == "Ready"),
            None,
        )
        assert recovered_ready is not None
        assert recovered_ready.status == "True", "pod should be Ready after the invalid Ingress was deleted"

        recovered_logs = kube_apis.v1.read_namespaced_pod_log(ic_pod_name, ic_namespace)
        assert (
            "Config safety: shared input fixed; pod now Ready (recovered from startup exclusion)" in recovered_logs
        ), "expected recovery log line after the shared input was fixed"

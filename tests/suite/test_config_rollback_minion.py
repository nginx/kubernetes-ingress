"""Tests for config rollback with mergeable Ingress (minion) resources."""

import pytest
import yaml
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    wait_and_assert_status_code,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    get_events_for_object,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    replace_ingress,
    wait_before_test,
    wait_until_all_pods_are_ready,
)

mergeable_ingress_src = f"{TEST_DATA}/config-rollback/ingress/mergeable-ingress.yaml"


@pytest.mark.ingresses
@pytest.mark.rollback
@pytest.mark.parametrize(
    "crd_ingress_controller, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-enable-config-rollback",
                    "-enable-snippets",
                    "-global-configuration=nginx-ingress/nginx-configuration",
                    "-enable-leader-election=false",
                ],
            },
            {"example": "transport-server-tcp-load-balance"},
        )
    ],
    indirect=True,
)
class TestConfigRollbackMinion:
    """Tests for rollback when patching a master or minion Ingress with an invalid snippet.

    Uses a mergeable Ingress setup (master + 2 minions).
    Parametrized by target (master/minion) and snippet value to show that regardless of
    which resource introduces the bad config, the entire master+minions group gets error events.
    """

    @pytest.fixture(scope="class")
    def mergeable_setup(
        self,
        request,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
    ):
        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        create_items_from_yaml(
            kube_apis,
            mergeable_ingress_src,
            test_namespace,
        )

        def fin():
            if request.config.getoption("--skip-fixture-teardown") == "no":
                delete_items_from_yaml(
                    kube_apis,
                    mergeable_ingress_src,
                    test_namespace,
                )
                delete_common_app(kube_apis, "simple", test_namespace)

        request.addfinalizer(fin)
        return {
            "master_name": "config-rollback-master",
            "minion1_name": "config-rollback-minion1",
            "minion2_name": "config-rollback-minion2",
            "namespace": test_namespace,
            "endpoint": ingress_controller_endpoint,
        }

    @pytest.mark.parametrize("target", ["master", "minion"])
    @pytest.mark.parametrize(
        "snippet_value,expected_error",
        [
            (
                "sub_filter_once invalid;",
                'invalid value "invalid" in "sub_filter_once" directive',
            ),
            (
                "add_header;",
                'invalid number of arguments in "add_header" directive',
            ),
        ],
    )
    def test_minion_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        mergeable_setup,
        transport_server_setup,
        test_namespace,
        target,
        snippet_value,
        expected_error,
    ):
        """Patch a master or minion with an invalid snippet — master + minions get error events, traffic rolls back."""
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)

        # Step 1: both minion paths serve traffic
        wait_and_assert_status_code(
            200,
            f"http://{mergeable_setup['endpoint'].public_ip}:{mergeable_setup['endpoint'].port}/backend1",
            "config-rollback-mergeable.example.com",
        )
        wait_and_assert_status_code(
            200,
            f"http://{mergeable_setup['endpoint'].public_ip}:{mergeable_setup['endpoint'].port}/backend2",
            "config-rollback-mergeable.example.com",
        )

        # Step 2: patch master or minion with invalid snippet
        with open(mergeable_ingress_src) as f:
            docs = list(yaml.safe_load_all(f))

        if target == "master":
            # Master: use server-snippets annotation
            master_body = docs[0]
            master_body["metadata"].setdefault("annotations", {})["nginx.org/server-snippets"] = snippet_value
            replace_ingress(kube_apis.networking_v1, mergeable_setup["master_name"], test_namespace, master_body)
        else:
            # Minion: use location-snippets annotation
            minion_body = docs[1]
            minion_body["metadata"].setdefault("annotations", {})["nginx.org/location-snippets"] = snippet_value
            replace_ingress(kube_apis.networking_v1, mergeable_setup["minion1_name"], test_namespace, minion_body)
        wait_before_test()

        # Step 3: traffic still works — rollback protected both paths
        wait_and_assert_status_code(
            200,
            f"http://{mergeable_setup['endpoint'].public_ip}:{mergeable_setup['endpoint'].port}/backend1",
            "config-rollback-mergeable.example.com",
        )
        wait_and_assert_status_code(
            200,
            f"http://{mergeable_setup['endpoint'].public_ip}:{mergeable_setup['endpoint'].port}/backend2",
            "config-rollback-mergeable.example.com",
        )
        conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            test_namespace,
            mergeable_setup["master_name"],
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert snippet_value.split(";")[0].split()[0] not in conf

        # Step 4: master event has actual nginx error and rollback confirmation
        master_events = get_events_for_object(kube_apis.v1, test_namespace, mergeable_setup["master_name"])
        latest_master = master_events[-1]
        assert latest_master.reason == "AddedOrUpdatedWithError"
        assert "but was not applied" in latest_master.message
        assert expected_error in latest_master.message
        assert "rolled back to previous working config" in latest_master.message

        # Step 5: both minions have error events
        minion1_events = get_events_for_object(kube_apis.v1, test_namespace, mergeable_setup["minion1_name"])
        latest_m1 = minion1_events[-1]
        assert latest_m1.reason == "AddedOrUpdatedWithError"
        assert "but was not applied" in latest_m1.message
        assert "rolled back to previous working config" in latest_m1.message
        assert expected_error in latest_m1.message

        minion2_events = get_events_for_object(kube_apis.v1, test_namespace, mergeable_setup["minion2_name"])
        latest_m2 = minion2_events[-1]
        assert latest_m2.reason == "AddedOrUpdatedWithError"
        assert "but was not applied" in latest_m2.message
        assert "rolled back to previous working config" in latest_m2.message
        assert expected_error in latest_m2.message

    # Step 6: restore originals
        with open(mergeable_ingress_src) as f:
            docs = list(yaml.safe_load_all(f))
        if target == "master":
            replace_ingress(kube_apis.networking_v1, mergeable_setup["master_name"], test_namespace, docs[0])
        else:
            replace_ingress(kube_apis.networking_v1, mergeable_setup["minion1_name"], test_namespace, docs[1])
        wait_before_test()

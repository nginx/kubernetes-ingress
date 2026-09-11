import time

import pytest
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_event
from suite.utils.resources_utils import (
    create_ingress_from_yaml,
    delete_ingress,
    get_e2e_run_selector,
    get_events,
    get_file_contents,
    get_first_pod_name,
)


@pytest.mark.ingresses
class TestSnippetAnnotation:
    """
    Checks if ingress snippets are enabled as a cli arg, that the value from a snippet annotation defined in an
    ingress resource is set in the nginx conf.
    """

    @pytest.mark.parametrize(
        "ingress_controller",
        [
            pytest.param({"extra_args": ["-enable-snippets=true"]}),
        ],
        indirect=["ingress_controller"],
    )
    def test_snippet_annotation_used(
        self, kube_apis, ingress_controller_prerequisites, ingress_controller, test_namespace
    ):
        file_name = f"{TEST_DATA}/annotations/standard/annotations-ingress-snippets.yaml"
        ingress_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, file_name)
        time.sleep(5)
        pod_namespace = ingress_controller_prerequisites.namespace
        pod_name = get_first_pod_name(
            kube_apis.v1,
            ingress_controller_prerequisites.namespace,
            get_e2e_run_selector(ingress_controller_prerequisites.e2e_run_id),
        )
        file_path = f"/etc/nginx/conf.d/{test_namespace}-{ingress_name}.conf"
        result_conf = get_file_contents(kube_apis.v1, file_path, pod_name, pod_namespace)
        snippet_annotation = "tcp_nodelay on;"
        assert snippet_annotation in result_conf, f"failed to find snippet ({snippet_annotation}) in nginx conf"

        # Now we assert the status of the ingress is correct
        event_text = f"Configuration for {test_namespace}/{ingress_name} was added or updated"
        events = get_events(kube_apis.v1, test_namespace)
        assert_event(event_text, events)

        delete_ingress(kube_apis.networking_v1, ingress_name, test_namespace)

    """
    Checks if ingress snippets are disabled as a cli arg, that the value of the snippet annotation on an ingress
    resource is ignored and does not get set in the nginx conf.
    """

    @pytest.mark.parametrize(
        "ingress_controller",
        [
            pytest.param({"extra_args": ["-enable-snippets=false"]}),
        ],
        indirect=["ingress_controller"],
    )
    def test_snippet_annotation_ignored(
        self, kube_apis, ingress_controller_prerequisites, ingress_controller, test_namespace
    ):
        file_name = f"{TEST_DATA}/annotations/standard/annotations-ingress-snippets.yaml"
        create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, file_name)
        time.sleep(5)

        # Now we assert the status of the ingress has correctly added a warning
        event_text = (
            f"annotations.nginx.org/server-snippets: Forbidden: snippet specified but snippets feature is not enabled"
        )
        events = get_events(kube_apis.v1, test_namespace)
        assert_event(event_text, events)

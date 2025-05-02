import time
from typing import Dict

import pytest
import yaml
from settings import TEST_DATA
from suite.utils.custom_resources_utils import get_pod_metrics
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress,
    create_ingress_controller,
    create_namespace_with_name_from_yaml,
    create_secret_from_yaml,
    delete_ingress_controller,
    delete_namespace,
    get_test_file_name,
    wait_until_all_pods_are_ready,
    write_to_json,
)
from suite.utils.vs_vsr_resources_utils import create_virtual_server

watched_namespaces = ""


def collect_metrics(request, namespace, metric_dict) -> Dict:
    """Get pod metrics and write them to a json"""

    metrics = get_pod_metrics(request, namespace)
    metric_dict[f"{request.node.name}+{time.time()}"] = metrics
    write_to_json(f"pod-metrics-{get_test_file_name(request.node.fspath)}.json", metric_dict)

    return metrics


@pytest.fixture(scope="class")
def ingress_ns_setup(
    request,
    kube_apis,
) -> None:
    """
    Create and deploy namespaces, apps and ingresses

    :param request: pytest fixture
    :param kube_apis: client apis
    """

    manifest = f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml"
    ns_count = int(request.config.getoption("--ns-count"))
    multi_ns = ""
    for i in range(1, ns_count + 1):
        watched_namespace = create_namespace_with_name_from_yaml(kube_apis.v1, f"ns-{i}", f"{TEST_DATA}/common/ns.yaml")
        multi_ns = multi_ns + f"{watched_namespace},"
        create_example_app(kube_apis, "simple", watched_namespace)
        create_secret_from_yaml(kube_apis.v1, watched_namespace, f"{TEST_DATA}/smoke/smoke-secret.yaml")
        with open(manifest) as f:
            doc = yaml.safe_load(f)
            doc["metadata"]["name"] = f"smoke-ingress-{i}"
            doc["spec"]["rules"][0]["host"] = f"smoke-{i}.example.com"
            create_ingress(kube_apis.networking_v1, watched_namespace, doc)
    global watched_namespaces
    watched_namespaces = multi_ns[:-1]
    for i in range(1, ns_count + 1):
        wait_until_all_pods_are_ready(kube_apis.v1, f"ns-{i}")

    def fin():
        for i in range(1, ns_count + 1):
            delete_namespace(kube_apis.v1, f"ns-{i}")

    request.addfinalizer(fin)


@pytest.mark.multi_ns
class TestMultipleSimpleIngress:
    """Test to output CPU/Memory perf metrics for pods with multiple namespaces (Ingresses)"""

    def test_ingress_multi_ns(
        self,
        request,
        kube_apis,
        cli_arguments,
        ingress_ns_setup,
        ingress_controller_prerequisites,
    ):
        metric_dict = {}
        namespace = ingress_controller_prerequisites.namespace
        extra_args = ["-enable-custom-resources=false", f"-watch-namespace={watched_namespaces}"]
        name = create_ingress_controller(kube_apis.v1, kube_apis.apps_v1_api, cli_arguments, namespace, extra_args)
        metrics = collect_metrics(request, namespace, metric_dict)
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)

        assert metrics


##############################################################################################################


@pytest.fixture(scope="class")
def vs_ns_setup(
    request,
    kube_apis,
    crds,
) -> None:
    """
    Create and deploy namespaces, apps and ingresses

    :param request: pytest fixture
    :param kube_apis: client apis
    :param crds: deploy Custom resource definitions
    """

    manifest = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
    ns_count = int(request.config.getoption("--ns-count"))
    multi_ns = ""
    for i in range(1, ns_count + 1):
        watched_namespace = create_namespace_with_name_from_yaml(kube_apis.v1, f"ns-{i}", f"{TEST_DATA}/common/ns.yaml")
        multi_ns = multi_ns + f"{watched_namespace},"
        create_example_app(kube_apis, "simple", watched_namespace)
        with open(manifest) as f:
            doc = yaml.safe_load(f)
            doc["metadata"]["name"] = f"virtual-server-{i}"
            doc["spec"]["host"] = f"virtual-server-{i}.example.com"
            create_virtual_server(kube_apis.custom_objects, doc, watched_namespace)
    global watched_namespaces
    watched_namespaces = multi_ns[:-1]
    for i in range(1, ns_count + 1):
        wait_until_all_pods_are_ready(kube_apis.v1, f"ns-{i}")

    def fin():
        for i in range(1, ns_count + 1):
            delete_namespace(kube_apis.v1, f"ns-{i}")

    request.addfinalizer(fin)


@pytest.mark.multi_ns
class TestMultipleVS:
    """Test to output CPU/Memory perf metrics for pods with multiple namespaces (VirtualServers)"""

    def test_vs_multi_ns(
        self,
        request,
        kube_apis,
        cli_arguments,
        vs_ns_setup,
        ingress_controller_prerequisites,
    ):
        metric_dict = {}
        namespace = ingress_controller_prerequisites.namespace
        extra_args = ["-enable-custom-resources=True", f"-watch-namespace={watched_namespaces}"]
        name = create_ingress_controller(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            cli_arguments,
            namespace,
            extra_args,
        )
        metrics = collect_metrics(request, namespace, metric_dict)
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)

        assert metrics

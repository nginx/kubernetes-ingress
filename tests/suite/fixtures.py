"""Describe project shared pytest fixtures."""

import time
import os
import pytest
import yaml

from kubernetes import config, client
from kubernetes.client import CoreV1Api, ExtensionsV1beta1Api, RbacAuthorizationV1beta1Api

from suite.kube_config_utils import ensure_context_in_config, get_current_context_name
from suite.resources_utils import create_namespace_with_name_from_yaml, delete_namespace, create_ns_and_sa_from_yaml
from suite.resources_utils import create_ingress_controller, delete_ingress_controller, configure_rbac, cleanup_rbac
from suite.resources_utils import create_service_from_yaml, get_service_node_ports, wait_for_public_ip
from suite.resources_utils import create_configmap_from_yaml, create_secret_from_yaml
from settings import ALLOWED_SERVICE_TYPES, ALLOWED_IC_TYPES, DEPLOYMENTS, TEST_DATA, ALLOWED_DEPLOYMENT_TYPES


class KubeApis:
    """
    Encapsulate all the used kubernetes-client APIs.

    Attributes:
        v1: CoreV1Api
        extensions_v1_beta1: ExtensionsV1beta1Api
        rbac_v1_beta1: RbacAuthorizationV1beta1Api
    """
    def __init__(self, v1: CoreV1Api, extensions_v1_beta1: ExtensionsV1beta1Api, rbac_v1_beta1: RbacAuthorizationV1beta1Api):
        self.v1 = v1
        self.extensions_v1_beta1 = extensions_v1_beta1
        self.rbac_v1_beta1 = rbac_v1_beta1


class PublicEndpoint:
    """
    Encapsulate the Public Endpoint info.

    Attributes:
        public_ip (str):
        port (int):
        port_ssl (int):
    """
    def __init__(self, public_ip, port=80, port_ssl=443):
        self.public_ip = public_ip
        self.port = port
        self.port_ssl = port_ssl


class IngressControllerPrerequisites:
    """
    Encapsulate shared items.

    Attributes:
        namespace (str): namespace name
        config_map (str): config_map name
    """
    def __init__(self, config_map, namespace):
        self.namespace = namespace
        self.config_map = config_map


@pytest.fixture(autouse=True)
def print_name() -> None:
    """Print out a current test name."""
    test_name = f"{os.environ.get('PYTEST_CURRENT_TEST').split(':')[2]} :: {os.environ.get('PYTEST_CURRENT_TEST').split(':')[4].split(' ')[0]}"
    print(f"\n============================= {test_name} =============================")


@pytest.fixture(scope="class")
def test_namespace(kube_apis, request) -> str:
    """
    Create a test namespace.

    :param kube_apis: client apis
    :param request: pytest fixture
    :return: str
    """
    timestamp = round(time.time() * 1000)
    print("------------------------- Create Test Namespace -----------------------------------")
    namespace = create_namespace_with_name_from_yaml(kube_apis.v1, f"test-namespace-{str(timestamp)}", f"{TEST_DATA}/common/ns.yaml")

    def fin():
        print("Delete test namespace")
        delete_namespace(kube_apis.v1, namespace)

    request.addfinalizer(fin)
    return namespace


@pytest.fixture(scope="class")
def ingress_controller(cli_arguments, kube_apis, ingress_controller_prerequisites, request) -> None:
    """
    Create Ingress Controller according to the context.

    :param cli_arguments: context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites
    :param request: pytest fixture
    :return:
    """
    namespace = ingress_controller_prerequisites.namespace
    print("------------------------- Create IC -----------------------------------")
    v1 = kube_apis.v1
    extensions_v1_beta1 = kube_apis.extensions_v1_beta1
    name = create_ingress_controller(v1, extensions_v1_beta1, cli_arguments, namespace)

    def fin():
        print("Delete IC:")
        delete_ingress_controller(extensions_v1_beta1, name, cli_arguments['deployment-type'], namespace)

    request.addfinalizer(fin)


@pytest.fixture(scope="session")
def ingress_controller_endpoint(cli_arguments, kube_apis, ingress_controller_prerequisites) -> PublicEndpoint:
    """
    Create an entry point for the IC.

    :param cli_arguments: tests context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites: common cluster context
    :return: PublicEndpoint
    """
    print("------------------------- Create Public Endpoint  -----------------------------------")
    namespace = ingress_controller_prerequisites.namespace
    if cli_arguments["service"] == "nodeport":
        service_name = create_service_from_yaml(kube_apis.v1, namespace, f"{DEPLOYMENTS}/service/nodeport.yaml")
        public_ip = cli_arguments["node-ip"]
        port, port_ssl = get_service_node_ports(kube_apis.v1, service_name, namespace)
        print(f"The Public IP: {public_ip}")
        return PublicEndpoint(public_ip, port, port_ssl)
    else:
        create_service_from_yaml(kube_apis.v1, namespace, f"{DEPLOYMENTS}/service/loadbalancer.yaml")
        public_ip = wait_for_public_ip(kube_apis.v1, namespace)
        print(f"The Public IP: {public_ip}")
        return PublicEndpoint(public_ip)


@pytest.fixture(scope="session")
def ingress_controller_prerequisites(cli_arguments, kube_apis, request) -> IngressControllerPrerequisites:
    """
    Create RBAC, SA, IC namespace and default-secret.

    :param cli_arguments: tests context
    :param kube_apis: client apis
    :param request: pytest fixture
    :return: IngressControllerPrerequisites
    """
    print("------------------------- Create IC Prerequisites  -----------------------------------")
    rbac = configure_rbac(kube_apis.rbac_v1_beta1)
    namespace = create_ns_and_sa_from_yaml(kube_apis.v1, f"{DEPLOYMENTS}/common/ns-and-sa.yaml")
    config_map_yaml = f"{DEPLOYMENTS}/common/nginx-config.yaml"
    create_configmap_from_yaml(kube_apis.v1, namespace, config_map_yaml)
    with open(config_map_yaml) as f:
        config_map = yaml.safe_load(f)
    create_secret_from_yaml(kube_apis.v1, namespace, f"{DEPLOYMENTS}/common/default-server-secret.yaml")

    def fin():
        print("Clean up prerequisites")
        delete_namespace(kube_apis.v1, namespace)
        cleanup_rbac(kube_apis.rbac_v1_beta1, rbac)

    request.addfinalizer(fin)

    return IngressControllerPrerequisites(config_map, namespace)


@pytest.fixture(scope="session")
def kube_apis(cli_arguments) -> KubeApis:
    """
    Set up kubernets-client to operate in cluster.

    :param cli_arguments: a set of command-line arguments
    :return: KubeApis
    """
    context_name = cli_arguments['context']
    kubeconfig = cli_arguments['kubeconfig']
    config.load_kube_config(config_file=kubeconfig, context=context_name, persist_config=False)
    v1 = client.CoreV1Api()
    extensions_v1_beta1 = client.ExtensionsV1beta1Api()
    rbac_v1_beta1 = client.RbacAuthorizationV1beta1Api()
    return KubeApis(v1, extensions_v1_beta1, rbac_v1_beta1)


@pytest.fixture(scope="session", autouse=True)
def cli_arguments(request) -> {}:
    """
    Verify the CLI arguments.

    :param request: pytest fixture
    :return: {context, image, image-pull-policy, deployment-type, ic-type, service, node-ip, kubeconfig}
    """
    result = {"kubeconfig": request.config.getoption("--kubeconfig")}
    assert result["kubeconfig"] != "", "Empty kubeconfig is not allowed"
    print(f"\nTests will use this kubeconfig: {result['kubeconfig']}")

    result["context"] = request.config.getoption("--context")
    if result["context"] != "":
        ensure_context_in_config(result["kubeconfig"], result["context"])
        print(f"Tests will run against: {result['context']}")
    else:
        result["context"] = get_current_context_name(result["kubeconfig"])
        print(f"Tests will use a current context: {result['context']}")

    result["image"] = request.config.getoption("--image")
    assert result["image"] != "", "Empty image is not allowed"
    print(f"Tests will use the image: {result['image']}")

    result["image-pull-policy"] = request.config.getoption("--image-pull-policy")
    assert result["image-pull-policy"] != "", "Empty image-pull-policy is not allowed"
    print(f"Tests will run with the image-pull-policy: {result['image-pull-policy']}")

    result["deployment-type"] = request.config.getoption("--deployment-type")
    assert result["deployment-type"] in ALLOWED_DEPLOYMENT_TYPES, f"Deployment type {result['deployment-type']} is not allowed"
    print(f"Tests will use the IC deployment of type: {result['deployment-type']}")

    result["ic-type"] = request.config.getoption("--ic-type")
    assert result["ic-type"] in ALLOWED_IC_TYPES, f"IC type {result['ic-type']} is not allowed"
    print(f"Tests will run against the IC of type: {result['ic-type']}")

    result["service"] = request.config.getoption("--service")
    assert result["service"] in ALLOWED_SERVICE_TYPES, f"Service {result['service']} is not allowed"
    print(f"Tests will use Service of this type: {result['service']}")
    if result['service'] == "nodeport":
        node_ip = request.config.getoption("--node-ip", None)
        assert node_ip is not None and node_ip != "", f"Service 'nodeport' requires a node-ip"
        result["node-ip"] = node_ip
        print(f"Tests will use the node-ip: {result['node-ip']}")
    return result

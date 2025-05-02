"""Describe project shared pytest fixtures."""

import os
import subprocess
import time

import pytest
import yaml
from kubernetes import client, config
from kubernetes.client import (
    ApiextensionsV1Api,
    AppsV1Api,
    CoreV1Api,
    CustomObjectsApi,
    NetworkingV1Api,
    RbacAuthorizationV1Api,
)
from kubernetes.client.rest import ApiException
from settings import ALLOWED_DEPLOYMENT_TYPES, ALLOWED_IC_TYPES, ALLOWED_SERVICE_TYPES, CRDS, DEPLOYMENTS, TEST_DATA
from suite.utils.custom_resources_utils import create_crd_from_yaml, delete_crd
from suite.utils.kube_config_utils import ensure_context_in_config, get_current_context_name
from suite.utils.resources_utils import (
    cleanup_rbac,
    configure_rbac,
    create_configmap_from_yaml,
    create_license,
    create_namespace_with_name_from_yaml,
    create_ns_and_sa_from_yaml,
    create_secret_from_yaml,
    create_service_from_yaml,
    delete_namespace,
    delete_testing_namespaces,
    get_service_node_ports,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_for_public_ip,
)
from suite.utils.yaml_utils import get_name_from_yaml


class KubeApis:
    """
    Encapsulate all the used kubernetes-client APIs.

    Attributes:
        v1: CoreV1Api
        networking_v1: NetworkingV1Api
        rbac_v1: RbacAuthorizationV1Api
        api_extensions_v1: ApiextensionsV1Api
        custom_objects: CustomObjectsApi
    """

    def __init__(
        self,
        v1: CoreV1Api,
        networking_v1: NetworkingV1Api,
        apps_v1_api: AppsV1Api,
        rbac_v1: RbacAuthorizationV1Api,
        api_extensions_v1: ApiextensionsV1Api,
        custom_objects: CustomObjectsApi,
    ):
        self.v1 = v1
        self.networking_v1 = networking_v1
        self.apps_v1_api = apps_v1_api
        self.rbac_v1 = rbac_v1
        self.api_extensions_v1 = api_extensions_v1
        self.custom_objects = custom_objects


class PublicEndpoint:
    """
    Encapsulate the Public Endpoint info.

    Attributes:
        public_ip (str):
        port (int):
        port_ssl (int):
    """

    def __init__(
        self,
        public_ip,
        port=80,
        port_ssl=443,
        api_port=8080,
        metrics_port=9113,
        tcp_server_port=3333,
        udp_server_port=3334,
        service_insight_port=9114,
        custom_ssl_port=8443,
        custom_http=8085,
        custom_https=8445,
    ):
        self.public_ip = public_ip
        self.port = port
        self.port_ssl = port_ssl
        self.api_port = api_port
        self.metrics_port = metrics_port
        self.tcp_server_port = tcp_server_port
        self.udp_server_port = udp_server_port
        self.service_insight_port = service_insight_port
        self.custom_ssl_port = custom_ssl_port
        self.custom_http = custom_http
        self.custom_https = custom_https


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
def test_namespace(kube_apis) -> str:
    """
    Create a test namespace.

    :param kube_apis: client apis
    :return: str
    """
    timestamp = round(time.time() * 1000)
    print("------------------------- Create Test Namespace -----------------------------------")
    namespace = create_namespace_with_name_from_yaml(
        kube_apis.v1, f"test-namespace-{str(timestamp)}", f"{TEST_DATA}/common/ns.yaml"
    )
    return namespace


@pytest.fixture(scope="session", autouse=True)
def delete_test_namespaces(kube_apis, request) -> None:
    """
    Delete all the testing namespaces.

    Testing namespaces are the ones starting with "test-namespace-"

    :param kube_apis: client apis
    :param request: pytest fixture
    :return: str
    """

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("------------------------- Delete All Test Namespaces -----------------------------------")
            delete_testing_namespaces(kube_apis.v1)

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
        public_ip = cli_arguments["node-ip"]
        print(f"The Public IP: {public_ip}")
        service_name = create_service_from_yaml(
            kube_apis.v1,
            namespace,
            f"{TEST_DATA}/common/service/nodeport-with-additional-ports.yaml",
        )
        (
            port,
            port_ssl,
            api_port,
            metrics_port,
            tcp_server_port,
            udp_server_port,
            service_insight_port,
            custom_ssl_port,
            custom_http,
            custom_https,
        ) = get_service_node_ports(kube_apis.v1, service_name, namespace)
        return PublicEndpoint(
            public_ip,
            port,
            port_ssl,
            api_port,
            metrics_port,
            tcp_server_port,
            udp_server_port,
            service_insight_port,
            custom_ssl_port,
            custom_http,
            custom_https,
        )
    else:
        create_service_from_yaml(
            kube_apis.v1,
            namespace,
            f"{TEST_DATA}/common/service/loadbalancer-with-additional-ports.yaml",
        )
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
    rbac = configure_rbac(kube_apis.rbac_v1)
    namespace = create_ns_and_sa_from_yaml(kube_apis.v1, f"{DEPLOYMENTS}/common/ns-and-sa.yaml")
    print("Create IngressClass resources:")
    subprocess.run(["kubectl", "apply", "-f", f"{DEPLOYMENTS}/common/ingress-class.yaml"])
    subprocess.run(
        [
            "kubectl",
            "apply",
            "-f",
            f"{TEST_DATA}/ingress-class/resource/custom-ingress-class-res.yaml",
        ]
    )
    config_map_yaml = f"{DEPLOYMENTS}/common/nginx-config.yaml"
    mgmt_config_map_yaml = f"{DEPLOYMENTS}/common/plus-mgmt-configmap.yaml"
    create_configmap_from_yaml(kube_apis.v1, namespace, config_map_yaml)
    mgmt_config_map_yaml = f"{DEPLOYMENTS}/common/plus-mgmt-configmap.yaml"
    with open(config_map_yaml) as f:
        config_map = yaml.safe_load(f)

    create_secret_from_yaml(kube_apis.v1, namespace, f"{TEST_DATA}/common/default-server-secret.yaml")
    # setup Plus JWT configuration
    if cli_arguments["ic-type"] == "nginx-plus-ingress":
        print("Create Plus JWT License:")
        license_name = create_license(kube_apis.v1, namespace, cli_arguments["plus-jwt"])
        print(f"License created: {license_name}")
        create_configmap_from_yaml(kube_apis.v1, namespace, mgmt_config_map_yaml)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up prerequisites")
            delete_namespace(kube_apis.v1, namespace)
            print("Delete IngressClass resources:")
            subprocess.run(["kubectl", "delete", "-f", f"{DEPLOYMENTS}/common/ingress-class.yaml"])
            subprocess.run(
                [
                    "kubectl",
                    "delete",
                    "-f",
                    f"{TEST_DATA}/ingress-class/resource/custom-ingress-class-res.yaml",
                ]
            )
            cleanup_rbac(kube_apis.rbac_v1, rbac)

    request.addfinalizer(fin)

    return IngressControllerPrerequisites(config_map, namespace)


@pytest.fixture(scope="session")
def kube_apis(cli_arguments) -> KubeApis:
    """
    Set up kubernetes-client to operate in cluster.

    :param cli_arguments: a set of command-line arguments
    :return: KubeApis
    """
    context_name = cli_arguments["context"]
    kubeconfig = cli_arguments["kubeconfig"]
    config.load_kube_config(config_file=kubeconfig, context=context_name, persist_config=False)
    v1 = client.CoreV1Api()
    networking_v1 = client.NetworkingV1Api()
    apps_v1_api = client.AppsV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()
    api_extensions_v1 = client.ApiextensionsV1Api()
    custom_objects = client.CustomObjectsApi()
    return KubeApis(v1, networking_v1, apps_v1_api, rbac_v1, api_extensions_v1, custom_objects)


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
    assert (
        result["deployment-type"] in ALLOWED_DEPLOYMENT_TYPES
    ), f"Deployment type {result['deployment-type']} is not allowed"
    print(f"Tests will use the IC deployment of type: {result['deployment-type']}")

    result["ic-type"] = request.config.getoption("--ic-type")
    assert result["ic-type"] in ALLOWED_IC_TYPES, f"IC type {result['ic-type']} is not allowed"
    print(f"Tests will run against the IC of type: {result['ic-type']}")
    if result["ic-type"] == "nginx-plus-ingress":
        print(f"Tests will use the Plus JWT")
        result["plus-jwt"] = request.config.getoption("--plus-jwt")

    result["replicas"] = request.config.getoption("--replicas")
    print(f"Number of pods spun up will be : {result['replicas']}")

    result["service"] = request.config.getoption("--service")
    assert result["service"] in ALLOWED_SERVICE_TYPES, f"Service {result['service']} is not allowed"
    print(f"Tests will use Service of this type: {result['service']}")
    if result["service"] == "nodeport":
        node_ip = request.config.getoption("--node-ip", None)
        assert node_ip is not None and node_ip != "", f"Service 'nodeport' requires a node-ip"
        result["node-ip"] = node_ip
        print(f"Tests will use the node-ip: {result['node-ip']}")
    result["skip-fixture-teardown"] = request.config.getoption("--skip-fixture-teardown")
    assert result["skip-fixture-teardown"] == "yes" or result["skip-fixture-teardown"] == "no"
    print(
        f"All test fixtures be available for debugging: {result['skip-fixture-teardown']}, /// ONLY USE THIS OPTION FOR INDIVIDUAL TEST DEBUGGING ///"
    )
    return result


@pytest.fixture(scope="class")
def crds(kube_apis, request) -> None:
    """
    Create an Ingress Controller with CRD enabled.

    :param kube_apis: client apis
    :param request: pytest fixture to parametrize this method
        {type: complete|rbac-without-vs, extra_args: }
        'type' type of test pre-configuration
        'extra_args' list of IC cli arguments
    :return:
    """
    vs_crd_name = get_name_from_yaml(f"{CRDS}/k8s.nginx.org_virtualservers.yaml")
    vsr_crd_name = get_name_from_yaml(f"{CRDS}/k8s.nginx.org_virtualserverroutes.yaml")
    pol_crd_name = get_name_from_yaml(f"{CRDS}/k8s.nginx.org_policies.yaml")
    ts_crd_name = get_name_from_yaml(f"{CRDS}/k8s.nginx.org_transportservers.yaml")
    gc_crd_name = get_name_from_yaml(f"{CRDS}/k8s.nginx.org_globalconfigurations.yaml")

    try:
        print("------------------------- Register CRDs -----------------------------------")
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            vs_crd_name,
            f"{CRDS}/k8s.nginx.org_virtualservers.yaml",
        )
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            vsr_crd_name,
            f"{CRDS}/k8s.nginx.org_virtualserverroutes.yaml",
        )
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            pol_crd_name,
            f"{CRDS}/k8s.nginx.org_policies.yaml",
        )
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            ts_crd_name,
            f"{CRDS}/k8s.nginx.org_transportservers.yaml",
        )
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            gc_crd_name,
            f"{CRDS}/k8s.nginx.org_globalconfigurations.yaml",
        )
    except ApiException as ex:
        # Finalizer method doesn't start if fixture creation was incomplete, ensure clean up here
        print(f"Failed to complete CRD IC fixture: {ex}\nClean up the cluster as much as possible.")
        delete_crd(kube_apis.api_extensions_v1, vs_crd_name)
        delete_crd(kube_apis.api_extensions_v1, vsr_crd_name)
        delete_crd(kube_apis.api_extensions_v1, pol_crd_name)
        delete_crd(kube_apis.api_extensions_v1, ts_crd_name)
        delete_crd(kube_apis.api_extensions_v1, gc_crd_name)
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            delete_crd(kube_apis.api_extensions_v1, vs_crd_name)
            delete_crd(kube_apis.api_extensions_v1, vsr_crd_name)
            delete_crd(kube_apis.api_extensions_v1, pol_crd_name)
            delete_crd(kube_apis.api_extensions_v1, ts_crd_name)
            delete_crd(kube_apis.api_extensions_v1, gc_crd_name)

    request.addfinalizer(fin)


@pytest.fixture(scope="function")
def restore_configmap(request, kube_apis, ingress_controller_prerequisites, test_namespace) -> None:
    """
    Return ConfigMap to the initial state after the test.

    :param request: internal pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_prerequisites:
    :param test_namespace: str
    :return:
    """

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def create_certmanager(request):
    """
    Create Cert-manager.

    :param kube_apis: client apis
    :param request: pytest fixture
    """
    issuer_name = request.param.get("issuer_name")
    cm_yaml = f"{TEST_DATA}/virtual-server-certmanager/certmanager.yaml"

    create_generic_from_yaml(cm_yaml, request)
    wait_before_test(120)
    create_issuer(issuer_name, request)


def create_issuer(issuer_name, request):
    """
    Create Cert-manager.

    :param kube_apis: client apis
    :param issuer_name: the name of the issuer
    :param request: pytest fixture
    """
    issuer_yaml = f"{TEST_DATA}/virtual-server-certmanager/{issuer_name}.yaml"

    print("------------------------- Deploy CertManager in the cluster -----------------------------------")
    create_generic_from_yaml(issuer_yaml, request)


def create_generic_from_yaml(file_path, request):
    """
    Create an object using a path to the yaml file.

    :param kube_apis: client apis
    :param request: pytest fixture
    """

    subprocess.run(["kubectl", "apply", "-f", f"{file_path}"])

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up resources from {file_path}:")
            subprocess.run(["kubectl", "delete", "-f", f"{file_path}"])

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def create_externaldns(request):
    """
    Create externalDNS deployment.

    :param kube_apis: client apis
    :param request: pytest fixture
    """
    ed_yaml = f"{TEST_DATA}/virtual-server-external-dns/external-dns.yaml"

    print("------------------------- Deploy ExternalDNS in the cluster -----------------------------------")
    create_generic_from_yaml(ed_yaml, request)

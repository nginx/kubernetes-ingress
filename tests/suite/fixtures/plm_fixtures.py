"""Describe pytest fixtures for the F5 WAF Policy Controller (PLM) integration."""

import base64
import json
import subprocess

import pytest
from kubernetes.client import CoreV1Api, CustomObjectsApi
from kubernetes.client.rest import ApiException
from settings import NGX_REG, PLM_CHART_VERSION
from suite.utils.custom_resources_utils import delete_crd
from suite.utils.resources_utils import (
    cleanup_rbac,
    configure_rbac_with_ap,
    create_ingress_controller_wafv5,
    create_namespace,
    delete_ingress_controller,
    delete_namespace,
    ensure_connection_to_public_endpoint,
    wait_until_all_pods_are_ready,
)

PLM_CHART = "f5-waf-policy-controller"
PLM_CHART_REPO = "https://helm.nginx.com/stable"
PLM_RELEASE = "plm"
PLM_NAMESPACE = "plm"
# The chart prefixes its SeaweedFS objects with "<release>-f5-waf".
PLM_FULLNAME = f"{PLM_RELEASE}-f5-waf"
AP_GROUP = "appprotect.f5.com"
# Installed from the chart's crds/ directory, which helm uninstall leaves behind.
PLM_CRD_PLURALS = ["appolicies", "aplogconfs", "apusersigs", "apsignatures"]
REG_SECRET = "regcred"


class PLMSetup:
    """
    Encapsulate the PLM installation details.

    Attributes:
        namespace (str): namespace PLM is installed in
        storage_url (str): SeaweedFS S3 endpoint, the -plm-storage-url value
        credentials_secret (str): namespace/name of the S3 credentials Secret
    """

    def __init__(self, namespace, storage_url, credentials_secret):
        self.namespace = namespace
        self.storage_url = storage_url
        self.credentials_secret = credentials_secret


def helm(cli_arguments, *args, check=True) -> None:
    """
    Run helm against the kubeconfig and context the tests use.

    :param cli_arguments: pytest context
    :param args: helm arguments
    :param check: raise if helm exits with an error
    """
    cmd = ["helm", "--kubeconfig", cli_arguments["kubeconfig"], "--kube-context", cli_arguments["context"], *args]
    print(f"Run: {' '.join(cmd)}")
    subprocess.run(cmd, check=check)


def create_registry_secret(v1: CoreV1Api, namespace, user, token) -> None:
    """
    Create the pull Secret for NGX_REG, which hosts the WAF and PLM images. Keep the Secret if it already exists.

    :param v1: CoreV1Api
    :param namespace: namespace name
    :param user: registry user
    :param token: registry token
    """
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    docker_config = json.dumps({"auths": {NGX_REG: {"username": user, "password": token, "auth": auth}}})
    body = {
        "metadata": {"name": REG_SECRET},
        "type": "kubernetes.io/dockerconfigjson",
        "data": {".dockerconfigjson": base64.b64encode(docker_config.encode()).decode()},
    }
    try:
        v1.create_namespaced_secret(namespace, body)
        print(f"Secret {REG_SECRET} created in namespace {namespace}")
    except ApiException as ex:
        if ex.status != 409:
            raise


def remove_plm_finalizers(custom_objects: CustomObjectsApi) -> None:
    """
    Clear finalizers on the appprotect.f5.com resources.

    Once PLM is uninstalled nothing removes them, so they block deleting the resources, the CRDs and namespaces.

    :param custom_objects: CustomObjectsApi
    """
    for plural in PLM_CRD_PLURALS:
        try:
            items = custom_objects.list_cluster_custom_object(AP_GROUP, "v1", plural)["items"]
        except ApiException as ex:
            if ex.status == 404:
                continue
            raise
        for item in items:
            meta = item["metadata"]
            if meta.get("finalizers"):
                print(f"Remove finalizers from {plural} {meta['namespace']}/{meta['name']}")
                custom_objects.patch_namespaced_custom_object(
                    AP_GROUP, "v1", meta["namespace"], plural, meta["name"], {"metadata": {"finalizers": None}}
                )


@pytest.fixture(scope="session")
def plm_setup(request, kube_apis, cli_arguments) -> PLMSetup:
    """
    Install PLM from its Helm chart, with images from NGX_REG and SeaweedFS TLS disabled.

    The chart installs the appprotect.f5.com/v1 CRDs, so the cluster must not have any appprotect.f5.com CRDs yet.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param cli_arguments: pytest context
    :return: PLMSetup
    """
    existing = [
        crd.metadata.name
        for crd in kube_apis.api_extensions_v1.list_custom_resource_definition().items
        if crd.spec.group == AP_GROUP
    ]
    if existing:
        pytest.fail(f"The PLM chart must install the {AP_GROUP} CRDs, but these exist already: {existing}")

    print("------------------------- Install PLM -----------------------------------")
    create_namespace(kube_apis.v1, {"metadata": {"name": PLM_NAMESPACE}})

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("------------------------- Uninstall PLM -----------------------------------")
            helm(cli_arguments, "uninstall", PLM_RELEASE, "--namespace", PLM_NAMESPACE, check=False)
            remove_plm_finalizers(kube_apis.custom_objects)
            for plural in PLM_CRD_PLURALS:
                try:
                    delete_crd(kube_apis.api_extensions_v1, f"{plural}.{AP_GROUP}")
                except ApiException as ex:
                    if ex.status != 404:
                        raise
            delete_namespace(kube_apis.v1, PLM_NAMESPACE)

    request.addfinalizer(fin)

    create_registry_secret(
        kube_apis.v1,
        PLM_NAMESPACE,
        request.config.getoption("--docker-registry-user"),
        request.config.getoption("--docker-registry-token"),
    )
    values = {
        "imagePullSecrets[0].name": REG_SECRET,
        "seaweedfs-operator.image.pullSecrets": REG_SECRET,
        "policyController.image.repository": f"{NGX_REG}/nap/waf-policy-controller",
        "compiler.image.repository": f"{NGX_REG}/nap/waf-compiler",
        "seaweedfsOperatorConfig.seaweedfs.image.repository": f"{NGX_REG}/nap/waf-seaweedfs",
        "seaweedfs-operator.image.repository": f"{NGX_REG}/nap/waf-seaweedfs-operator",
        "seaweedfsOperatorConfig.seaweedfs.certificates.enabled": "false",
    }
    set_args = [arg for key, value in values.items() for arg in ("--set", f"{key}={value}")]
    helm(
        cli_arguments,
        "install",
        PLM_RELEASE,
        PLM_CHART,
        "--repo",
        PLM_CHART_REPO,
        "--version",
        PLM_CHART_VERSION,
        "--namespace",
        PLM_NAMESPACE,
        *set_args,
        "--wait",
        "--timeout",
        "10m",
    )
    # helm --wait does not cover the SeaweedFS pods, which the operator creates.
    wait_until_all_pods_are_ready(kube_apis.v1, PLM_NAMESPACE, None)

    return PLMSetup(
        PLM_NAMESPACE,
        f"http://{PLM_FULLNAME}-seaweed-filer.{PLM_NAMESPACE}.svc.cluster.local:8333",
        f"{PLM_NAMESPACE}/{PLM_FULLNAME}-seaweedfs-auth",
    )


@pytest.fixture(scope="class")
def crd_ingress_controller_with_plm(
    cli_arguments, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint, request, crds, plm_setup
) -> None:
    """
    Create an Ingress Controller with WAF v5 that fetches its bundles from PLM storage.

    Unlike crd_ingress_controller_with_waf_v5, it never registers the appprotect.f5.com CRDs, because PLM owns them.

    :param cli_arguments: pytest context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites:
    :param ingress_controller_endpoint:
    :param request: pytest fixture to parametrize this method
        {extra_args: }
        'extra_args' list of IC arguments
    :param crds: the common IC crds
    :param plm_setup: the PLM installation
    :return:
    """
    namespace = ingress_controller_prerequisites.namespace
    name = "nginx-ingress"
    extra_args = [
        "-enable-app-protect",
        f"-plm-storage-url={plm_setup.storage_url}",
        f"-plm-storage-credentials-secret={plm_setup.credentials_secret}",
        *getattr(request, "param", {}).get("extra_args", []),
    ]
    create_registry_secret(
        kube_apis.v1,
        namespace,
        request.config.getoption("--docker-registry-user"),
        request.config.getoption("--docker-registry-token"),
    )
    print("--------------------Create roles and bindings for AppProtect------------------------")
    rbac = configure_rbac_with_ap(kube_apis.rbac_v1)
    try:
        print("------------------------- Create IC with PLM -----------------------------------")
        name = create_ingress_controller_wafv5(
            kube_apis.v1, kube_apis.apps_v1_api, cli_arguments, namespace, REG_SECRET, extra_args
        )
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )
    except Exception as ex:
        print(f"Failed to complete PLM IC fixture: {ex}\nClean up the cluster as much as possible.")
        cleanup_rbac(kube_apis.rbac_v1, rbac)
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Remove ap-rbac")
            cleanup_rbac(kube_apis.rbac_v1, rbac)
            print("Delete IC:")
            delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)

    request.addfinalizer(fin)

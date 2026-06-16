"""Describe project shared pytest fixtures related to setup of ingress controller."""

import os
import subprocess
import time

import pytest
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from settings import DEPLOYMENTS, NGX_REG, TEST_DATA
from suite.utils.resources_utils import (
    create_dos_arbitrator,
    create_ingress_controller,
    create_ingress_controller_wafv5,
    create_items_from_yaml,
    delete_dos_arbitrator,
    delete_ingress_controller,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    get_first_pod_name,
    patch_rbac,
    replace_configmap_from_yaml,
    wait_until_all_pods_are_ready,
)

"""Fixtures for creating Ingress Controller instances"""


@pytest.fixture(scope="class")
def ingress_controller(cli_arguments, kube_apis, ingress_controller_prerequisites, request) -> str:
    """
    Create Ingress Controller according to the context.

    :param cli_arguments: context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites
    :param request: pytest fixture
    :return: IC name
    """
    namespace = ingress_controller_prerequisites.namespace
    name = "nginx-ingress"
    print("------------------------- Create IC without CRDs -----------------------------------")
    try:
        extra_args = request.param.get("extra_args", None)
        extra_args.append("-enable-custom-resources=false")
    except AttributeError:
        print("IC will start with CRDs disabled and without any additional cli-arguments")
        extra_args = ["-enable-custom-resources=false"]
    try:
        name = create_ingress_controller(kube_apis.v1, kube_apis.apps_v1_api, cli_arguments, namespace, extra_args)
    except ApiException as ex:
        # Finalizer doesn't start if fixture creation was incomplete, ensure clean up here
        print(f"Failed to complete IC fixture: {ex}\nClean up the cluster as much as possible.")
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete IC:")
            delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)

    request.addfinalizer(fin)

    return name


@pytest.fixture(scope="class")
def crd_ingress_controller(
    cli_arguments, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint, request, crds
) -> None:
    """
    Create an Ingress Controller with CRD enabled.

    :param crds: the common ingress controller crds.
    :param cli_arguments: pytest context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites
    :param ingress_controller_endpoint:
    :param request: pytest fixture to parametrize this method
        {type: complete|rbac-without-vs,
        'extra_args': list of IC cli arguments }
    :return:
    """
    namespace = ingress_controller_prerequisites.namespace
    name = "nginx-ingress"
    orig_port = 0

    try:
        print("------------------------- Update ClusterRole -----------------------------------")
        if request.param["type"] == "rbac-without-vs":
            patch_rbac(kube_apis.rbac_v1, f"{TEST_DATA}/virtual-server/rbac-without-vs.yaml")
        print("------------------------- Create IC -----------------------------------")
        name = create_ingress_controller(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            cli_arguments,
            namespace,
            request.param.get("extra_args", None),
        )
        if request.param["type"] == "tls-passthrough-custom-port":
            orig_port = ingress_controller_endpoint.port_ssl
            ingress_controller_endpoint.port_ssl = ingress_controller_endpoint.custom_ssl_port
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )
    except ApiException:
        # Finalizer method doesn't start if fixture creation was incomplete, ensure clean up here
        print("Restore the ClusterRole:")
        patch_rbac(kube_apis.rbac_v1, f"{DEPLOYMENTS}/rbac/rbac.yaml")
        print("Remove the IC:")
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Restore the ClusterRole:")
            patch_rbac(kube_apis.rbac_v1, f"{DEPLOYMENTS}/rbac/rbac.yaml")
            print("Remove the IC:")
            delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
            if request.param["type"] == "tls-passthrough-custom-port":
                ingress_controller_endpoint.port_ssl = orig_port

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def crd_ingress_controller_with_ap(
    cli_arguments,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    request,
    crds,
    ap_crds,
    ap_rbac,
) -> None:
    """
    Create an Ingress Controller with AppProtect CRD enabled.

    CRD registration and RBAC are managed by the session-scoped ap_crds and ap_rbac fixtures.

    :param crds: the common IC crds (session-scoped).
    :param ap_crds: the AppProtect CRDs (session-scoped).
    :param ap_rbac: the AppProtect RBAC (session-scoped).
    :param cli_arguments: pytest context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites
    :param ingress_controller_endpoint:
    :param request: pytest fixture to parametrize this method
        {extra_args: }
        'extra_args' list of IC arguments
    :return:
    """
    namespace = ingress_controller_prerequisites.namespace
    name = "nginx-ingress"
    try:
        print("------------------------- Create IC -----------------------------------")
        name = create_ingress_controller(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            cli_arguments,
            namespace,
            request.param.get("extra_args", None),
        )
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )
    except Exception as ex:
        print(f"Failed to complete AP IC fixture: {ex}\nClean up the cluster as much as possible.")
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Remove the IC:")
            delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def crd_ingress_controller_with_waf_v5(
    cli_arguments,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    request,
    crds,
    ap_crds,
    ap_rbac,
) -> None:
    """
    Create an Ingress Controller with WAF v5.

    CRD registration and RBAC are managed by the session-scoped crds, ap_crds and ap_rbac fixtures.

    :param cli_arguments: pytest context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites
    :param ingress_controller_endpoint:
    :param request: pytest fixture to parametrize this method
        {type: complete|rorfs, extra_args: }
        'extra_args' list of IC arguments
    :param crds: the common IC crds (session-scoped).
    :param ap_crds: the AppProtect CRDs (session-scoped).
    :param ap_rbac: the AppProtect RBAC (session-scoped).
    :return:
    """
    dir = f"{TEST_DATA}/ap-waf-v5"  # directory with WAFv5 bundle generated in setup-smoke workflow
    assert os.path.isfile(f"{dir}/wafv5.tgz")

    namespace = ingress_controller_prerequisites.namespace
    name = "nginx-ingress"
    user = request.config.getoption("--docker-registry-user")
    token = request.config.getoption("--docker-registry-token")
    subprocess.run(
        [
            "kubectl",
            "create",
            "secret",
            "-n",
            f"{namespace}",
            "docker-registry",
            "regcred",
            f"--docker-server={NGX_REG}",
            f"--docker-username={user}",
            f"--docker-password={token}",
        ]
    )

    try:
        if request.param["type"] == "rorfs":  # WAFv5 with readOnlyRootFileSystem
            name = create_ingress_controller_wafv5(
                kube_apis.v1,
                kube_apis.apps_v1_api,
                cli_arguments,
                namespace,
                "regcred",
                request.param.get("extra_args", None),
                True,
            )
        else:
            name = create_ingress_controller_wafv5(
                kube_apis.v1,
                kube_apis.apps_v1_api,
                cli_arguments,
                namespace,
                "regcred",
                request.param.get("extra_args", None),
            )

        print("------------------------- Copy WAFv5 bundle into IC pod -----------------------------------")
        try:
            with open(f"{dir}/wafv5.tgz", "rb") as f:
                file_content = f.read()
            exec_command = ["sh", "-c", "cat > /etc/app_protect/bundles/wafv5.tgz"]
            pod_name = get_first_pod_name(kube_apis.v1, namespace)
            container_name = "nginx-plus-ingress"
            resp = stream(
                kube_apis.v1.connect_get_namespaced_pod_exec,
                pod_name,
                namespace,
                container=container_name,
                command=exec_command,
                stderr=True,
                stdin=True,
                stdout=True,
                tty=False,
                _preload_content=False,
            )
            resp.write_stdin(file_content)
            resp.close()
        except Exception as ex:
            pytest.fail(f"Failed to copy WAFv5 bundle into the pod: {ex}")

        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )
    except Exception as ex:
        print(f"Failed to complete WAF v5 IC fixture: {ex}\nClean up the cluster as much as possible.")
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete IC:")
            delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def crd_ingress_controller_with_dos(
    cli_arguments,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    request,
    crds,
    dos_crds,
    dos_rbac,
) -> None:
    """
    Create an Ingress Controller with DoS CRDs enabled.

    CRD registration and RBAC are managed by the session-scoped dos_crds and dos_rbac fixtures.

    :param crds: the common IC crds (session-scoped).
    :param dos_crds: the DoS CRDs (session-scoped).
    :param dos_rbac: the DoS RBAC (session-scoped).
    :param cli_arguments: pytest context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites
    :param ingress_controller_endpoint:
    :param request: pytest fixture to parametrize this method
        {extra_args: }
        'extra_args' list of IC arguments
    :return:
    """
    namespace = ingress_controller_prerequisites.namespace
    name = "nginx-ingress"

    try:
        print("------------------------- Create syslog svc -----------------------")
        src_syslog_yaml = f"{TEST_DATA}/dos/dos-syslog.yaml"
        create_items_from_yaml(kube_apis, src_syslog_yaml, namespace)

        print("------------------------- Create accesslog svc -----------------------")
        src_accesslog_yaml = f"{TEST_DATA}/dos/dos-accesslog.yaml"
        create_items_from_yaml(kube_apis, src_accesslog_yaml, namespace)

        before = time.time()
        wait_until_all_pods_are_ready(kube_apis.v1, namespace)
        after = time.time()
        print(f"All pods came up in {int(after-before)} seconds")

        print("------------------------- Create dos arbitrator -----------------------")
        dos_arbitrator_name = create_dos_arbitrator(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            namespace,
            f"{DEPLOYMENTS}/deployment/appprotect-dos-arb.yaml",
            f"{DEPLOYMENTS}/service/appprotect-dos-arb-svc.yaml",
        )

        print("------------------------- Create IC -----------------------------------")
        name = create_ingress_controller(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            cli_arguments,
            namespace,
            request.param.get("extra_args", None),
        )
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )
    except Exception as ex:
        print(f"Failed to complete DoS IC fixture: {ex}\nClean up the cluster as much as possible.")
        delete_dos_arbitrator(kube_apis.v1, kube_apis.apps_v1_api, dos_arbitrator_name, namespace)
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
        delete_items_from_yaml(kube_apis, src_syslog_yaml, namespace)
        delete_items_from_yaml(kube_apis, src_accesslog_yaml, namespace)
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Remove dos arbitrator:")
            delete_dos_arbitrator(kube_apis.v1, kube_apis.apps_v1_api, dos_arbitrator_name, namespace)
            print("Remove the IC:")
            delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
            print("Remove the syslog svc:")
            delete_items_from_yaml(kube_apis, src_syslog_yaml, namespace)
            print("Remove the accesslog svc:")
            delete_items_from_yaml(kube_apis, src_accesslog_yaml, namespace)

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def crd_ingress_controller_with_ed(
    cli_arguments, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint, request, crds, ed_crds
) -> None:
    """
    Create an Ingress Controller with ExternalDNS CRD enabled.

    CRD registration is managed by the session-scoped ed_crds fixture.

    :param crds: the common IC crds (session-scoped).
    :param ed_crds: the DNSEndpoint CRD (session-scoped).
    :param cli_arguments: pytest context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites
    :param ingress_controller_endpoint:
    :param request: pytest fixture to parametrize this method
        {extra_args: }
        'extra_args' list of IC cli arguments
    :return:
    """
    namespace = ingress_controller_prerequisites.namespace
    name = "nginx-ingress"

    try:
        print("------------------------- Create IC -----------------------------------")
        name = create_ingress_controller(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            cli_arguments,
            namespace,
            request.param.get("extra_args", None),
        )
        ensure_connection_to_public_endpoint(
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.port,
            ingress_controller_endpoint.port_ssl,
        )
        print("---------------- Replace ConfigMap with external-status-address --------------------")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/virtual-server-external-dns/nginx-config.yaml",
        )
    except ApiException:
        print("Remove the IC:")
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{DEPLOYMENTS}/common/nginx-config.yaml",
        )
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Remove the IC:")
            delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )

    request.addfinalizer(fin)

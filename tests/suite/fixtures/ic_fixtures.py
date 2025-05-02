"""Describe project shared pytest fixtures related to setup of ingress controller."""

import os
import subprocess
import time

import pytest
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from settings import CRDS, DEPLOYMENTS, NGX_REG, TEST_DATA
from suite.utils.custom_resources_utils import create_crd_from_yaml, delete_crd
from suite.utils.resources_utils import (
    cleanup_rbac,
    configure_rbac_with_ap,
    configure_rbac_with_dos,
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
from suite.utils.yaml_utils import get_name_from_yaml


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
    cli_arguments, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint, request, crds
) -> None:
    """
    Create an Ingress Controller with AppProtect CRD enabled.
    :param crds: the common IC crds.
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
        print("--------------------Create roles and bindings for AppProtect------------------------")
        rbac = configure_rbac_with_ap(kube_apis.rbac_v1)

        print("------------------------- Register AP CRD -----------------------------------")
        ap_pol_crd_name = get_name_from_yaml(f"{CRDS}/appprotect.f5.com_appolicies.yaml")
        ap_log_crd_name = get_name_from_yaml(f"{CRDS}/appprotect.f5.com_aplogconfs.yaml")
        ap_uds_crd_name = get_name_from_yaml(f"{CRDS}/appprotect.f5.com_apusersigs.yaml")
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            ap_pol_crd_name,
            f"{CRDS}/appprotect.f5.com_appolicies.yaml",
        )
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            ap_log_crd_name,
            f"{CRDS}/appprotect.f5.com_aplogconfs.yaml",
        )
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            ap_uds_crd_name,
            f"{CRDS}/appprotect.f5.com_apusersigs.yaml",
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
        print(f"Failed to complete CRD IC fixture: {ex}\nClean up the cluster as much as possible.")
        delete_crd(
            kube_apis.api_extensions_v1,
            ap_pol_crd_name,
        )
        delete_crd(
            kube_apis.api_extensions_v1,
            ap_log_crd_name,
        )
        delete_crd(
            kube_apis.api_extensions_v1,
            ap_uds_crd_name,
        )
        print("Remove ap-rbac")
        cleanup_rbac(kube_apis.rbac_v1, rbac)

        print("Remove the IC:")
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("--------------Cleanup----------------")
            delete_crd(
                kube_apis.api_extensions_v1,
                ap_pol_crd_name,
            )
            delete_crd(
                kube_apis.api_extensions_v1,
                ap_log_crd_name,
            )
            delete_crd(
                kube_apis.api_extensions_v1,
                ap_uds_crd_name,
            )
            print("Remove ap-rbac")
            cleanup_rbac(kube_apis.rbac_v1, rbac)

            print("Remove the IC:")
            delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def crd_ingress_controller_with_waf_v5(
    cli_arguments, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint, request, crds
) -> None:
    """
    Create an Ingress Controller with WAF v5.
    :param crds: the common IC crds.
    :param cli_arguments: pytest context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites
    :param ingress_controller_endpoint:
    :param request: pytest fixture to parametrize this method
        {extra_args: }
        'extra_args' list of IC arguments
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

    rbac = None
    try:
        print("--------------------Create roles and bindings for AppProtect------------------------")
        rbac = configure_rbac_with_ap(kube_apis.rbac_v1)

        print("------------------------- Register AP CRD -----------------------------------")
        ap_pol_crd_name = get_name_from_yaml(f"{CRDS}/appprotect.f5.com_appolicies.yaml")
        ap_log_crd_name = get_name_from_yaml(f"{CRDS}/appprotect.f5.com_aplogconfs.yaml")
        ap_uds_crd_name = get_name_from_yaml(f"{CRDS}/appprotect.f5.com_apusersigs.yaml")
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            ap_pol_crd_name,
            f"{CRDS}/appprotect.f5.com_appolicies.yaml",
        )
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            ap_log_crd_name,
            f"{CRDS}/appprotect.f5.com_aplogconfs.yaml",
        )
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            ap_uds_crd_name,
            f"{CRDS}/appprotect.f5.com_apusersigs.yaml",
        )
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
        try:
            with open(f"{dir}/wafv5.tgz", "rb") as f:
                file_content = f.read()
            exec_command = ["sh", "-c", f"cat > /etc/app_protect/bundles/wafv5.tgz"]
            pod_name = get_first_pod_name(kube_apis.v1, namespace)
            container_name = f"nginx-plus-ingress"
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
        print(f"Failed to complete CRD IC fixture: {ex}\nClean up the cluster as much as possible.")
        delete_crd(
            kube_apis.api_extensions_v1,
            ap_pol_crd_name,
        )
        delete_crd(
            kube_apis.api_extensions_v1,
            ap_log_crd_name,
        )
        delete_crd(
            kube_apis.api_extensions_v1,
            ap_uds_crd_name,
        )
        print("Remove ap-rbac")
        cleanup_rbac(kube_apis.rbac_v1, rbac)

        print("Remove the IC:")
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            delete_crd(
                kube_apis.api_extensions_v1,
                ap_pol_crd_name,
            )
            delete_crd(
                kube_apis.api_extensions_v1,
                ap_log_crd_name,
            )
            delete_crd(
                kube_apis.api_extensions_v1,
                ap_uds_crd_name,
            )
            print("Remove ap-rbac")
            cleanup_rbac(kube_apis.rbac_v1, rbac)
            print("Delete IC:")
            delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def crd_ingress_controller_with_dos(
    cli_arguments, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint, request, crds
) -> None:
    """
    Create an Ingress Controller with DOS CRDs enabled.
    :param crds: the common IC crds.
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
        print("--------------------Create roles and bindings for AppProtect------------------------")
        rbac = configure_rbac_with_dos(kube_apis.rbac_v1)

        print("------------------------- Register AP CRD -----------------------------------")
        dos_pol_crd_name = get_name_from_yaml(f"{CRDS}/appprotectdos.f5.com_apdospolicy.yaml")
        dos_log_crd_name = get_name_from_yaml(f"{CRDS}/appprotectdos.f5.com_apdoslogconfs.yaml")
        dos_protected_crd_name = get_name_from_yaml(f"{CRDS}/appprotectdos.f5.com_dosprotectedresources.yaml")
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            dos_pol_crd_name,
            f"{CRDS}/appprotectdos.f5.com_apdospolicy.yaml",
        )
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            dos_log_crd_name,
            f"{CRDS}/appprotectdos.f5.com_apdoslogconfs.yaml",
        )
        create_crd_from_yaml(
            kube_apis.api_extensions_v1,
            dos_protected_crd_name,
            f"{CRDS}/appprotectdos.f5.com_dosprotectedresources.yaml",
        )

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
        print(f"syslog and accesslog svc was created")

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
        print(f"Failed to complete CRD IC fixture: {ex}\nClean up the cluster as much as possible.")
        delete_crd(
            kube_apis.api_extensions_v1,
            dos_pol_crd_name,
        )
        delete_crd(
            kube_apis.api_extensions_v1,
            dos_log_crd_name,
        )
        delete_crd(
            kube_apis.api_extensions_v1,
            dos_protected_crd_name,
        )
        print("Remove ap-rbac")
        cleanup_rbac(kube_apis.rbac_v1, rbac)
        print("Remove dos arbitrator:")
        delete_dos_arbitrator(kube_apis.v1, kube_apis.apps_v1_api, dos_arbitrator_name, namespace)
        print("Remove the IC:")
        delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("--------------Cleanup----------------")
            delete_crd(
                kube_apis.api_extensions_v1,
                dos_pol_crd_name,
            )
            delete_crd(
                kube_apis.api_extensions_v1,
                dos_log_crd_name,
            )
            delete_crd(
                kube_apis.api_extensions_v1,
                dos_protected_crd_name,
            )
            print("Remove ap-rbac")
            cleanup_rbac(kube_apis.rbac_v1, rbac)
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
        {type: complete|rbac-without-vs, extra_args: }
        'type' type of test pre-configuration
        'extra_args' list of IC cli arguments
    :return:
    """
    namespace = ingress_controller_prerequisites.namespace
    name = "nginx-ingress"

    print("---------------------- Register DNSEndpoint CRD ------------------------------")
    external_dns_crd_name = get_name_from_yaml(f"{CRDS}/externaldns.nginx.org_dnsendpoints.yaml")
    create_crd_from_yaml(
        kube_apis.api_extensions_v1,
        external_dns_crd_name,
        f"{CRDS}/externaldns.nginx.org_dnsendpoints.yaml",
    )

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
        cm_source = f"{TEST_DATA}/virtual-server-external-dns/nginx-config.yaml"
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_source,
        )
    except ApiException:
        # Finalizer method doesn't start if fixture creation was incomplete, ensure clean up here
        print("Restore the ClusterRole:")
        patch_rbac(kube_apis.rbac_v1, f"{DEPLOYMENTS}/rbac/rbac.yaml")
        print("Remove the DNSEndpoint CRD:")
        delete_crd(
            kube_apis.api_extensions_v1,
            external_dns_crd_name,
        )
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
            print("Restore the ClusterRole:")
            patch_rbac(kube_apis.rbac_v1, f"{DEPLOYMENTS}/rbac/rbac.yaml")
            print("Remove the DNSEndpoint CRD:")
            delete_crd(
                kube_apis.api_extensions_v1,
                external_dns_crd_name,
            )
            print("Remove the IC:")
            delete_ingress_controller(kube_apis.apps_v1_api, name, cli_arguments["deployment-type"], namespace)
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )

    request.addfinalizer(fin)

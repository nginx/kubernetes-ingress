"""Describe project shared pytest fixtures related to setup of ingress controller."""

import os
import subprocess
import time
from typing import Optional

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

# ---------------------------------------------------------------------------
# Session-scoped IC Pool
# ---------------------------------------------------------------------------


class ICPool:
    """Manages a single IC deployment across test classes, reusing it when the config matches.

    The pool tracks the currently-running IC's configuration key (derived from
    the ``type`` and ``extra_args`` parameters). When a test class requests an IC
    with the same key, the existing deployment is reused. When the key differs,
    the old IC is torn down and a new one is created.
    """

    def __init__(self, kube_apis, cli_arguments, prerequisites, endpoint):
        self._kube_apis = kube_apis
        self._cli_arguments = cli_arguments
        self._prerequisites = prerequisites
        self._endpoint = endpoint
        self._current_key: Optional[tuple] = None
        self._name: Optional[str] = None

    @staticmethod
    def _config_key(params: dict) -> tuple:
        """Derive a hashable key from IC params."""
        extra_args = tuple(sorted(params.get("extra_args") or []))
        return extra_args

    def ensure(self, params: dict) -> str:
        """Ensure an IC with the requested configuration is running.

        If the currently-running IC matches the requested config, it is reused.
        Otherwise the existing IC is torn down and a new one is created.

        :param params: the fixture request.param dict
        :return: the IC deployment name
        """
        key = self._config_key(params)
        namespace = self._prerequisites.namespace

        if self._current_key == key and self._name is not None:
            print(f"------------------------- Reuse IC (key={key}) -----------------------------------")
            ensure_connection_to_public_endpoint(
                self._endpoint.public_ip,
                self._endpoint.port,
                self._endpoint.port_ssl,
            )
            return self._name

        # Tear down the old IC if one exists with a different config
        if self._name is not None:
            print(
                f"------------------------- Recycle IC (old key={self._current_key}) -----------------------------------"
            )
            delete_ingress_controller(
                self._kube_apis.apps_v1_api, self._name, self._cli_arguments["deployment-type"], namespace
            )
            self._name = None
            self._current_key = None

        print(f"------------------------- Create IC (key={key}) -----------------------------------")
        self._name = create_ingress_controller(
            self._kube_apis.v1,
            self._kube_apis.apps_v1_api,
            self._cli_arguments,
            namespace,
            params.get("extra_args", None),
        )
        self._current_key = key
        ensure_connection_to_public_endpoint(
            self._endpoint.public_ip,
            self._endpoint.port,
            self._endpoint.port_ssl,
        )
        return self._name

    def teardown(self) -> None:
        """Tear down the currently-running IC (called at session end)."""
        if self._name is not None:
            namespace = self._prerequisites.namespace
            print("------------------------- Teardown IC Pool -----------------------------------")
            delete_ingress_controller(
                self._kube_apis.apps_v1_api, self._name, self._cli_arguments["deployment-type"], namespace
            )
            self._name = None
            self._current_key = None


@pytest.fixture(scope="session")
def ic_pool(kube_apis, cli_arguments, ingress_controller_prerequisites, ingress_controller_endpoint, request):
    """Session-scoped IC pool that reuses IC deployments with matching configurations."""
    pool = ICPool(kube_apis, cli_arguments, ingress_controller_prerequisites, ingress_controller_endpoint)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            pool.teardown()

    request.addfinalizer(fin)
    return pool


# ---------------------------------------------------------------------------
# Fixtures for creating Ingress Controller instances
# ---------------------------------------------------------------------------


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
    cli_arguments, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint, request, crds, ic_pool
) -> None:
    """
    Create or reuse an Ingress Controller with CRD enabled via the session IC pool.

    The IC pool keeps a running IC alive across test classes that share the same
    configuration (extra_args). Only when a class requests different args does the
    pool recycle the IC.

    :param crds: the common ingress controller crds.
    :param cli_arguments: pytest context
    :param kube_apis: client apis
    :param ingress_controller_prerequisites
    :param ingress_controller_endpoint:
    :param request: pytest fixture to parametrize this method
        {type: complete|rbac-without-vs|tls-passthrough-custom-port,
        'extra_args': list of IC cli arguments }
    :param ic_pool: session-scoped IC pool
    :return:
    """
    orig_port = 0

    try:
        if request.param["type"] == "rbac-without-vs":
            print("------------------------- Update ClusterRole -----------------------------------")
            patch_rbac(kube_apis.rbac_v1, f"{TEST_DATA}/virtual-server/rbac-without-vs.yaml")

        ic_pool.ensure(request.param)

        if request.param["type"] == "tls-passthrough-custom-port":
            orig_port = ingress_controller_endpoint.port_ssl
            ingress_controller_endpoint.port_ssl = ingress_controller_endpoint.custom_ssl_port
    except ApiException:
        print("Restore the ClusterRole:")
        patch_rbac(kube_apis.rbac_v1, f"{DEPLOYMENTS}/rbac/rbac.yaml")
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            if request.param["type"] == "rbac-without-vs":
                print("Restore the ClusterRole:")
                patch_rbac(kube_apis.rbac_v1, f"{DEPLOYMENTS}/rbac/rbac.yaml")
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
    ic_pool,
) -> None:
    """
    Create or reuse an Ingress Controller with AppProtect CRD enabled via the session IC pool.

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
    :param ic_pool: session-scoped IC pool
    :return:
    """
    try:
        ic_pool.ensure(request.param)
    except Exception as ex:
        print(f"Failed to complete AP IC fixture: {ex}\nClean up the cluster as much as possible.")
        pytest.fail("IC setup failed")


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
    ic_pool,
) -> None:
    """
    Create an Ingress Controller with DoS CRDs enabled via the session IC pool.

    CRD registration and RBAC are managed by the session-scoped dos_crds and dos_rbac fixtures.
    Syslog, accesslog, and DoS arbitrator are class-scoped ancillary resources.

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
    :param ic_pool: session-scoped IC pool
    :return:
    """
    namespace = ingress_controller_prerequisites.namespace

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

        ic_pool.ensure(request.param)
    except Exception as ex:
        print(f"Failed to complete DoS IC fixture: {ex}\nClean up the cluster as much as possible.")
        delete_dos_arbitrator(kube_apis.v1, kube_apis.apps_v1_api, dos_arbitrator_name, namespace)
        delete_items_from_yaml(kube_apis, src_syslog_yaml, namespace)
        delete_items_from_yaml(kube_apis, src_accesslog_yaml, namespace)
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Remove dos arbitrator:")
            delete_dos_arbitrator(kube_apis.v1, kube_apis.apps_v1_api, dos_arbitrator_name, namespace)
            print("Remove the syslog svc:")
            delete_items_from_yaml(kube_apis, src_syslog_yaml, namespace)
            print("Remove the accesslog svc:")
            delete_items_from_yaml(kube_apis, src_accesslog_yaml, namespace)

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def crd_ingress_controller_with_ed(
    cli_arguments,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    request,
    crds,
    ed_crds,
    ic_pool,
) -> None:
    """
    Create or reuse an Ingress Controller with ExternalDNS CRD enabled via the session IC pool.

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
    :param ic_pool: session-scoped IC pool
    :return:
    """
    try:
        ic_pool.ensure(request.param)
        print("---------------- Replace ConfigMap with external-status-address --------------------")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/virtual-server-external-dns/nginx-config.yaml",
        )
    except ApiException:
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            f"{DEPLOYMENTS}/common/nginx-config.yaml",
        )
        pytest.fail("IC setup failed")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )

    request.addfinalizer(fin)

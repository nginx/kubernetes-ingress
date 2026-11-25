"""
Tests for namespace-scoped (tenant) installs of the Helm chart.

A cluster admin applies the CRDs and deployments/rbac/nic-tenant-aggregate.yaml, and installs one
installMode=platform release per tenant. Each tenant release is then installed by a namespace admin,
impersonated with helm --kube-as-user, who holds only the built-in "admin" role in the tenant's namespaces.

The Helm unit tests in charts/tests check what the chart renders. These tests check what only a real
cluster can: that a namespace admin can install the tenant chart, that the API server rejects what a
namespace admin isn't allowed to do, and that the tenant Roles are enough for NIC to serve traffic.
"""

import os
import shutil
import subprocess
import tempfile
import time

import pytest
import requests
import yaml
from kubernetes.client.rest import ApiException
from settings import CRDS, DEPLOYMENTS, HELM_CHARTS, TEST_DATA
from suite.utils.custom_resources_utils import create_crd, delete_crd
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress,
    create_namespace_with_name_from_yaml,
    delete_namespace,
    generate_e2e_run_id,
    get_e2e_run_selector,
    retry_get_until_status_code,
    wait_before_test,
    wait_until_all_pods_are_ready,
)

PLATFORM_NAMESPACE = "tenant-platform"
TENANT_RELEASE = "nic"
SERVICE_ACCOUNT = "nic"
TENANT_CHART_NAME = "nginx-ingress-tenant"
# The tenant chart's full name for release "nic" is "nic-nginx-ingress-tenant".
TENANT_SERVICE = f"{TENANT_RELEASE}-{TENANT_CHART_NAME}-controller"
AGGREGATE_MANIFEST = f"{DEPLOYMENTS}/rbac/nic-tenant-aggregate.yaml"
AGGREGATE_CLUSTER_ROLE = "nginx-ingress-tenant-aggregate"
NIC_CRDS = [
    "k8s.nginx.org_virtualservers.yaml",
    "k8s.nginx.org_virtualserverroutes.yaml",
    "k8s.nginx.org_transportservers.yaml",
    "k8s.nginx.org_policies.yaml",
    "k8s.nginx.org_globalconfigurations.yaml",
]

# Each tenant: its namespace admin, the namespaces it administers (the first is the release namespace),
# and its IngressClass.
TENANTS = {
    "a": {"user": "tenant-a-admin", "namespaces": ["tenant-a", "tenant-a-apps"], "ingress_class": "tenant-a"},
    "b": {"user": "tenant-b-admin", "namespaces": ["tenant-b"], "ingress_class": "tenant-b"},
    # Used only by the failure scenarios; never gets a working release.
    "c": {"user": "tenant-c-admin", "namespaces": ["tenant-c"], "ingress_class": "tenant-c"},
}


class HelmResult:
    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TenantSetup:
    def __init__(self, cli_arguments, tenant_chart, node_ip):
        self.cli_arguments = cli_arguments
        self.tenant_chart = tenant_chart
        self.node_ip = node_ip
        self.http_ports = {}


def run_helm(cli_arguments, args, as_user=None, timeout=600) -> HelmResult:
    """Run helm against the test cluster, as cluster admin or impersonating as_user."""
    cmd = ["helm", *args, "--kubeconfig", cli_arguments["kubeconfig"], "--kube-context", cli_arguments["context"]]
    if as_user:
        cmd += ["--kube-as-user", as_user]
    print(f"Running: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    print(proc.stdout)
    print(proc.stderr)
    return HelmResult(proc.returncode, proc.stdout, proc.stderr)


def kubectl_can_i(cli_arguments, verb, resource, namespace, as_user) -> bool:
    """Return whether as_user may perform verb on resource in namespace."""
    cmd = [
        "kubectl",
        "--kubeconfig",
        cli_arguments["kubeconfig"],
        "--context",
        cli_arguments["context"],
        "auth",
        "can-i",
        verb,
        resource,
        "-n",
        namespace,
        "--as",
        as_user,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return proc.stdout.strip() == "yes"


def wait_until_can_i(cli_arguments, verb, resource, namespace, as_user, timeout=60) -> None:
    """Wait until as_user may perform verb on resource. ClusterRole aggregation is asynchronous."""
    deadline = time.monotonic() + timeout
    while not kubectl_can_i(cli_arguments, verb, resource, namespace, as_user):
        if time.monotonic() > deadline:
            pytest.fail(f"{as_user} still can't {verb} {resource} in namespace {namespace} after {timeout}s")
        time.sleep(2)


def build_tenant_chart(directory) -> str:
    """
    Package the chart the way .github/workflows/publish-helm.yml does with tenant: true:
    no CRDs, named nginx-ingress-tenant, and installMode tenant by default.
    """
    chart = os.path.join(directory, TENANT_CHART_NAME)
    # symlinks=True keeps crds as a link, so it can be removed like in the workflow.
    shutil.copytree(HELM_CHARTS, chart, symlinks=True)
    crds = os.path.join(chart, "crds")
    if os.path.islink(crds):
        os.unlink(crds)
    else:
        shutil.rmtree(crds)
    replace_line(os.path.join(chart, "Chart.yaml"), "name: nginx-ingress", f"name: {TENANT_CHART_NAME}")
    replace_line(os.path.join(chart, "values.yaml"), "installMode: full", "installMode: tenant")
    return chart


def replace_line(path, old, new) -> None:
    with open(path) as f:
        lines = f.read().split("\n")
    assert lines.count(old) == 1, f"expected exactly one line {old!r} in {path}"
    lines[lines.index(old)] = new
    with open(path, "w") as f:
        f.write("\n".join(lines))


def image_values(cli_arguments) -> list:
    """Helm values that run the image under test with the suite's pull policy."""
    repository, tag = cli_arguments["image"].rsplit(":", 1)
    return [
        "--set",
        f"controller.image.repository={repository}",
        "--set",
        f"controller.image.tag={tag}",
        "--set",
        f"controller.image.pullPolicy={cli_arguments['image-pull-policy']}",
        "--set",
        "controller.service.type=NodePort",
        "--set",
        "controller.telemetryReporting.enable=false",
    ]


def install_platform(cli_arguments, tenant) -> None:
    """Install the tenant's platform release (IngressClass and reader ClusterRole) as cluster admin."""
    t = TENANTS[tenant]
    result = run_helm(
        cli_arguments,
        [
            "install",
            f"platform-{tenant}",
            HELM_CHARTS,
            "-n",
            PLATFORM_NAMESPACE,
            "--skip-crds",
            "--set",
            "installMode=platform",
            "--set",
            f"platform.tenantNamespace={t['namespaces'][0]}",
            "--set",
            f"controller.serviceAccount.name={SERVICE_ACCOUNT}",
            "--set",
            f"controller.ingressClass.name={t['ingress_class']}",
        ],
    )
    assert result.returncode == 0, f"platform release for tenant {tenant} failed: {result.stderr}"


def install_tenant(cli_arguments, chart, tenant, watch_namespaces, extra_args=None) -> HelmResult:
    """Install a tenant release as the tenant's namespace admin."""
    t = TENANTS[tenant]
    # --set/--set-string treat "," as a separator between key=value pairs, so a literal "," in a
    # value must be escaped, or Helm reads each namespace after the first as its own bare key.
    watch_namespace_value = "\\,".join(watch_namespaces)
    args = [
        "install",
        TENANT_RELEASE,
        chart,
        "-n",
        t["namespaces"][0],
        "--set",
        f"controller.serviceAccount.name={SERVICE_ACCOUNT}",
        "--set",
        f"controller.ingressClass.name={t['ingress_class']}",
        "--set-string",
        f"controller.watchNamespace={watch_namespace_value}",
        *image_values(cli_arguments),
        *(extra_args or []),
    ]
    return run_helm(cli_arguments, args, as_user=t["user"])


def uninstall(cli_arguments, release, namespace) -> None:
    run_helm(cli_arguments, ["uninstall", release, "-n", namespace, "--ignore-not-found", "--wait"])


def http_node_port(kube_apis, namespace) -> int:
    service = kube_apis.v1.read_namespaced_service(TENANT_SERVICE, namespace)
    return next(p.node_port for p in service.spec.ports if p.name == "http")


def ingress_body(name, host, ingress_class) -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": name},
        "spec": {
            "ingressClassName": ingress_class,
            "rules": [
                {
                    "host": host,
                    "http": {
                        "paths": [
                            {
                                "path": "/backend1",
                                "pathType": "Prefix",
                                "backend": {"service": {"name": "backend1-svc", "port": {"number": 80}}},
                            }
                        ]
                    },
                }
            ],
        },
    }


def assert_status_stays(req_url, host, expected_status, duration=5, interval=1) -> None:
    """
    GET req_url repeatedly for `duration` seconds and fail on the first response whose status code
    is not expected_status.

    Unlike retry_get_until_status_code, which returns on the first match, this observes the whole
    window: a single matching response is not enough to show the host stays unserved, because a
    namespaced informer's sync queue can take a moment to reach a just-created resource, and an
    isolation check made right after creating that resource could otherwise pass on NGINX's
    default-server response before either controller has reconciled it.

    Tolerates ConnectionError, caused by NGINX reloads, the same way retry_get_until_status_code does.
    """
    deadline = time.monotonic() + duration
    attempts = 0
    while True:
        attempts += 1
        try:
            resp = requests.get(req_url, headers={"host": host})
            assert resp.status_code == expected_status, (
                f"expected {expected_status} from {host}, got {resp.status_code} on attempt {attempts} "
                f"(observed for {duration}s to allow for a delayed reconciliation)"
            )
        except requests.exceptions.ConnectionError as e:
            print(f"Attempt {attempts}: connection dropped during reload ({e})")
        if time.monotonic() > deadline:
            break
        wait_before_test(interval)
    if attempts <= 1:
        pytest.fail(
            f"only {attempts} request(s) were made to {host} in {duration}s; the observation window is too short"
        )


def cleanup_step(description, func, *args, **kwargs) -> None:
    """Run a teardown step, logging and continuing past any failure so one broken step can't
    leave the rest of the cleanup undone."""
    try:
        func(*args, **kwargs)
    except Exception as ex:
        print(f"cleanup: {description} failed: {ex}")


def create_admin_binding(kube_apis, user, namespace) -> None:
    """Make user a namespace admin: bind it to the built-in admin ClusterRole in namespace."""
    kube_apis.rbac_v1.create_namespaced_role_binding(
        namespace,
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": f"{user}-admin"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "admin"},
            "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": user}],
        },
    )


@pytest.fixture(scope="module")
def tenant_setup(request, kube_apis, cli_arguments) -> TenantSetup:
    """
    The platform phase, as cluster admin: NIC CRDs, the tenant aggregate ClusterRole, the tenant namespaces
    with their admins, and the platform namespace. Also builds the tenant chart.
    """
    if cli_arguments["ic-type"] == "nginx-plus-ingress":
        pytest.skip("Tenant install tests run with NGINX OSS only")
    if cli_arguments["service"] != "nodeport":
        pytest.skip("Tenant install tests reach each tenant's NodePort Service")
    if shutil.which("helm") is None:
        pytest.fail('helm not found in the test image; rebuild it with "make -f tests/Makefile build"')

    skip_teardown = request.config.getoption("--skip-fixture-teardown") == "yes"
    created_crds = []
    created_namespaces = []
    created_aggregate = False
    tmp = tempfile.mkdtemp()

    def fin():
        if skip_teardown:
            return
        print("------------------------- Tenant install teardown -----------------------------------")
        # Each step runs independently: a failure (e.g. a release or namespace already gone, or a
        # transient API error) must not stop the rest of the cleanup from running.
        # Only uninstall releases in namespaces this fixture created: if setup failed because a
        # namespace already existed (see the create_namespace_with_name_from_yaml loop below),
        # created_namespaces is incomplete, and this must not uninstall someone else's release in
        # a namespace this run never touched.
        for tenant in TENANTS:
            if TENANTS[tenant]["namespaces"][0] in created_namespaces:
                cleanup_step(
                    f"uninstall tenant release in {TENANTS[tenant]['namespaces'][0]}",
                    uninstall,
                    cli_arguments,
                    TENANT_RELEASE,
                    TENANTS[tenant]["namespaces"][0],
                )
            if PLATFORM_NAMESPACE in created_namespaces:
                cleanup_step(
                    f"uninstall platform-{tenant}", uninstall, cli_arguments, f"platform-{tenant}", PLATFORM_NAMESPACE
                )
        for namespace in created_namespaces:
            cleanup_step(f"delete namespace {namespace}", delete_namespace, kube_apis.v1, namespace)
        if created_aggregate:
            cleanup_step(
                f"delete cluster role {AGGREGATE_CLUSTER_ROLE}",
                kube_apis.rbac_v1.delete_cluster_role,
                AGGREGATE_CLUSTER_ROLE,
            )
        for name in created_crds:
            cleanup_step(f"delete CRD {name}", delete_crd, kube_apis.api_extensions_v1, name)
        cleanup_step("remove temp chart directory", shutil.rmtree, tmp, ignore_errors=True)

    request.addfinalizer(fin)

    print("------------------------- Tenant install platform prerequisites -----------------------------------")
    # Apply only the CRDs that aren't installed yet, and remove only those afterwards.
    existing = {crd.metadata.name for crd in kube_apis.api_extensions_v1.list_custom_resource_definition().items}
    for file in NIC_CRDS:
        with open(f"{CRDS}/{file}") as f:
            body = yaml.safe_load(f)
        if body["metadata"]["name"] not in existing:
            create_crd(kube_apis.api_extensions_v1, body)
            created_crds.append(body["metadata"]["name"])

    with open(AGGREGATE_MANIFEST) as f:
        aggregate = yaml.safe_load(f)
    try:
        kube_apis.rbac_v1.create_cluster_role(aggregate)
        created_aggregate = True
    except ApiException as ex:
        if ex.status != 409:
            raise

    all_namespaces = [PLATFORM_NAMESPACE, *(ns for t in TENANTS.values() for ns in t["namespaces"])]
    for name in all_namespaces:
        try:
            create_namespace_with_name_from_yaml(kube_apis.v1, name, f"{TEST_DATA}/common/ns.yaml")
        except ApiException as ex:
            if ex.status != 409:
                raise
            pytest.fail(
                f"namespace {name} already exists; remove leftovers from an earlier run with:\n"
                f"  kubectl delete ns {' '.join(all_namespaces)}\n"
                f"  kubectl delete clusterrole {AGGREGATE_CLUSTER_ROLE}"
            )
        created_namespaces.append(name)
    for t in TENANTS.values():
        for namespace in t["namespaces"]:
            create_admin_binding(kube_apis, t["user"], namespace)

    # The aggregate is merged into "admin" asynchronously. Wait until the tenant admins hold its rules,
    # including the Lease rules Helm needs to own the tenant release's Lease.
    for t in TENANTS.values():
        wait_until_can_i(cli_arguments, "create", "virtualservers.k8s.nginx.org", t["namespaces"][0], t["user"])
        wait_until_can_i(cli_arguments, "patch", "leases.coordination.k8s.io", t["namespaces"][0], t["user"])

    return TenantSetup(cli_arguments, build_tenant_chart(tmp), cli_arguments["node-ip"])


@pytest.mark.tenant_install
class TestTenantIsolation:
    """
    Two tenants, each installed by its own namespace admin with no extra flags, serve only the Ingresses
    in their own namespaces and with their own IngressClass.
    """

    @pytest.fixture(scope="class")
    def tenants(self, request, kube_apis, tenant_setup) -> TenantSetup:
        cli_arguments = tenant_setup.cli_arguments
        watched = {"a": TENANTS["a"]["namespaces"], "b": TENANTS["b"]["namespaces"]}
        for tenant in watched:
            install_platform(cli_arguments, tenant)
            result = install_tenant(cli_arguments, tenant_setup.tenant_chart, tenant, watched[tenant], ["--wait"])
            assert result.returncode == 0, f"tenant {tenant} install as {TENANTS[tenant]['user']} failed"
            tenant_setup.http_ports[tenant] = http_node_port(kube_apis, TENANTS[tenant]["namespaces"][0])

        e2e_run_id = generate_e2e_run_id()
        apps = {
            "tenant-a": ("a-ingress", "a.example.com", TENANTS["a"]["ingress_class"]),
            "tenant-a-apps": ("a-apps-ingress", "a-apps.example.com", TENANTS["a"]["ingress_class"]),
            "tenant-b": ("b-ingress", "b.example.com", TENANTS["b"]["ingress_class"]),
        }
        for namespace, (name, host, ingress_class) in apps.items():
            create_example_app(kube_apis, "simple", namespace, e2e_run_id=e2e_run_id)
            create_ingress(kube_apis.networking_v1, namespace, ingress_body(name, host, ingress_class))
            wait_until_all_pods_are_ready(kube_apis.v1, namespace, get_e2e_run_selector(e2e_run_id))

        # Wait until each tenant's own controller actually serves its own
        # host before testing isolation.
        for namespace, (_, host, _) in apps.items():
            tenant = "a" if namespace.startswith("tenant-a") else "b"
            resp = retry_get_until_status_code(self.url(tenant_setup, tenant), host, 200)
            assert resp.status_code == 200, f"setup: tenant {tenant} never served its own host {host}"

        # An Ingress in tenant b's namespace that names tenant a's IngressClass. Tenant a doesn't watch
        # tenant-b, and tenant b ignores other classes, so nothing serves it.
        create_ingress(
            kube_apis.networking_v1,
            "tenant-b",
            ingress_body("b-claims-a-ingress", "b-claims-a.example.com", TENANTS["a"]["ingress_class"]),
        )
        create_ingress(
            kube_apis.networking_v1,
            "tenant-b",
            ingress_body("b-control-ingress", "b-control.example.com", TENANTS["b"]["ingress_class"]),
        )
        resp = retry_get_until_status_code(self.url(tenant_setup, "b"), "b-control.example.com", 200)
        assert resp.status_code == 200, "setup: tenant b never served the control Ingress b-control-ingress"

        return tenant_setup

    def url(self, tenants, tenant) -> str:
        return f"http://{tenants.node_ip}:{tenants.http_ports[tenant]}/backend1"

    def test_tenants_serve_their_own_namespaces(self, tenants):
        for tenant, host in [("a", "a.example.com"), ("a", "a-apps.example.com"), ("b", "b.example.com")]:
            resp = retry_get_until_status_code(self.url(tenants, tenant), host, 200)
            assert resp.status_code == 200, f"tenant {tenant} returned {resp.status_code} for its host {host}"

    def test_tenants_do_not_serve_each_other(self, tenants):
        # The tenants fixture already waited for each tenant to serve its own host, so by now both
        # controllers have reconciled; assert_status_stays checks the other tenant's host stays
        # unserved over an observation window, rather than returning on the first 404.
        for tenant, host in [("a", "b.example.com"), ("b", "a.example.com"), ("b", "a-apps.example.com")]:
            assert_status_stays(self.url(tenants, tenant), host, 404)

    def test_ingress_class_of_another_tenant_is_not_served(self, tenants):
        # The tenants fixture already waited for tenant b's control Ingress to be served, which
        # happened after the claimed-class Ingress in its sync queue; assert_status_stays then
        # checks the claimed-class host stays unserved by both controllers.
        for tenant in ["a", "b"]:
            assert_status_stays(self.url(tenants, tenant), "b-claims-a.example.com", 404)


@pytest.mark.tenant_install
class TestMainChartTenantModeNeedsCRDRights:
    """
    The main chart still contains the CRDs, so installing it with installMode=tenant and without --skip-crds
    attempts the CRD install, which a namespace admin isn't allowed to do. This is why tenants use the
    nginx-ingress-tenant chart.
    """

    def test_crd_install_is_forbidden(self, tenant_setup):
        cli_arguments = tenant_setup.cli_arguments
        t = TENANTS["c"]
        try:
            result = run_helm(
                cli_arguments,
                [
                    "install",
                    TENANT_RELEASE,
                    HELM_CHARTS,
                    "-n",
                    t["namespaces"][0],
                    "--set",
                    "installMode=tenant",
                    "--set",
                    f"controller.serviceAccount.name={SERVICE_ACCOUNT}",
                    "--set",
                    f"controller.ingressClass.name={t['ingress_class']}",
                    *image_values(cli_arguments),
                ],
                as_user=t["user"],
            )
        finally:
            uninstall(cli_arguments, TENANT_RELEASE, t["namespaces"][0])
        assert result.returncode != 0, "a namespace admin installed the main chart's CRDs"
        assert "forbidden" in result.stderr and "customresourcedefinitions" in result.stderr, result.stderr


@pytest.mark.tenant_install
class TestTenantInstallNeedsAdminInEveryWatchedNamespace:
    """
    A tenant release creates a Role in every watched namespace as the installing user, so the installer
    must be admin in each of them.
    """

    def test_watching_a_namespace_without_admin_is_forbidden(self, tenant_setup):
        cli_arguments = tenant_setup.cli_arguments
        t = TENANTS["c"]
        # tenant-c-admin isn't admin in tenant-b.
        watched = [t["namespaces"][0], "tenant-b"]
        try:
            result = install_tenant(cli_arguments, tenant_setup.tenant_chart, "c", watched)
        finally:
            uninstall(cli_arguments, TENANT_RELEASE, t["namespaces"][0])
        assert result.returncode != 0, "tenant install succeeded in a namespace where the installer isn't admin"
        assert "forbidden" in result.stderr and "roles" in result.stderr and "tenant-b" in result.stderr, result.stderr

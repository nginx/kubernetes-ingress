"""End-to-end tests for ACME HTTP-01 challenges served through NIC, against an in-cluster Pebble ACME server."""

import base64
import subprocess

import OpenSSL
import pytest
import yaml
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.custom_assertions import wait_and_assert_status_code
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_ingress,
    delete_secret,
    generate_e2e_run_id,
    get_e2e_run_selector,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    get_vs_nginx_template_conf,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import create_virtual_server_from_yaml, delete_virtual_server
from suite.utils.yaml_utils import (
    get_first_host_from_yaml,
    get_first_ingress_host_from_yaml,
    get_secret_name_from_vs_or_ts_yaml,
)

ACME_DATA = f"{TEST_DATA}/acme-pebble"
htpasswd_secret_src = f"{ACME_DATA}/htpasswd-secret.yaml"
basic_auth_policy_src = f"{ACME_DATA}/policy-basic-auth.yaml"
vs_src = f"{ACME_DATA}/virtual-server.yaml"
vs_basic_auth_src = f"{ACME_DATA}/virtual-server-basic-auth.yaml"
ingress_src = f"{ACME_DATA}/ingress-edit-in-place.yaml"
ingress_spoof_src = f"{ACME_DATA}/ingress-spoof.yaml"
spoof_tls_secret_src = f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
# Test-only credentials matching htpasswd-secret.yaml.
credentials = ("foo", "bar")
certificate_ready_timeout = 120


class ACMESetup:
    """
    Encapsulate the details of an ACME test resource.

    Attributes:
        public_endpoint (PublicEndpoint):
        namespace (str): test namespace
        name (str): VirtualServer or Ingress name
        host (str): the resource's host
        secret_name (str): the TLS Secret, which is also the name of the cert-manager Certificate
    """

    def __init__(self, public_endpoint, namespace, name, host, secret_name):
        self.public_endpoint = public_endpoint
        self.namespace = namespace
        self.name = name
        self.host = host
        self.secret_name = secret_name

    def http_url(self, path="/"):
        return f"http://{self.public_endpoint.public_ip}:{self.public_endpoint.port}{path}"

    def https_url(self, path="/"):
        return f"https://{self.public_endpoint.public_ip}:{self.public_endpoint.port_ssl}{path}"


def setup_backend_and_auth(request, kube_apis, namespace, with_policy) -> None:
    """Create the backend app, the htpasswd Secret and optionally the basic-auth Policy, with teardown."""
    e2e_run_id = generate_e2e_run_id()
    create_example_app(kube_apis, "simple", namespace, e2e_run_id=e2e_run_id)
    create_secret_from_yaml(kube_apis.v1, namespace, htpasswd_secret_src)
    policy_name = (
        create_policy_from_yaml(kube_apis.custom_objects, basic_auth_policy_src, namespace) if with_policy else None
    )
    wait_until_all_pods_are_ready(kube_apis.v1, namespace, get_e2e_run_selector(e2e_run_id))

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up the backend app and basic auth resources:")
            if policy_name:
                delete_policy(kube_apis.custom_objects, policy_name, namespace)
            delete_secret(kube_apis.v1, "acme-htpasswd", namespace)
            delete_common_app(kube_apis, "simple", namespace)

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def acme_virtual_servers_setup(request, kube_apis, ingress_controller_endpoint, test_namespace) -> dict:
    """
    Deploy two VirtualServers with TLS redirect and the Pebble ClusterIssuer: one plain, and one with a spec-level
    basic-auth Policy (server-level auth_basic, which the challenge location must turn off) whose only route is a
    regex catch-all (~ ^/) with the same Policy at route level, which would capture the challenge token path unless
    the challenge location is exact-match.

    :return: {"plain": ACMESetup, "basic_auth": ACMESetup}
    """
    print("------------------------- Deploy ACME VirtualServers -----------------------------------")
    setup_backend_and_auth(request, kube_apis, test_namespace, with_policy=True)
    setups = {}
    for key, src in (("plain", vs_src), ("basic_auth", vs_basic_auth_src)):
        vs_name = create_virtual_server_from_yaml(kube_apis.custom_objects, src, test_namespace)
        request.addfinalizer(lambda name=vs_name: delete_vs_unless_skipped(request, kube_apis, name, test_namespace))
        setups[key] = ACMESetup(
            ingress_controller_endpoint,
            test_namespace,
            vs_name,
            get_first_host_from_yaml(src),
            get_secret_name_from_vs_or_ts_yaml(src),
        )
    return setups


def delete_vs_unless_skipped(request, kube_apis, name, namespace) -> None:
    if request.config.getoption("--skip-fixture-teardown") == "no":
        print(f"Clean up the ACME VirtualServer {name}:")
        delete_virtual_server(kube_apis.custom_objects, name, namespace)


@pytest.fixture(scope="class")
def acme_ingress_setup(request, kube_apis, ingress_controller_endpoint, test_namespace) -> ACMESetup:
    """
    Deploy an Ingress with ssl-redirect and basic auth.

    :param request: {"ingress_src": path, "tls_secret_src": optional path to a static TLS Secret}
    """
    print("------------------------- Deploy ACME Ingress -----------------------------------")
    src = request.param["ingress_src"]
    setup_backend_and_auth(request, kube_apis, test_namespace, with_policy=False)
    static_secret = None
    if request.param.get("tls_secret_src"):
        static_secret = create_secret_from_yaml(kube_apis.v1, test_namespace, request.param["tls_secret_src"])
    ingress_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, src)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up the ACME Ingress:")
            delete_ingress(kube_apis.networking_v1, ingress_name, test_namespace)
            if static_secret:
                delete_secret(kube_apis.v1, static_secret, test_namespace)

    request.addfinalizer(fin)

    with open(src) as f:
        secret_name = yaml.safe_load(f)["spec"]["tls"][0]["secretName"]
    return ACMESetup(
        ingress_controller_endpoint, test_namespace, ingress_name, get_first_ingress_host_from_yaml(src), secret_name
    )


def get_certificate_ready_condition(kube_apis, namespace, name):
    try:
        cert = kube_apis.custom_objects.get_namespaced_custom_object(
            "cert-manager.io", "v1", namespace, "certificates", name
        )
    except ApiException as ex:
        if ex.status == 404:
            return None
        raise
    for condition in cert.get("status", {}).get("conditions", []):
        if condition["type"] == "Ready":
            return condition
    return None


def print_acme_debug_info(kube_apis, ingress_controller_prerequisites, setup: ACMESetup, kind) -> None:
    print("------------------------- ACME debug info -----------------------------------")
    for cmd in (
        ["kubectl", "get", "clusterissuers,certificates,challenges,orders,certificaterequests", "-A", "-o", "yaml"],
        ["kubectl", "get", "ingresses", "-A", "-o", "yaml"],
        ["kubectl", "get", "virtualservers", "-n", setup.namespace, "-o", "yaml"],
    ):
        res = subprocess.run(cmd, capture_output=True, text=True)
        print(f"$ {' '.join(cmd)}\n{res.stdout or res.stderr}")
    ic_namespace = ingress_controller_prerequisites.namespace
    pod_name = get_first_pod_name(kube_apis.v1, ic_namespace)
    try:
        if kind == "vs":
            conf = get_vs_nginx_template_conf(kube_apis.v1, setup.namespace, setup.name, pod_name, ic_namespace)
        else:
            conf = get_ingress_nginx_template_conf(kube_apis.v1, setup.namespace, setup.name, pod_name, ic_namespace)
        print(f"NGINX config for {setup.host}:\n{conf}")
    except ApiException as ex:
        print(f"Could not read the NGINX config: {ex}")


def wait_for_certificate_ready(kube_apis, ingress_controller_prerequisites, setup: ACMESetup, kind) -> None:
    """Wait up to certificate_ready_timeout seconds for the Certificate to become Ready, dumping ACME state if not."""
    condition = None
    waited = 0
    while waited < certificate_ready_timeout:
        condition = get_certificate_ready_condition(kube_apis, setup.namespace, setup.secret_name)
        if condition and condition["status"] == "True":
            print(f"Certificate {setup.secret_name} is Ready after ~{waited}s")
            return
        print(f"Certificate {setup.secret_name} not Ready yet: {condition}")
        wait_before_test(5)
        waited += 5
    print_acme_debug_info(kube_apis, ingress_controller_prerequisites, setup, kind)
    pytest.fail(f"Certificate {setup.secret_name} not Ready after {certificate_ready_timeout}s. Last: {condition}")


def get_secret_issuer_cn(kube_apis, namespace, name) -> str:
    secret = kube_apis.v1.read_namespaced_secret(name, namespace)
    cert_pem = base64.b64decode(secret.data["tls.crt"])
    # load_certificate reads the first PEM block, which is the leaf.
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
    return cert.get_issuer().CN


@pytest.mark.vs
@pytest.mark.acme
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [{"type": "complete", "extra_args": ["-enable-custom-resources", "-enable-cert-manager"]}],
    indirect=True,
)
class TestACMEVirtualServer:
    def test_issue_with_tls_redirect(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        create_pebble,
        acme_virtual_servers_setup,
    ):
        setup = acme_virtual_servers_setup["plain"]
        print("\nStep 1: wait for the Pebble Certificate to become Ready")
        wait_for_certificate_ready(kube_apis, ingress_controller_prerequisites, setup, "vs")

        print("\nStep 2: verify the Secret was issued by Pebble")
        issuer_cn = get_secret_issuer_cn(kube_apis, setup.namespace, setup.secret_name)
        print(f"Issuer CN: {issuer_cn}")
        assert "Pebble" in issuer_cn

        print("\nStep 3: verify HTTP still redirects to HTTPS")
        wait_and_assert_status_code(301, setup.http_url(), setup.host, allow_redirects=False)
        wait_and_assert_status_code(200, setup.https_url(), setup.host, verify=False)

    def test_issue_with_tls_redirect_and_basic_auth(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        create_pebble,
        acme_virtual_servers_setup,
    ):
        setup = acme_virtual_servers_setup["basic_auth"]
        print("\nStep 1: wait for the Pebble Certificate to become Ready")
        wait_for_certificate_ready(kube_apis, ingress_controller_prerequisites, setup, "vs")

        print("\nStep 2: verify basic auth still protects the regex catch-all route")
        wait_and_assert_status_code(401, setup.https_url(), setup.host, verify=False)
        wait_and_assert_status_code(200, setup.https_url(), setup.host, verify=False, auth=credentials)

        print("\nStep 3: verify HTTP still redirects to HTTPS")
        wait_and_assert_status_code(301, setup.http_url(), setup.host, allow_redirects=False)


@pytest.mark.ingresses
@pytest.mark.acme
@pytest.mark.parametrize(
    "crd_ingress_controller, acme_ingress_setup",
    [
        (
            {"type": "complete", "extra_args": ["-enable-custom-resources", "-enable-cert-manager"]},
            {"ingress_src": ingress_src},
        )
    ],
    indirect=True,
)
class TestACMEIngress:
    def test_issue_edit_in_place_ssl_redirect_basic_auth(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        create_pebble,
        acme_ingress_setup,
    ):
        setup = acme_ingress_setup
        print("\nStep 1: wait for the Pebble Certificate to become Ready")
        wait_for_certificate_ready(kube_apis, ingress_controller_prerequisites, setup, "ingress")

        print("\nStep 2: verify basic auth and the HTTPS redirect still apply")
        wait_and_assert_status_code(401, setup.https_url(), setup.host, verify=False)
        wait_and_assert_status_code(301, setup.http_url(), setup.host, allow_redirects=False)


@pytest.mark.ingresses
@pytest.mark.acme
@pytest.mark.parametrize(
    "crd_ingress_controller, acme_ingress_setup",
    [
        (
            # No Pebble or cert-manager: the Ingress exemption needs neither, and this backend is a
            # normal Service, so nothing may be exempted.
            {"type": "complete", "extra_args": ["-enable-custom-resources"]},
            {"ingress_src": ingress_spoof_src, "tls_secret_src": spoof_tls_secret_src},
        )
    ],
    indirect=True,
)
class TestACMEIngressSpoof:
    def test_non_solver_backend_not_exempt(self, kube_apis, crd_ingress_controller, acme_ingress_setup):
        setup = acme_ingress_setup
        path = "/.well-known/acme-challenge/x"
        print("\nStep 1: verify a challenge path to a non-solver backend is still redirected")
        wait_and_assert_status_code(301, setup.http_url(path), setup.host, allow_redirects=False)

        print("\nStep 2: verify it still requires basic auth over HTTPS")
        wait_and_assert_status_code(401, setup.https_url(path), setup.host, verify=False)

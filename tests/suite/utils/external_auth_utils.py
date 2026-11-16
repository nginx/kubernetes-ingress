"""Shared helpers, file path constants, and fixtures for external auth policy tests."""

import json
import logging
from base64 import b64encode

import grpc
import pytest
import requests
from kubernetes.stream import stream
from settings import DEPLOYMENTS, TEST_DATA
from suite.grpc.helloworld_pb2 import HelloRequest
from suite.grpc.helloworld_pb2_grpc import GreeterStub
from suite.utils.policy_resources_utils import (
    setup_policy_backend,
    teardown_policy_backend,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_secret,
    ensure_response_from_backend,
    generate_e2e_run_id,
    get_e2e_run_selector,
    get_first_pod_name,
    get_reload_count,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_for_reload,
    wait_until_all_pods_are_ready,
)
from suite.utils.ssl_utils import get_certificate
from suite.utils.vs_vsr_resources_utils import apply_and_assert_valid_vs, delete_and_create_vs_from_yaml
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared file path constants
# ---------------------------------------------------------------------------

# HTTP backend and credentials
ext_auth_backend_secret_src = f"{TEST_DATA}/external-auth/backend/htpasswd-secret.yaml"
ext_auth_backend_src = f"{TEST_DATA}/external-auth/backend/external-auth-backend.yaml"
valid_credentials = f"{TEST_DATA}/external-auth/credentials.txt"
invalid_credentials = f"{TEST_DATA}/external-auth/invalid-credentials.txt"

# HTTP policies (no TLS)
ext_auth_pol_valid_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-valid.yaml"
ext_auth_pol_valid_multi_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-valid-multi.yaml"
ext_auth_pol_invalid_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-invalid.yaml"
ext_auth_pol_invalid_svc_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-invalid-svc.yaml"
ext_auth_pol_signin_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-signin.yaml"
ext_auth_pol_custom_port_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-custom-port.yaml"

# TLS backend and secrets
ext_auth_tls_backend_src = f"{TEST_DATA}/external-auth/backend/external-auth-backend-tls.yaml"
ext_auth_tls_server_secret_src = f"{TEST_DATA}/external-auth/backend/external-auth-server-tls-secret.yaml"
ext_auth_tls_ca_secret_src = f"{TEST_DATA}/external-auth/backend/external-auth-ca-secret.yaml"
ext_auth_tls_ca_secret_opaque_src = f"{TEST_DATA}/external-auth/backend/external-auth-ca-secret-opaque.yaml"
ext_auth_tls_missing_ca_crt_src = f"{TEST_DATA}/external-auth/backend/missing-ca-crt-secret.yaml"

# TLS policies
ext_auth_pol_tls_basic_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-basic.yaml"
ext_auth_pol_tls_full_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-full.yaml"
ext_auth_pol_tls_nonexistent_ca_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-nonexistent-ca.yaml"
ext_auth_pol_tls_missing_ca_crt_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-missing-ca-crt.yaml"
ext_auth_pol_tls_bad_sni_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-bad-sni.yaml"
ext_auth_pol_tls_cross_ns_ca_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-cross-ns-ca.yaml"
ext_auth_pol_tls_no_trusted_cert_src = (
    f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-no-trusted-cert.yaml"
)
ext_auth_pol_tls_default_sni_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-default-sni.yaml"
ext_auth_pol_tls_verify_no_ssl_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-verify-no-ssl.yaml"
ext_auth_pol_tls_custom_port_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-custom-port.yaml"
ext_auth_pol_tls_signin_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-signin.yaml"
ext_auth_pol_tls_disabled_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-disabled.yaml"
ext_auth_pol_tls_full_multi_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-full-multi.yaml"

# Standard VS (used to restore VS state after tests)
std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"

# ---------------------------------------------------------------------------
# Ingress setup helper
# ---------------------------------------------------------------------------


class IngressSetup:
    """Encapsulate Ingress test setup details."""

    def __init__(self, ingress_host, request_url, ingress_src, namespace, metrics_url):
        self.ingress_host = ingress_host
        self.request_url = request_url
        self.ingress_src = ingress_src
        self.namespace = namespace
        self.metrics_url = metrics_url


def create_ingress_setup(
    kube_apis,
    ingress_controller_endpoint,
    ingress_controller_prerequisites,
    test_namespace,
    ingress_src,
    e2e_run_id,
):
    """Deploy the backend app and create the Ingress, returning an IngressSetup."""
    create_example_app(kube_apis, "simple", test_namespace, e2e_run_id)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace, get_e2e_run_selector(e2e_run_id))

    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
    count_before = get_reload_count(metrics_url)
    create_items_from_yaml(kube_apis, ingress_src, test_namespace, e2e_run_id)

    ingress_host = get_first_ingress_host_from_yaml(ingress_src)
    request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"

    wait_for_reload(metrics_url, count_before)

    return IngressSetup(ingress_host, request_url, ingress_src, test_namespace, metrics_url)


def delete_ingress_setup(kube_apis, ingress_setup):
    """Delete the Ingress and backend app."""
    delete_items_from_yaml(kube_apis, ingress_setup.ingress_src, ingress_setup.namespace)
    delete_common_app(kube_apis, "simple", ingress_setup.namespace)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def to_base64(b64_string):
    """Encode a string to base64."""
    return b64encode(b64_string.encode("ascii")).decode("ascii")


def valid_auth_headers():
    """Return Authorization header with valid credentials for ensure_response_from_backend."""
    with open(valid_credentials) as f:
        data = f.readline().strip()
    return {"authorization": f"Basic {to_base64(data)}"}


def build_ext_auth_headers(vs_host, credentials=None):
    """Build request headers for external auth tests.

    Args:
        vs_host: The VirtualServer/VSR host header value.
        credentials: Path to credentials file, or None for no-auth requests.

    Returns:
        Dict with 'host' and optionally 'authorization' keys.
    """
    if credentials is None:
        return {"host": vs_host}
    with open(credentials) as f:
        data = f.readline().strip()
    return {"host": vs_host, "authorization": f"Basic {to_base64(data)}"}


def _teardown_ext_auth_resources(kube_apis, namespace, secret_names, policy_names, *, tls=False):
    """Teardown external auth backend (HTTP or TLS).

    Args:
        kube_apis: KubeApis instance.
        namespace: Kubernetes namespace.
        secret_names: List of secret names to delete.
        policy_names: List of policy names to delete.
        tls: If True, use TLS backend YAML for deletion.
    """
    teardown_policy_backend(
        kube_apis,
        namespace,
        backend_yaml=ext_auth_tls_backend_src if tls else ext_auth_backend_src,
        secret_names=secret_names,
        policy_names=policy_names,
    )


# ---------------------------------------------------------------------------
# Setup / teardown helpers
# ---------------------------------------------------------------------------


def setup_ext_auth(
    kube_apis,
    namespace,
    credentials,
    policy_yamls,
    vs_host,
    *,
    e2e_run_id=None,
    tls=False,
    validate_policies=True,
):
    """Setup external auth backend (HTTP or TLS) with policies and request headers.

    Args:
        kube_apis: KubeApis instance.
        namespace: Kubernetes namespace.
        credentials: Path to credentials file, or None for no-auth requests.
        policy_yamls: List of policy YAML file paths (1 or more).
        vs_host: The VirtualServer/VSR host header value.
        e2e_run_id: Run ID applied to the external auth backend workload.
        tls: If True, deploy TLS backend with server TLS and CA secrets.
        validate_policies: If True, wait for each policy to reach Valid state.

    Returns:
        (secret_names: list[str], policy_names: list[str], headers: dict)
    """
    e2e_run_id = e2e_run_id or generate_e2e_run_id()
    if tls:
        secret_yamls = [
            ext_auth_backend_secret_src,
            ext_auth_tls_server_secret_src,
            ext_auth_tls_ca_secret_src,
        ]
        backend_yaml = ext_auth_tls_backend_src
    else:
        secret_yamls = [ext_auth_backend_secret_src]
        backend_yaml = ext_auth_backend_src

    secret_names, policy_names = setup_policy_backend(
        kube_apis,
        namespace,
        secret_yamls=secret_yamls,
        backend_yaml=backend_yaml,
        policy_yamls=policy_yamls,
        e2e_run_id=e2e_run_id,
        validate_policies=validate_policies,
        wait_for_service="external-auth-svc",
    )
    headers = build_ext_auth_headers(vs_host, credentials)
    return secret_names, policy_names, headers


def teardown_ext_auth(kube_apis, namespace, secret_names, policy_names, *, tls=False):
    """Teardown external auth backend (HTTP or TLS).

    Args:
        kube_apis: KubeApis instance.
        namespace: Kubernetes namespace.
        secret_names: List of secret names to delete.
        policy_names: List of policy names to delete.
        tls: If True, use TLS backend YAML for deletion.
    """
    teardown_policy_backend(
        kube_apis,
        namespace,
        backend_yaml=ext_auth_tls_backend_src if tls else ext_auth_backend_src,
        secret_names=secret_names,
        policy_names=policy_names,
    )


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ext_auth_setup(request, kube_apis, test_namespace, e2e_run_id):
    """Parametrized fixture that deploys the external auth backend and policies.

    ``request.param`` is a tuple: ``(policy_yamls[, tls[, validate_policies[, ca_secret_src]]])``.

    .. code-block:: python

        @pytest.mark.parametrize("ext_auth_setup", [
            ([ext_auth_pol_valid_src],),
        ], indirect=True)
        def test_something(self, ext_auth_setup, ...):
            secret_names, policy_names = ext_auth_setup
            headers = build_ext_auth_headers("host", valid_credentials)

    Teardown is guaranteed via ``request.addfinalizer`` -- even when the test
    raises an exception or deletes resources mid-test.
    """
    params = request.param
    policy_yamls = params[0]
    tls = params[1] if len(params) > 1 else False
    validate_policies = params[2] if len(params) > 2 else True
    ca_secret_src = params[3] if len(params) > 3 else ext_auth_tls_ca_secret_src

    backend_yaml = ext_auth_tls_backend_src if tls else ext_auth_backend_src
    secret_yamls = (
        [ext_auth_backend_secret_src, ext_auth_tls_server_secret_src, ca_secret_src]
        if tls
        else [ext_auth_backend_secret_src]
    )

    secret_names, policy_names = setup_policy_backend(
        kube_apis,
        test_namespace,
        secret_yamls=secret_yamls,
        backend_yaml=backend_yaml,
        policy_yamls=policy_yamls,
        e2e_run_id=e2e_run_id,
        validate_policies=validate_policies,
        wait_for_service="external-auth-svc",
    )

    def fin():
        try:
            _teardown_ext_auth_resources(kube_apis, test_namespace, secret_names, policy_names, tls=tls)
        except Exception:
            logger.debug("ext_auth_setup teardown: ignoring error (resource may already be deleted)")

    request.addfinalizer(fin)
    return secret_names, policy_names


@pytest.fixture
def ext_auth_ingress(
    request,
    kube_apis,
    ingress_controller_endpoint,
    ingress_controller_prerequisites,
    test_namespace,
    e2e_run_id,
):
    """Parametrized fixture that creates an Ingress with guaranteed teardown.

    The ingress YAML path is provided via ``request.param``:

    .. code-block:: python

        @pytest.mark.parametrize("ext_auth_ingress", [my_ingress_src], indirect=True)
        def test_something(self, ext_auth_ingress, ...):
            resp = requests.get(ext_auth_ingress.request_url, headers=headers)
    """
    ing = create_ingress_setup(
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
        request.param,
        e2e_run_id,
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            try:
                delete_ingress_setup(kube_apis, ing)
            except Exception:
                logger.debug("ext_auth_ingress teardown: ignoring error (resource may already be deleted)")

    request.addfinalizer(fin)
    return ing


@pytest.fixture
def ext_auth_restore_vs(kube_apis, virtual_server_setup):
    """Restore the standard VirtualServer spec after each test.

    This ensures the VS is returned to its baseline state even when a test
    raises an exception mid-way through.
    """
    yield

    try:
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )
    except Exception:
        logger.debug("ext_auth_restore_vs teardown: ignoring error during VS restore")


# ---------------------------------------------------------------------------
# authResponseHeaders acceptance scenarios
# (docs/developer/external-auth-response-headers-high-level-design.md)
# ---------------------------------------------------------------------------

headers_echo_backend_src = f"{TEST_DATA}/external-auth/backend/headers-echo-backend.yaml"
ext_auth_pol_response_headers_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-response-headers.yaml"


# Listed by Policy P, and returned by the test auth services on every response.
RETURNED_HEADERS = (("Tenant-UUID", "tenant-123"), ("User-UUID", "user-456"), ("X-Session-ID", "session-789"))

# The longest name the field accepts. The test auth services return it.
LONGEST_HEADER_NAME = "X-Longest-Auth-Response-Header-Name-Allowed-46"


def deploy_headers_echo(kube_apis, namespace, e2e_run_id):
    """Deploy the echo backend that reports request header lines, and wait for it."""
    create_items_from_yaml(kube_apis, headers_echo_backend_src, namespace, e2e_run_id)
    wait_until_all_pods_are_ready(kube_apis.v1, namespace, get_e2e_run_selector(e2e_run_id))


def delete_headers_echo(kube_apis, namespace):
    """Delete the echo backend."""
    delete_items_from_yaml(kube_apis, headers_echo_backend_src, namespace)


@pytest.fixture
def headers_echo_backend(request, kube_apis, test_namespace, e2e_run_id):
    """Deploy the echo backend in the test namespace, with guaranteed teardown."""
    deploy_headers_echo(kube_apis, test_namespace, e2e_run_id)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            try:
                delete_headers_echo(kube_apis, test_namespace)
            except Exception:
                logger.debug("headers_echo_backend teardown: ignoring error (resource may already be deleted)")

    request.addfinalizer(fin)
    return test_namespace


@pytest.fixture
def ext_auth_http2_config(request, kube_apis, ingress_controller_prerequisites, test_namespace):
    """Turn on HTTP/2 in the ConfigMap, and add the TLS secret of the gRPC VirtualServers."""
    cm_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
    cm_namespace = ingress_controller_prerequisites.namespace
    replace_configmap_from_yaml(
        kube_apis.v1, cm_name, cm_namespace, f"{TEST_DATA}/virtual-server-grpc/nginx-config.yaml"
    )
    secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/virtual-server-grpc/tls-secret.yaml"
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            delete_secret(kube_apis.v1, secret_name, test_namespace)
            replace_configmap_from_yaml(kube_apis.v1, cm_name, cm_namespace, f"{DEPLOYMENTS}/common/nginx-config.yaml")

    request.addfinalizer(fin)


def echoed_lines(body):
    """Return the request header lines that the echo backend reports, as (name, value) pairs."""
    return [(name, value) for name, value in json.loads(body)["headers"]]


def header_values(lines, name):
    """Return the values of every line named name, compared ignoring case, in order."""
    return [value for line_name, value in lines if line_name.lower() == name.lower()]


def lines_named(lines, name):
    """Return the lines named name, compared ignoring case, each with its own spelling."""
    return [(line_name, value) for line_name, value in lines if line_name.lower() == name.lower()]


def request_echo(url, host, headers=None, credentials=valid_credentials):
    """Send a request through NIC, with credentials and extra headers, and return the response."""
    request_headers = build_ext_auth_headers(host, credentials)
    request_headers.update(headers or {})
    return requests.get(url, headers=request_headers)


def request_lines(url, host, headers=None, credentials=valid_credentials):
    """Send a request through NIC, and return the header lines that the echo backend received."""
    resp = request_echo(url, host, headers, credentials)
    assert resp.status_code == 200, resp.text
    return echoed_lines(resp.text)


def wait_and_request_lines(url, host, headers=None):
    """Wait until NIC answers with valid credentials, then return the lines of a request with extra headers."""
    ensure_response_from_backend(url, host, additional_headers=valid_auth_headers(), check404=True)
    return request_lines(url, host, headers)


def apply_vs_and_wait(kube_apis, setup, vs_src):
    """Replace the VirtualServer, check that it is Valid, and wait until it answers."""
    apply_and_assert_valid_vs(kube_apis, setup.namespace, setup.vs_name, vs_src)
    ensure_response_from_backend(setup.backend_1_url, setup.vs_host, additional_headers=valid_auth_headers())


def echo_from_pod(kube_apis, namespace, headers):
    """Send a request straight to the echo backend from inside its pod, and return the lines it reports."""
    pod = get_first_pod_name(kube_apis.v1, namespace, "app=headers-echo")
    command = ["wget", "-qO-"]
    for name, value in headers.items():
        command += ["--header", f"{name}: {value}"]
    command.append("http://127.0.0.1:8080/")
    body = stream(
        kube_apis.v1.connect_get_namespaced_pod_exec,
        pod,
        namespace,
        command=command,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
    )
    return echoed_lines(body)


def grpc_auth_metadata(extra=()):
    """Return gRPC call metadata with valid credentials, followed by extra entries."""
    return (("authorization", valid_auth_headers()["authorization"]),) + tuple(extra)


def _say_hello_lines(channel_factory, metadata, attempts):
    for attempt in range(attempts):
        with channel_factory() as channel:
            try:
                reply = GreeterStub(channel).SayHello(HelloRequest(name="scenario"), metadata=metadata, timeout=10)
                return echoed_lines(reply.message)
            except grpc.RpcError as e:
                if attempt == attempts - 1:
                    pytest.fail(f"gRPC call failed: {e.code()} {e.details()}")
                wait_before_test()


def grpc_tls_lines(endpoint, host, metadata, attempts=10):
    """Call the gRPC echo backend through NIC over TLS, and return the metadata it received."""
    cert = get_certificate(endpoint.public_ip, host, endpoint.port_ssl)
    credentials = grpc.ssl_channel_credentials(root_certificates=cert.encode())
    options = (("grpc.ssl_target_name_override", host),)
    return _say_hello_lines(
        lambda: grpc.secure_channel(f"{endpoint.public_ip}:{endpoint.port_ssl}", credentials, options),
        metadata,
        attempts,
    )

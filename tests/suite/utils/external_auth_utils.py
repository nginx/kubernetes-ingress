"""Shared helpers, file path constants, and fixtures for external auth policy tests."""

import logging
from base64 import b64encode

import pytest
from settings import TEST_DATA
from suite.utils.policy_resources_utils import (
    setup_policy_backend,
    teardown_policy_backend,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    get_reload_count,
    wait_for_reload,
    wait_until_all_pods_are_ready,
)
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
ext_auth_pol_cross_ns_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-cross-ns.yaml"
ext_auth_pol_signin_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-signin.yaml"
ext_auth_pol_custom_port_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-custom-port.yaml"

# TLS backend and secrets
ext_auth_tls_backend_src = f"{TEST_DATA}/external-auth/backend/external-auth-backend-tls.yaml"
ext_auth_tls_server_secret_src = f"{TEST_DATA}/external-auth/backend/external-auth-server-tls-secret.yaml"
ext_auth_tls_ca_secret_src = f"{TEST_DATA}/external-auth/backend/external-auth-ca-secret.yaml"
ext_auth_tls_wrong_ca_src = f"{TEST_DATA}/external-auth/backend/wrong-type-ca-secret.yaml"

# TLS policies
ext_auth_pol_tls_basic_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-basic.yaml"
ext_auth_pol_tls_full_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-full.yaml"
ext_auth_pol_tls_nonexistent_ca_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-nonexistent-ca.yaml"
ext_auth_pol_tls_wrong_ca_type_src = f"{TEST_DATA}/external-auth/policies/external-auth-policy-tls-wrong-ca-type.yaml"
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
):
    """Deploy the backend app and create the Ingress, returning an IngressSetup."""
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
    count_before = get_reload_count(metrics_url)
    create_items_from_yaml(kube_apis, ingress_src, test_namespace)

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
        tls: If True, deploy TLS backend with server TLS and CA secrets.
        validate_policies: If True, wait for each policy to reach Valid state.

    Returns:
        (secret_names: list[str], policy_names: list[str], headers: dict)
    """
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
        validate_policies=validate_policies,
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
def ext_auth_setup(kube_apis, test_namespace):
    """Factory fixture that creates external auth resources with guaranteed teardown.

    Yields a callable with the same interface as ``setup_ext_auth`` minus
    ``kube_apis`` and ``namespace`` (they are captured from the enclosing
    fixtures).  Resources are tracked and torn down after the test completes
    -- even when the test raises an exception.

    Destructive tests that manually delete a resource mid-test are safe:
    the teardown silently ignores resources that no longer exist.
    """
    created = []

    def _setup(credentials, policy_yamls, vs_host, *, tls=False, validate_policies=True):
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            credentials,
            policy_yamls,
            vs_host,
            tls=tls,
            validate_policies=validate_policies,
        )
        created.append((secret_names, policy_names, tls))
        return secret_names, policy_names, headers

    yield _setup

    for secret_names, policy_names, tls in reversed(created):
        try:
            teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=tls)
        except Exception:
            logger.debug("ext_auth_setup teardown: ignoring error (resource may already be deleted)")


@pytest.fixture
def ext_auth_ingress(
    kube_apis,
    ingress_controller_endpoint,
    ingress_controller_prerequisites,
    test_namespace,
):
    """Factory fixture that creates Ingress resources with guaranteed teardown.

    Yields a callable that accepts an ``ingress_src`` path and returns an
    ``IngressSetup`` instance.  All created Ingress resources are deleted
    after the test completes -- even when the test raises an exception.
    """
    created = []

    def _setup(ingress_src):
        ing = create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ingress_src,
        )
        created.append(ing)
        return ing

    yield _setup

    for ing in reversed(created):
        try:
            delete_ingress_setup(kube_apis, ing)
        except Exception:
            logger.debug("ext_auth_ingress teardown: ignoring error (resource may already be deleted)")

"""Shared helpers and file path constants for external auth policy tests (VS and VSR)."""

from base64 import b64encode

from settings import TEST_DATA
from suite.utils.policy_resources_utils import setup_policy_backend, teardown_policy_backend

# ---------------------------------------------------------------------------
# Shared file path constants
# ---------------------------------------------------------------------------

# HTTP backend and credentials
ext_auth_backend_secret_src = f"{TEST_DATA}/external-auth-policy/backend/htpasswd-secret.yaml"
ext_auth_backend_src = f"{TEST_DATA}/external-auth-policy/backend/external-auth-backend.yaml"
valid_credentials = f"{TEST_DATA}/external-auth-policy/credentials.txt"
invalid_credentials = f"{TEST_DATA}/external-auth-policy/invalid-credentials.txt"

# HTTP policies (no TLS)
ext_auth_pol_valid_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-valid.yaml"
ext_auth_pol_valid_multi_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-valid-multi.yaml"
ext_auth_pol_invalid_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-invalid.yaml"
ext_auth_pol_invalid_svc_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-invalid-svc.yaml"
ext_auth_pol_cross_ns_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-cross-ns.yaml"
ext_auth_pol_signin_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-signin.yaml"
ext_auth_pol_custom_port_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-custom-port.yaml"

# TLS backend and secrets
ext_auth_tls_backend_src = f"{TEST_DATA}/external-auth-policy/backend/external-auth-backend-tls.yaml"
ext_auth_tls_server_secret_src = f"{TEST_DATA}/external-auth-policy/backend/external-auth-server-tls-secret.yaml"
ext_auth_tls_ca_secret_src = f"{TEST_DATA}/external-auth-policy/backend/external-auth-ca-secret.yaml"
ext_auth_tls_wrong_ca_src = f"{TEST_DATA}/external-auth-policy/backend/wrong-type-ca-secret.yaml"

# TLS policies
ext_auth_pol_tls_basic_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-basic.yaml"
ext_auth_pol_tls_full_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-full.yaml"
ext_auth_pol_tls_nonexistent_ca_src = (
    f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-nonexistent-ca.yaml"
)
ext_auth_pol_tls_wrong_ca_type_src = (
    f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-wrong-ca-type.yaml"
)
ext_auth_pol_tls_bad_sni_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-bad-sni.yaml"
ext_auth_pol_tls_cross_ns_ca_src = (
    f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-cross-ns-ca.yaml"
)
ext_auth_pol_tls_no_trusted_cert_src = (
    f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-no-trusted-cert.yaml"
)
ext_auth_pol_tls_default_sni_src = (
    f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-default-sni.yaml"
)
ext_auth_pol_tls_verify_no_ssl_src = (
    f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-verify-no-ssl.yaml"
)
ext_auth_pol_tls_custom_port_src = (
    f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-custom-port.yaml"
)
ext_auth_pol_tls_signin_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-signin.yaml"
ext_auth_pol_tls_disabled_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-disabled.yaml"
ext_auth_pol_tls_full_multi_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-tls-full-multi.yaml"


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


def setup_ext_auth(kube_apis, namespace, credentials, policy_yamls, vs_host, *, tls=False, validate_policies=True):
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
        secret_yamls = [ext_auth_backend_secret_src, ext_auth_tls_server_secret_src, ext_auth_tls_ca_secret_src]
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

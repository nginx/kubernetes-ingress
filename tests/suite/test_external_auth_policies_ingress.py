import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.external_auth_utils import (
    ext_auth_backend_src,
    ext_auth_pol_custom_port_src,
    ext_auth_pol_invalid_src,
    ext_auth_pol_invalid_svc_src,
    ext_auth_pol_signin_src,
    ext_auth_pol_tls_bad_sni_src,
    ext_auth_pol_tls_basic_src,
    ext_auth_pol_tls_cross_ns_ca_src,
    ext_auth_pol_tls_custom_port_src,
    ext_auth_pol_tls_default_sni_src,
    ext_auth_pol_tls_disabled_src,
    ext_auth_pol_tls_full_multi_src,
    ext_auth_pol_tls_full_src,
    ext_auth_pol_tls_no_trusted_cert_src,
    ext_auth_pol_tls_nonexistent_ca_src,
    ext_auth_pol_tls_signin_src,
    ext_auth_pol_tls_verify_no_ssl_src,
    ext_auth_pol_tls_wrong_ca_type_src,
    ext_auth_pol_valid_multi_src,
    ext_auth_pol_valid_src,
    ext_auth_tls_backend_src,
    ext_auth_tls_wrong_ca_src,
    invalid_credentials,
    setup_ext_auth,
    teardown_ext_auth,
    valid_auth_headers,
    valid_credentials,
)
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy, read_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_secret,
    ensure_response_from_backend,
    get_reload_count,
    wait_before_test,
    wait_for_reload,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

# ---------------------------------------------------------------------------
# Ingress manifest paths
# ---------------------------------------------------------------------------

# Standard (single) Ingress variants
ext_auth_ing_standard_src = f"{TEST_DATA}/external-auth/ingress/standard/ext-auth-ingress.yaml"
ext_auth_ing_standard_invalid_svc_src = f"{TEST_DATA}/external-auth/ingress/standard-invalid-svc/ext-auth-ingress.yaml"
ext_auth_ing_standard_signin_src = f"{TEST_DATA}/external-auth/ingress/standard-signin/ext-auth-ingress.yaml"
ext_auth_ing_standard_custom_port_src = f"{TEST_DATA}/external-auth/ingress/standard-custom-port/ext-auth-ingress.yaml"
ext_auth_ing_standard_multi_src = f"{TEST_DATA}/external-auth/ingress/standard-multi/ext-auth-ingress.yaml"

# Standard TLS Ingress variants
ext_auth_ing_standard_tls_src = f"{TEST_DATA}/external-auth/ingress/standard-tls/ext-auth-ingress.yaml"
ext_auth_ing_standard_tls_multi_src = f"{TEST_DATA}/external-auth/ingress/standard-tls-multi/ext-auth-ingress.yaml"

# Mergeable Ingress variants
ext_auth_ing_mergeable_src = f"{TEST_DATA}/external-auth/ingress/mergeable/ext-auth-ingress.yaml"
ext_auth_ing_mergeable_invalid_svc_src = (
    f"{TEST_DATA}/external-auth/ingress/mergeable-invalid-svc/ext-auth-ingress.yaml"
)
ext_auth_ing_mergeable_tls_src = f"{TEST_DATA}/external-auth/ingress/mergeable-tls/ext-auth-ingress.yaml"
ext_auth_ing_minion_policy_src = f"{TEST_DATA}/external-auth/ingress/minion-policy/ext-auth-ingress.yaml"
ext_auth_ing_mergeable_override_src = f"{TEST_DATA}/external-auth/ingress/mergeable-override/ext-auth-ingress.yaml"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


class IngressSetup:
    """Encapsulate Ingress test setup details."""

    def __init__(self, ingress_host, request_url, ingress_src, namespace, metrics_url):
        self.ingress_host = ingress_host
        self.request_url = request_url
        self.ingress_src = ingress_src
        self.namespace = namespace
        self.metrics_url = metrics_url


def _create_ingress_setup(
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


def _delete_ingress_setup(kube_apis, ingress_setup):
    """Delete the Ingress and backend app."""
    delete_items_from_yaml(kube_apis, ingress_setup.ingress_src, ingress_setup.namespace)
    delete_common_app(kube_apis, "simple", ingress_setup.namespace)


# ============================================================================
# HTTP (non-TLS) External Auth Policies on Ingress
# ============================================================================


@pytest.mark.policies
@pytest.mark.policies_external_auth
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        {
            "type": "complete",
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-leader-election=false",
                f"-enable-prometheus-metrics",
            ],
        },
    ],
    indirect=True,
)
class TestExternalAuthPoliciesIngress:
    # ------------------------------------------------------------------
    # Valid policy tests
    # ------------------------------------------------------------------

    @pytest.mark.smoke
    def test_external_auth_policy_valid_standard(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy on a standard Ingress with valid credentials.
        Verifies the policy CRD status is Valid and the backend proxies correctly.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_src,
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_external_auth_policy_valid_mergeable(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy on a mergeable Ingress (policy on master).
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_mergeable_src,
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        ensure_response_from_backend(
            ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers(), check404=True
        )

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    # ------------------------------------------------------------------
    # Credentials tests
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_external_auth_policy_credentials_standard(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
        credentials,
    ):
        """
        Test external-auth policy on standard Ingress with valid, invalid, and no credentials.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_external_auth_policy_credentials_mergeable(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
        credentials,
    ):
        """
        Test external-auth policy on mergeable Ingress (policy on master)
        with valid, invalid, and no credentials.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_mergeable_src,
        )
        ensure_response_from_backend(
            ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers(), check404=True
        )

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_external_auth_policy_credentials_minion(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
        credentials,
    ):
        """
        Test external-auth policy on mergeable Ingress with policy on the minion
        (location-level auth) with valid, invalid, and no credentials.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_minion_policy_src,
        )
        ensure_response_from_backend(
            ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers(), check404=True
        )

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    # ------------------------------------------------------------------
    # CRD validation test
    # ------------------------------------------------------------------

    @pytest.mark.smoke
    def test_external_auth_policy_invalid_rejected_by_crd(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
    ):
        """
        Test that a policy with an invalid authURI (no leading slash) is rejected
        at the CRD validation level by the Kubernetes API server.
        """
        with pytest.raises(ApiException) as exc_info:
            create_policy_from_yaml(kube_apis.custom_objects, ext_auth_pol_invalid_src, test_namespace)

        assert exc_info.value.status == 422
        assert "authURI" in exc_info.value.body

    # ------------------------------------------------------------------
    # Non-existent service tests
    # ------------------------------------------------------------------

    def test_external_auth_policy_nonexistent_svc_standard(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy on standard Ingress that references a non-existent service.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_invalid_svc_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_invalid_svc_src,
        )
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        assert resp.status_code == 500
        assert "Internal Server Error" in resp.text

    def test_external_auth_policy_nonexistent_svc_mergeable(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy on mergeable Ingress that references a non-existent service.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_invalid_svc_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_mergeable_invalid_svc_src,
        )
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        assert resp.status_code == 500
        assert "Internal Server Error" in resp.text

    # ------------------------------------------------------------------
    # Delete policy tests
    # ------------------------------------------------------------------

    def test_external_auth_policy_delete_policy_standard(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that deleting the external auth policy causes HTTP 500 on a standard Ingress.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete: {resp1.status_code}")

        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete: {resp2.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    def test_external_auth_policy_delete_policy_mergeable(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that deleting the external auth policy causes HTTP 500 on a mergeable Ingress.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_mergeable_src,
        )
        ensure_response_from_backend(
            ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers(), check404=True
        )

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete: {resp1.status_code}")

        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete: {resp2.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    # ------------------------------------------------------------------
    # Delete backend test
    # ------------------------------------------------------------------

    def test_external_auth_policy_delete_backend(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that deleting the external auth backend service causes HTTP 500.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete: {resp1.status_code}")

        print("Delete external auth backend")
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete: {resp2.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    # ------------------------------------------------------------------
    # Override / precedence tests
    # ------------------------------------------------------------------

    def test_external_auth_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that when multiple policies are referenced in the nginx.org/policies
        annotation, the first listed policy takes precedence.
        Both policies reference the same auth backend, so the request should succeed.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_multi_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_external_auth_policy_master_vs_minion_override(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that a policy on the minion takes precedence over a policy on the master
        for the minion's path. Master has 'valid-multi', minion has 'valid'.
        Both reference the same backend, so the request should succeed.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_mergeable_override_src,
        )
        ensure_response_from_backend(
            ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers(), check404=True
        )

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    # ------------------------------------------------------------------
    # Signin URI test
    # ------------------------------------------------------------------

    def test_external_auth_policy_signin_uri(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy with authSigninURI set on a standard Ingress.
        Verifies the policy is accepted as Valid and authenticated requests pass through.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_signin_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_signin_src,
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        assert policy_info["status"]["state"] == "Valid"
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    # ------------------------------------------------------------------
    # Custom port test
    # ------------------------------------------------------------------

    def test_external_auth_policy_custom_port(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy with authServicePorts set to a custom port (8080).
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_custom_port_src],
            "ext-auth-ingress.example.com",
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_custom_port_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text


# ============================================================================
# TLS External Auth Policies on Ingress
# ============================================================================


@pytest.mark.policies
@pytest.mark.policies_external_auth
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        {
            "type": "complete",
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-leader-election=false",
                f"-enable-prometheus-metrics",
            ],
        },
    ],
    indirect=True,
)
class TestExternalAuthPoliciesIngressTLS:
    """Test external-auth policies with TLS configurations on Ingress resources."""

    # ------------------------------------------------------------------
    # Positive TLS tests
    # ------------------------------------------------------------------

    def test_tls_ssl_enabled_only(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy with sslEnabled: true only (no certificate verification).
        The IC connects to the auth backend over HTTPS but does not verify its certificate.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_basic_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.smoke
    def test_tls_full_verify_standard(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy with full TLS verification on standard Ingress:
        sslEnabled, sslVerify, sslVerifyDepth, sniName, and trustedCertSecret.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        assert policy_info["status"]["state"] == "Valid"

        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_tls_full_verify_mergeable(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy with full TLS verification on mergeable Ingress
        (policy on master).
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_mergeable_tls_src,
        )
        ensure_response_from_backend(
            ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers(), check404=True
        )

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_tls_credentials(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
        credentials,
    ):
        """
        Test external-auth policy with full TLS using valid, invalid, and no credentials.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    def test_tls_http_fallback(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that a TLS-capable backend still serves HTTP when sslEnabled is explicitly false.
        The IC connects over HTTP (port 80) even though the backend also listens on HTTPS.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_disabled_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_tls_signin_uri(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy with sslEnabled and authSigninURI on Ingress.
        Verifies the policy is Valid and authenticated requests pass through over TLS.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_signin_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])

        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert policy_info["status"]["state"] == "Valid"
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_tls_custom_port(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test external-auth policy with sslEnabled and authServicePorts: [8443].
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_custom_port_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    # ------------------------------------------------------------------
    # Controller error tests (HTTP 500)
    # ------------------------------------------------------------------

    def test_tls_verify_without_ssl_enabled(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that sslVerify: true without sslEnabled: true causes an error.
        The IC treats this as an invalid configuration, resulting in HTTP 500.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_verify_no_ssl_src],
            "ext-auth-ingress.example.com",
            tls=True,
            validate_policies=False,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 500

    def test_tls_nonexistent_ca_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that referencing a non-existent trustedCertSecret results in HTTP 500.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_nonexistent_ca_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 500

    def test_tls_wrong_ca_secret_type(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that referencing a trustedCertSecret with wrong type (kubernetes.io/tls
        instead of nginx.org/ca) results in HTTP 500.
        """
        print("Create wrong-type CA secret")
        wrong_secret = create_secret_from_yaml(kube_apis.v1, test_namespace, ext_auth_tls_wrong_ca_src)

        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_wrong_ca_type_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)
        delete_secret(kube_apis.v1, wrong_secret, test_namespace)

        assert resp.status_code == 500

    def test_tls_cross_ns_nonexistent_ca(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that referencing a trustedCertSecret in a non-existent namespace
        (fakens/external-auth-ca-secret) results in HTTP 500.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_cross_ns_ca_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 500

    # ------------------------------------------------------------------
    # Runtime TLS failure tests (HTTP 500)
    # ------------------------------------------------------------------

    def test_tls_bad_sni_name(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that an incorrect sniName (wrong-name.example.com) causes TLS
        verification failure at runtime. The auth_request module returns HTTP 500
        for subrequest failures.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_bad_sni_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 500

    def test_tls_verify_no_trusted_cert(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that sslVerify: true without trustedCertSecret falls back to the
        system CA bundle. Since the auth backend uses a self-signed certificate,
        the system CA cannot verify it, causing HTTP 500.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_no_trusted_cert_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 500

    def test_tls_default_sni_mismatch(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that omitting sniName with sslVerify causes a TLS verification failure.
        The default SNI name (<svcName>.<svcNs>.svc) does not match the server
        certificate SAN (external-auth-tls), so NGINX rejects the connection (HTTP 500).
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_default_sni_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)

        assert resp.status_code == 500

    # ------------------------------------------------------------------
    # Lifecycle / destructive tests
    # ------------------------------------------------------------------

    def test_tls_delete_ca_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that deleting the CA secret (trustedCertSecret) after a working
        TLS setup causes HTTP 500 for subsequent requests.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete - Status: {resp1.status_code}")

        print("Delete CA secret")
        delete_secret(kube_apis.v1, secret_names[2], test_namespace)  # ca_secret
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete - Status: {resp2.status_code}")

        # Cleanup (ca_secret already deleted)
        _delete_ingress_setup(kube_apis, ing)
        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)  # htpasswd_secret
        delete_secret(kube_apis.v1, secret_names[1], test_namespace)  # tls_secret

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    def test_tls_delete_server_tls_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test behavior after deleting the server TLS secret (external-auth-server-tls-secret).
        This secret is mounted in the backend pod, not referenced by the IC policy.
        The running backend retains the cert in memory, so requests continue to succeed.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete - Status: {resp1.status_code}")

        print("Delete server TLS secret")
        delete_secret(kube_apis.v1, secret_names[1], test_namespace)  # tls_secret
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete - Status: {resp2.status_code}")

        # Cleanup (tls_secret already deleted)
        _delete_ingress_setup(kube_apis, ing)
        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)  # htpasswd_secret
        delete_secret(kube_apis.v1, secret_names[2], test_namespace)  # ca_secret

        assert resp1.status_code == 200
        # Backend retains cert in memory; IC config unchanged; request should still succeed
        assert resp2.status_code == 200

    def test_tls_delete_backend(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that requests fail when the TLS external auth backend service is deleted.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete - Status: {resp1.status_code}")

        print("Delete TLS external auth backend")
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, test_namespace)
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete - Status: {resp2.status_code}")

        # Cleanup (backend already deleted)
        _delete_ingress_setup(kube_apis, ing)
        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)  # htpasswd_secret
        delete_secret(kube_apis.v1, secret_names[1], test_namespace)  # tls_secret
        delete_secret(kube_apis.v1, secret_names[2], test_namespace)  # ca_secret

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    # ------------------------------------------------------------------
    # Override / precedence test
    # ------------------------------------------------------------------

    def test_tls_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Test that when multiple TLS policies are referenced in the annotation,
        the first listed policy takes precedence. Both TLS policies reference the
        same backend with the same TLS config, so both orderings should succeed.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src, ext_auth_pol_tls_full_multi_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = _create_ingress_setup(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            ext_auth_ing_standard_tls_multi_src,
        )
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        _delete_ingress_setup(kube_apis, ing)
        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_policy(kube_apis.custom_objects, policy_names[1], test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)  # htpasswd_secret
        delete_secret(kube_apis.v1, secret_names[1], test_namespace)  # tls_secret
        delete_secret(kube_apis.v1, secret_names[2], test_namespace)  # ca_secret

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

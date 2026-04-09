import pytest
import requests
from settings import TEST_DATA
from suite.utils.external_auth_utils import (
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
    ext_auth_tls_backend_src,
    ext_auth_tls_wrong_ca_src,
    invalid_credentials,
    valid_auth_headers,
    valid_credentials,
)
from suite.utils.policy_resources_utils import delete_policy, read_policy
from suite.utils.resources_utils import (
    create_secret_from_yaml,
    delete_items_from_yaml,
    delete_secret,
    ensure_response_from_backend,
    wait_before_test,
)

# ---------------------------------------------------------------------------
# Ingress manifest paths
# ---------------------------------------------------------------------------

# Standard TLS Ingress variants
ext_auth_ing_standard_tls_src = f"{TEST_DATA}/external-auth/ingress/standard-tls/ext-auth-ingress.yaml"
ext_auth_ing_standard_tls_multi_src = f"{TEST_DATA}/external-auth/ingress/standard-tls-multi/ext-auth-ingress.yaml"

# Mergeable TLS Ingress variant
ext_auth_ing_mergeable_tls_src = f"{TEST_DATA}/external-auth/ingress/mergeable-tls/ext-auth-ingress.yaml"


# ============================================================================
# TLS External Auth Policies on Ingress
# ============================================================================


@pytest.mark.policies
@pytest.mark.policies_external_auth
@pytest.mark.policies_external_auth_tls
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
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy with sslEnabled: true only (no certificate verification).
        The IC connects to the auth backend over HTTPS but does not verify its certificate.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_basic_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.smoke
    def test_tls_full_verify_standard(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy with full TLS verification on standard Ingress:
        sslEnabled, sslVerify, sslVerifyDepth, sniName, and trustedCertSecret.
        """
        _secret_names, policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        assert policy_info["status"]["state"] == "Valid"

        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_tls_full_verify_mergeable(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy with full TLS verification on mergeable Ingress
        (policy on master).
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_mergeable_tls_src)
        ensure_response_from_backend(
            ing.request_url,
            ing.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=True,
        )

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_tls_credentials(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
        credentials,
    ):
        """
        Test external-auth policy with full TLS using valid, invalid, and no credentials.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    def test_tls_http_fallback(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that a TLS-capable backend still serves HTTP when sslEnabled is explicitly false.
        The IC connects over HTTP (port 80) even though the backend also listens on HTTPS.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_disabled_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_tls_signin_uri(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy with sslEnabled and authSigninURI on Ingress.
        Verifies the policy is Valid and authenticated requests pass through over TLS.
        """
        _secret_names, policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_signin_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])

        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert policy_info["status"]["state"] == "Valid"
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_tls_custom_port(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy with sslEnabled and authServicePorts: [8443].
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_custom_port_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    # ------------------------------------------------------------------
    # Controller error tests (HTTP 500)
    # ------------------------------------------------------------------

    def test_tls_verify_without_ssl_enabled(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that sslVerify: true without sslEnabled: true causes an error.
        The IC treats this as an invalid configuration, resulting in HTTP 500.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_verify_no_ssl_src],
            "ext-auth-ingress.example.com",
            tls=True,
            validate_policies=False,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 500

    def test_tls_nonexistent_ca_secret(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that referencing a non-existent trustedCertSecret results in HTTP 500.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_nonexistent_ca_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 500

    def test_tls_wrong_ca_secret_type(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that referencing a trustedCertSecret with wrong type (kubernetes.io/tls
        instead of nginx.org/ca) results in HTTP 500.
        """
        print("Create wrong-type CA secret")
        wrong_secret = create_secret_from_yaml(kube_apis.v1, test_namespace, ext_auth_tls_wrong_ca_src)

        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_wrong_ca_type_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        delete_secret(kube_apis.v1, wrong_secret, test_namespace)

        assert resp.status_code == 500

    def test_tls_cross_ns_nonexistent_ca(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that referencing a trustedCertSecret in a non-existent namespace
        (fakens/external-auth-ca-secret) results in HTTP 500.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_cross_ns_ca_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 500

    # ------------------------------------------------------------------
    # Runtime TLS failure tests (HTTP 500)
    # ------------------------------------------------------------------

    def test_tls_bad_sni_name(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that an incorrect sniName (wrong-name.example.com) causes TLS
        verification failure at runtime. The auth_request module returns HTTP 500
        for subrequest failures.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_bad_sni_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 500

    def test_tls_verify_no_trusted_cert(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that sslVerify: true without trustedCertSecret falls back to the
        system CA bundle. Since the auth backend uses a self-signed certificate,
        the system CA cannot verify it, causing HTTP 500.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_no_trusted_cert_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 500

    def test_tls_default_sni_mismatch(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that omitting sniName with sslVerify causes a TLS verification failure.
        The default SNI name (<svcName>.<svcNs>.svc) does not match the server
        certificate SAN (external-auth-tls), so NGINX rejects the connection (HTTP 500).
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_default_sni_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 500

    # ------------------------------------------------------------------
    # Lifecycle / destructive tests
    # ------------------------------------------------------------------

    def test_tls_delete_ca_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that deleting the CA secret (trustedCertSecret) after a working
        TLS setup causes HTTP 500 for subsequent requests.
        """
        secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete - Status: {resp1.status_code}")

        print("Delete CA secret")
        delete_secret(kube_apis.v1, secret_names[2], test_namespace)  # ca_secret
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete - Status: {resp2.status_code}")

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    def test_tls_delete_server_tls_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test behavior after deleting the server TLS secret (external-auth-server-tls-secret).
        This secret is mounted in the backend pod, not referenced by the IC policy.
        The running backend retains the cert in memory, so requests continue to succeed.
        """
        secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete - Status: {resp1.status_code}")

        print("Delete server TLS secret")
        delete_secret(kube_apis.v1, secret_names[1], test_namespace)  # tls_secret
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete - Status: {resp2.status_code}")

        assert resp1.status_code == 200
        # Backend retains cert in memory; IC config unchanged; request should still succeed
        assert resp2.status_code == 200

    def test_tls_delete_backend(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that requests fail when the TLS external auth backend service is deleted.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete - Status: {resp1.status_code}")

        print("Delete TLS external auth backend")
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, test_namespace)
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete - Status: {resp2.status_code}")

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    # ------------------------------------------------------------------
    # Override / precedence test
    # ------------------------------------------------------------------

    def test_tls_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that when multiple TLS policies are referenced in the annotation,
        the first listed policy takes precedence. Both TLS policies reference the
        same backend with the same TLS config, so both orderings should succeed.
        """
        _secret_names, policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_tls_full_src, ext_auth_pol_tls_full_multi_src],
            "ext-auth-ingress.example.com",
            tls=True,
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_tls_multi_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        # Manually delete both policies as part of the test action.
        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_policy(kube_apis.custom_objects, policy_names[1], test_namespace)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

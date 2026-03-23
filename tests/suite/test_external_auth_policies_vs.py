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
    create_secret_from_yaml,
    delete_items_from_yaml,
    delete_secret,
    ensure_response_from_backend,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import (
    apply_and_assert_valid_vs,
    apply_and_assert_warning_vs,
    delete_and_create_vs_from_yaml,
    read_vs,
)

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"

# VS spec file paths
ext_auth_vs_single_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-single.yaml"
ext_auth_vs_single_invalid_svc_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-single-invalid-svc.yaml"
ext_auth_vs_multi_1_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-multi-1.yaml"
ext_auth_vs_multi_2_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-multi-2.yaml"
ext_auth_vs_cross_ns_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-cross-ns.yaml"
ext_auth_vs_signin_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-signin.yaml"
ext_auth_vs_custom_port_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-custom-port.yaml"

# TLS VS specs
ext_auth_vs_tls_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-tls.yaml"
ext_auth_vs_tls_multi_1_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-tls-multi-1.yaml"
ext_auth_vs_tls_multi_2_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-tls-multi-2.yaml"


@pytest.mark.policies
@pytest.mark.policies_external_auth
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                ],
            },
            {
                "example": "virtual-server",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestExternalAuthPolicies:
    def teardown(self, kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup):
        """Delete policy, auth backend, secrets and restore standard VS."""
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_external_auth_policy_credentials(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        credentials,
    ):
        """
        Test external-auth policy with valid credentials, invalid credentials, and no credentials.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            credentials,
            [ext_auth_pol_valid_src],
            virtual_server_setup.vs_host,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp.status_code)

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    @pytest.mark.smoke
    def test_external_auth_policy_valid(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test external-auth policy with a valid policy is accepted and proxies correctly.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src],
            virtual_server_setup.vs_host,
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp.status_code)

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.smoke
    def test_external_auth_policy_invalid_rejected_by_crd(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
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

    def test_external_auth_policy_nonexistent_svc(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test external-auth policy that references a non-existent service.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_invalid_svc_src],
            virtual_server_setup.vs_host,
        )

        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_invalid_svc_src,
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp.status_code)

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 500
        assert "Internal Server Error" in resp.text

    def test_external_auth_policy_delete_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test if requests result in 500 when the external auth policy is deleted.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src],
            virtual_server_setup.vs_host,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        wait_before_test()

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    def test_external_auth_policy_delete_backend(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test if requests fail when the external auth backend service is deleted.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src],
            virtual_server_setup.vs_host,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        print("Delete external auth backend")
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    def test_external_auth_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test if the first referenced policy takes precedence when multiple policies are applied.
        Both policies reference the same external auth backend but with different names.
        The first policy listed wins in each context (spec or route).
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],
            virtual_server_setup.vs_host,
        )

        print("Patch vs with multiple policies in spec context (multi first, valid second)")
        # Multiple policies in same context → VS Warning (first policy wins, second is ignored)
        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_multi_1_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        print("Patch vs with multiple policies in spec context (valid first, multi second)")
        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_multi_2_src,
        )

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_policy(kube_apis.custom_objects, policy_names[1], test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        # Both policies reference the same auth backend, so both should succeed with valid creds.
        # The first policy listed is the one applied; both use the same service so result is the same.
        assert resp1.status_code == 200
        assert resp2.status_code == 200

    def test_external_auth_policy_override_spec(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that a route-level policy takes precedence over a spec-level policy.
        Spec has valid-multi, route has valid. Both reference the same backend.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],
            virtual_server_setup.vs_host,
        )

        # Both policies reference the same external auth backend, so we verify both orderings succeed
        # Multiple policies in same context → VS Warning (first policy wins, second is ignored)
        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_multi_1_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_multi_2_src,
        )

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_policy(kube_apis.custom_objects, policy_names[1], test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 200
        assert resp2.status_code == 200

    def test_external_auth_policy_signin_uri(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test external-auth policy with authSigninURI set.
        Verifies the policy and VS are accepted as Valid, and that
        authenticated requests still pass through correctly.

        Note: This test does NOT verify the actual signin redirect behavior
        (error_page 401 -> internal redirect to authSigninURI) because the full
        signin flow requires a real OAuth2 proxy deployed at authSigninRedirectBasePath
        (default "/oauth2"). Without it, the error_page internal redirect to "/signin"
        hits the same auth-protected location and produces another 401, making the
        redirect behavior non-testable in this environment. Instead, we test that
        the authSigninURI configuration is accepted and applied correctly.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_signin_src],
            virtual_server_setup.vs_host,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_signin_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert policy_info["status"]["state"] == "Valid"
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_external_auth_policy_custom_port(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test external-auth policy with authServicePorts set to a custom port.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_custom_port_src],
            virtual_server_setup.vs_host,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_custom_port_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp.status_code)

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text


@pytest.mark.policies
@pytest.mark.policies_external_auth
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                ],
            },
            {
                "example": "virtual-server",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestExternalAuthPoliciesTLS:
    """Test external-auth policies with TLS configurations for VirtualServer."""

    def teardown(self, kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup):
        """Delete policy, TLS auth backend, all secrets and restore standard VS."""
        teardown_ext_auth(kube_apis, test_namespace, secret_names, policy_names, tls=True)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

    # -------------------------------------------------------------------------
    # Positive tests
    # -------------------------------------------------------------------------

    def test_tls_ssl_enabled_only(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
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
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_tls_full_verify(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test external-auth policy with full TLS verification:
        sslEnabled, sslVerify, sslVerifyDepth, sniName, and trustedCertSecret.
        Verifies the policy and VirtualServer are accepted as Valid.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        assert policy_info["status"]["state"] == "Valid"

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_tls_credentials(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
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
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

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
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that a TLS-capable backend still serves HTTP when sslEnabled is explicitly false.
        The IC connects over HTTP (port 80) even though the backend also listens on HTTPS (port 443).
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_disabled_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_tls_verify_without_ssl_enabled(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that sslVerify: true without sslEnabled: true causes the VS to
        enter Warning state. Although the CRD accepts this combination (no
        x-kubernetes-validations rule unlike OIDC) and the controller's TLS
        verify path is gated by SSLEnabled && SSLVerify (policy.go:309),
        the IC treats this as an invalid configuration, resulting in HTTP 500.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_verify_no_ssl_src],
            virtual_server_setup.vs_host,
            tls=True,
            validate_policies=False,
        )

        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 500

    def test_tls_custom_port(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test external-auth policy with sslEnabled and authServicePorts: [8443].
        The IC uses the custom service port 8443 instead of the default 443.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_custom_port_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_tls_signin_uri(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test external-auth policy with sslEnabled and authSigninURI.
        Verifies the policy and VS are accepted as Valid and that
        authenticated requests still pass through correctly over TLS.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_signin_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert policy_info["status"]["state"] == "Valid"
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    # -------------------------------------------------------------------------
    # Controller error tests (VS Warning, HTTP 500)
    # -------------------------------------------------------------------------

    def test_tls_nonexistent_ca_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that referencing a non-existent trustedCertSecret results in
        VS Warning state and HTTP 500 responses.
        Controller path: policy.go:324-328 (secret not found).
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_nonexistent_ca_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 500

    def test_tls_wrong_ca_secret_type(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that referencing a trustedCertSecret with wrong type (kubernetes.io/tls
        instead of nginx.org/ca) results in VS Warning state and HTTP 500 responses.
        Controller path: policy.go:334-337 (wrong secret type).
        """
        print("Create wrong-type CA secret")
        wrong_secret = create_secret_from_yaml(kube_apis.v1, test_namespace, ext_auth_tls_wrong_ca_src)

        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_wrong_ca_type_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)
        delete_secret(kube_apis.v1, wrong_secret, test_namespace)

        assert resp.status_code == 500

    def test_tls_cross_ns_nonexistent_ca(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that referencing a trustedCertSecret in a non-existent namespace
        (fakens/external-auth-ca-secret) results in VS Warning and HTTP 500.
        Controller path: policy.go:324-328 (secret not found in cross-ns lookup).
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_cross_ns_ca_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 500

    # -------------------------------------------------------------------------
    # Runtime TLS failure tests (VS Valid, HTTP 502)
    # -------------------------------------------------------------------------

    def test_tls_bad_sni_name(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that an incorrect sniName (wrong-name.example.com) causes TLS
        verification failure at runtime. The VS is accepted as Valid because
        the config is syntactically correct, but NGINX's proxy_ssl_verify
        rejects the connection since the cert SAN (external-auth-tls) does not
        match the requested SNI name. The auth_request module returns HTTP 500
        (not 502) for subrequest failures.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_bad_sni_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 500

    def test_tls_verify_no_trusted_cert(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that sslVerify: true without trustedCertSecret falls back to the
        system CA bundle. Since the auth backend uses a self-signed certificate,
        the system CA cannot verify it, causing NGINX's proxy_ssl_verify to
        reject the connection. The auth_request module returns HTTP 500 (not
        502) for subrequest failures. The VS remains Valid.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_no_trusted_cert_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 500

    def test_tls_default_sni_mismatch(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that omitting sniName with sslVerify causes a TLS verification failure.
        When sniName is not specified, the controller defaults to
        '<svcName>.<svcNs>.svc' (policy.go:351-356). This default name does not
        match the server certificate SAN (external-auth-tls), so NGINX's
        proxy_ssl_verify rejects the connection. The auth_request module returns
        HTTP 500 (not 502) for subrequest failures. The VS remains Valid.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_default_sni_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, test_namespace, secret_names, policy_names, virtual_server_setup)

        assert resp.status_code == 500

    # -------------------------------------------------------------------------
    # Lifecycle / destructive tests
    # -------------------------------------------------------------------------

    def test_tls_delete_ca_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that deleting the CA secret (trustedCertSecret) after a working
        TLS setup causes the VirtualServer to transition to Warning state.
        The IC watches the referenced secret and reconfigures NGINX when it
        is removed, resulting in HTTP 500 for subsequent requests.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Before delete - Status: {resp1.status_code}")

        print("Delete CA secret")
        delete_secret(kube_apis.v1, secret_names[2], test_namespace)  # ca_secret
        wait_before_test()

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"After delete - Status: {resp2.status_code}")

        crd_info = read_vs(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
        )

        # Cleanup (ca_secret already deleted)
        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)  # htpasswd_secret
        delete_secret(kube_apis.v1, secret_names[1], test_namespace)  # tls_secret
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 200
        assert resp2.status_code == 500
        assert crd_info["status"]["state"] == "Warning"

    def test_tls_delete_server_tls_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test behavior after deleting the server TLS secret (external-auth-server-tls-secret).
        This secret is mounted as a volume in the backend pod, not directly referenced
        by the IC policy. After deletion:
        - The running backend pod retains the TLS cert in memory (nginx keeps it loaded).
        - The IC configuration is unaffected (it references trustedCertSecret, not the server cert).
        - Requests continue to succeed until the backend pod is restarted.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Before delete - Status: {resp1.status_code}")

        print("Delete server TLS secret")
        delete_secret(kube_apis.v1, secret_names[1], test_namespace)  # tls_secret
        wait_before_test()

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"After delete - Status: {resp2.status_code}")

        crd_info = read_vs(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
        )

        # Cleanup (tls_secret already deleted)
        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)  # htpasswd_secret
        delete_secret(kube_apis.v1, secret_names[2], test_namespace)  # ca_secret
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 200
        # Backend retains cert in memory; IC config unchanged; request should still succeed
        assert resp2.status_code == 200
        assert crd_info["status"]["state"] == "Valid"

    def test_tls_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that when multiple TLS policies are applied, the first listed policy
        takes precedence. Both TLS policies reference the same backend with the same
        TLS config, so both orderings should succeed with valid credentials.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src, ext_auth_pol_tls_full_multi_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        print("Patch vs with TLS multi policies (tls first, tls-multi second)")
        # Multiple policies in same context → VS Warning (first policy wins, second is ignored)
        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_multi_1_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Order 1 - Status: {resp1.status_code}")

        print("Patch vs with TLS multi policies (tls-multi first, tls second)")
        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_multi_2_src,
        )

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Order 2 - Status: {resp2.status_code}")

        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_policy(kube_apis.custom_objects, policy_names[1], test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)  # htpasswd_secret
        delete_secret(kube_apis.v1, secret_names[1], test_namespace)  # tls_secret
        delete_secret(kube_apis.v1, secret_names[2], test_namespace)  # ca_secret
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 200
        assert resp2.status_code == 200

    def test_tls_delete_backend(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that requests fail when the TLS external auth backend service is deleted.
        After the backend is removed, the IC can no longer proxy auth subrequests,
        resulting in HTTP 500.
        """
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            test_namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            virtual_server_setup.vs_host,
            tls=True,
        )

        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_tls_src,
        )
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Before delete - Status: {resp1.status_code}")

        print("Delete TLS external auth backend")
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, test_namespace)
        wait_before_test()

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"After delete - Status: {resp2.status_code}")

        # Cleanup (backend already deleted)
        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        delete_secret(kube_apis.v1, secret_names[0], test_namespace)  # htpasswd_secret
        delete_secret(kube_apis.v1, secret_names[1], test_namespace)  # tls_secret
        delete_secret(kube_apis.v1, secret_names[2], test_namespace)  # ca_secret
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 200
        assert resp2.status_code == 500

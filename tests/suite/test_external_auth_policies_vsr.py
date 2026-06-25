import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_valid_vsr, assert_vsr_status
from suite.utils.external_auth_utils import (
    ext_auth_backend_src,
    ext_auth_pol_invalid_src,
    ext_auth_pol_invalid_svc_src,
    ext_auth_pol_tls_bad_sni_src,
    ext_auth_pol_tls_basic_src,
    ext_auth_pol_tls_full_multi_src,
    ext_auth_pol_tls_full_src,
    ext_auth_pol_tls_no_trusted_cert_src,
    ext_auth_pol_tls_nonexistent_ca_src,
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
from suite.utils.vs_vsr_resources_utils import patch_v_s_route_from_yaml, patch_virtual_server_from_yaml

std_vs_src = f"{TEST_DATA}/virtual-server-route/standard/virtual-server.yaml"
std_vsr_src = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"

# VSR spec file paths
ext_auth_vsr_valid_src = f"{TEST_DATA}/external-auth/route-subroute/virtual-server-route-valid-subroute.yaml"
ext_auth_vsr_valid_multi_src = (
    f"{TEST_DATA}/external-auth/route-subroute/virtual-server-route-valid-subroute-multi.yaml"
)
ext_auth_vsr_invalid_svc_src = (
    f"{TEST_DATA}/external-auth/route-subroute/virtual-server-route-invalid-svc-subroute.yaml"
)
ext_auth_vsr_override_src = f"{TEST_DATA}/external-auth/route-subroute/virtual-server-route-override-subroute.yaml"
ext_auth_vs_override_spec_src = f"{TEST_DATA}/external-auth/route-subroute/virtual-server-vsr-spec-override.yaml"
ext_auth_vs_override_route_src = f"{TEST_DATA}/external-auth/route-subroute/virtual-server-vsr-route-override.yaml"

# TLS VSR specs
ext_auth_vsr_tls_src = f"{TEST_DATA}/external-auth/route-subroute/virtual-server-route-tls-subroute.yaml"
ext_auth_vsr_tls_multi_src = f"{TEST_DATA}/external-auth/route-subroute/virtual-server-route-tls-multi-subroute.yaml"
ext_auth_vs_tls_spec_override_src = (
    f"{TEST_DATA}/external-auth/route-subroute/virtual-server-vsr-tls-spec-override.yaml"
)
ext_auth_vs_tls_route_override_src = (
    f"{TEST_DATA}/external-auth/route-subroute/virtual-server-vsr-tls-route-override.yaml"
)


@pytest.mark.policies
@pytest.mark.policies_external_auth
@pytest.mark.policies_external_auth_vs
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                ],
            },
            {"example": "virtual-server-route"},
        )
    ],
    indirect=True,
)
class TestExternalAuthPoliciesVsr:
    def teardown(self, kube_apis, namespace, secret_names, policy_names, v_s_route_setup):
        """Delete policy, auth backend, secret and restore standard VSR."""
        teardown_ext_auth(kube_apis, namespace, secret_names, policy_names)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_external_auth_policy_credentials(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        credentials,
    ):
        """
        Test external-auth policy on VSR with valid credentials, invalid credentials, and no credentials.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            credentials,
            [ext_auth_pol_valid_src],
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {ext_auth_vsr_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_valid_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(resp.status_code)

        self.teardown(kube_apis, v_s_route_setup.route_m.namespace, secret_names, policy_names, v_s_route_setup)

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
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test external-auth policy on VSR with a valid policy is accepted and proxies correctly.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_valid_src],
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {ext_auth_vsr_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_valid_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(resp.status_code)

        policy_info = read_policy(kube_apis.custom_objects, v_s_route_setup.route_m.namespace, policy_names[0])
        assert_valid_vsr(kube_apis, v_s_route_setup.route_m.namespace, v_s_route_setup.route_m.name)

        self.teardown(kube_apis, v_s_route_setup.route_m.namespace, secret_names, policy_names, v_s_route_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )

    @pytest.mark.smoke
    def test_external_auth_policy_invalid_rejected_by_crd(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test that a policy with an invalid authURI (no leading slash) is rejected
        at the CRD validation level by the Kubernetes API server.
        """
        with pytest.raises(ApiException) as exc_info:
            create_policy_from_yaml(
                kube_apis.custom_objects, ext_auth_pol_invalid_src, v_s_route_setup.route_m.namespace
            )

        assert exc_info.value.status == 422
        assert "authURI" in exc_info.value.body

    def test_external_auth_policy_nonexistent_svc(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test external-auth policy on VSR that references a non-existent service.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_invalid_svc_src],
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {ext_auth_vsr_invalid_svc_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_invalid_svc_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(resp.status_code)

        assert_vsr_status(kube_apis, v_s_route_setup.route_m.namespace, v_s_route_setup.route_m.name, "Warning")

        self.teardown(kube_apis, v_s_route_setup.route_m.namespace, secret_names, policy_names, v_s_route_setup)

        assert resp.status_code == 500
        assert "Internal Server Error" in resp.text

    def test_external_auth_policy_delete_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test if requests result in 500 when the external auth policy is deleted.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_valid_src],
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {ext_auth_vsr_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_valid_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(resp1.status_code)

        delete_policy(kube_apis.custom_objects, policy_names[0], v_s_route_setup.route_m.namespace)
        wait_before_test()

        resp2 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(resp2.status_code)

        assert_vsr_status(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            "Warning",
            expected_messages=[f"{v_s_route_setup.route_m.namespace}/{policy_names[0]} is missing"],
        )

        delete_items_from_yaml(kube_apis, ext_auth_backend_src, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[0], v_s_route_setup.route_m.namespace)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )

        assert resp1.status_code == 200
        assert "Request ID:" in resp1.text
        assert resp2.status_code == 500
        assert "Internal Server Error" in resp2.text

    def test_external_auth_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test if the first referenced policy takes precedence when multiple policies
        are applied on the same subroute context.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with override policies: {ext_auth_vsr_override_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_override_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(resp.status_code)

        delete_policy(kube_apis.custom_objects, policy_names[0], v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, policy_names[1], v_s_route_setup.route_m.namespace)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[0], v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )

        # Both policies reference the same auth backend, so with valid creds the first policy wins
        # and the request should succeed
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.parametrize("vs_src", [ext_auth_vs_override_route_src, ext_auth_vs_override_spec_src])
    def test_external_auth_policy_override_vs_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        vs_src,
    ):
        """
        Test that a policy specified in vsr:subroute takes preference over a policy specified in:
        1. vs:spec (policy at spec level)
        2. vs:route (policy at route level)
        Both policies reference the same external auth backend.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {ext_auth_vsr_valid_multi_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_valid_multi_src,
            v_s_route_setup.route_m.namespace,
        )
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            vs_src,
            v_s_route_setup.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers=headers,
        )
        print(resp.status_code)

        delete_policy(kube_apis.custom_objects, policy_names[0], v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, policy_names[1], v_s_route_setup.route_m.namespace)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[0], v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            std_vs_src,
            v_s_route_setup.namespace,
        )

        # The subroute policy (valid-multi) should take precedence over VS-level policy (valid).
        # Both reference the same backend, so request succeeds with valid creds.
        assert resp.status_code == 200
        assert "Request ID:" in resp.text


@pytest.mark.policies
@pytest.mark.policies_external_auth
@pytest.mark.policies_external_auth_tls
@pytest.mark.policies_external_auth_vs
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                ],
            },
            {"example": "virtual-server-route"},
        )
    ],
    indirect=True,
)
class TestExternalAuthPoliciesVsrTLS:
    """TLS-specific external auth policy tests for VirtualServerRoute."""

    def teardown(self, kube_apis, namespace, secret_names, policy_names, v_s_route_setup):
        """Delete TLS policy, backend, all secrets, and restore standard VSR."""
        teardown_ext_auth(kube_apis, namespace, secret_names, policy_names, tls=True)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )

    # ------------------------------------------------------------------
    # Positive TLS tests
    # ------------------------------------------------------------------

    def test_tls_ssl_enabled_only(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test TLS with sslEnabled: true only (encryption, no verification).
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_tls_basic_src],
            v_s_route_setup.vs_host,
            tls=True,
        )

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_tls_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, v_s_route_setup.route_m.namespace, secret_names, policy_names, v_s_route_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.smoke
    def test_tls_full_verify(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test full TLS verification: sslEnabled + sslVerify + sslVerifyDepth + sniName + trustedCertSecret.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            v_s_route_setup.vs_host,
            tls=True,
        )

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_tls_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"Status: {resp.status_code}")

        policy_info = read_policy(kube_apis.custom_objects, v_s_route_setup.route_m.namespace, policy_names[0])
        assert_valid_vsr(kube_apis, v_s_route_setup.route_m.namespace, v_s_route_setup.route_m.name)

        self.teardown(kube_apis, v_s_route_setup.route_m.namespace, secret_names, policy_names, v_s_route_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_tls_credentials(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        credentials,
    ):
        """
        Test full TLS external auth with valid, invalid, and no credentials.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            credentials,
            [ext_auth_pol_tls_full_src],
            v_s_route_setup.vs_host,
            tls=True,
        )

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_tls_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown(kube_apis, v_s_route_setup.route_m.namespace, secret_names, policy_names, v_s_route_setup)

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    # ------------------------------------------------------------------
    # Controller error tests (VS Warning, HTTP 500)
    # ------------------------------------------------------------------

    def test_tls_nonexistent_ca_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test TLS policy referencing a non-existent trustedCertSecret.
        Controller rejects config: VSR Warning, HTTP 500.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_tls_nonexistent_ca_src],
            v_s_route_setup.vs_host,
            tls=True,
        )

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_tls_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"Status: {resp.status_code}")

        assert_vsr_status(kube_apis, v_s_route_setup.route_m.namespace, v_s_route_setup.route_m.name, "Warning")

        self.teardown(kube_apis, v_s_route_setup.route_m.namespace, secret_names, policy_names, v_s_route_setup)

        assert resp.status_code == 500

    def test_tls_wrong_ca_secret_type(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test TLS policy with trustedCertSecret pointing to a kubernetes.io/tls secret
        instead of nginx.org/ca. Controller rejects: VSR Warning, HTTP 500.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_tls_wrong_ca_type_src],
            v_s_route_setup.vs_host,
            tls=True,
        )

        # Also create the wrong-type secret so it exists but has the wrong type
        wrong_secret = create_secret_from_yaml(
            kube_apis.v1, v_s_route_setup.route_m.namespace, ext_auth_tls_wrong_ca_src
        )

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_tls_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"Status: {resp.status_code}")

        assert_vsr_status(kube_apis, v_s_route_setup.route_m.namespace, v_s_route_setup.route_m.name, "Warning")

        delete_secret(kube_apis.v1, wrong_secret, v_s_route_setup.route_m.namespace)
        self.teardown(kube_apis, v_s_route_setup.route_m.namespace, secret_names, policy_names, v_s_route_setup)

        assert resp.status_code == 500

    # ------------------------------------------------------------------
    # Runtime TLS failure tests (VS Valid, HTTP 500 via auth_request)
    # ------------------------------------------------------------------

    def test_tls_bad_sni_name(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test TLS with mismatched sniName. Config is valid but TLS handshake fails at
        runtime. NGINX auth_request returns 500 for subrequest failures.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_tls_bad_sni_src],
            v_s_route_setup.vs_host,
            tls=True,
        )

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_tls_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"Status: {resp.status_code}")

        assert_valid_vsr(kube_apis, v_s_route_setup.route_m.namespace, v_s_route_setup.route_m.name)

        self.teardown(kube_apis, v_s_route_setup.route_m.namespace, secret_names, policy_names, v_s_route_setup)

        assert resp.status_code == 500

    def test_tls_verify_no_trusted_cert(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test TLS with sslVerify: true but no trustedCertSecret. System CA bundle
        cannot verify the self-signed cert, causing auth_request failure (500).
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_tls_no_trusted_cert_src],
            v_s_route_setup.vs_host,
            tls=True,
        )

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_tls_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"Status: {resp.status_code}")

        assert_valid_vsr(kube_apis, v_s_route_setup.route_m.namespace, v_s_route_setup.route_m.name)

        self.teardown(kube_apis, v_s_route_setup.route_m.namespace, secret_names, policy_names, v_s_route_setup)

        assert resp.status_code == 500

    # ------------------------------------------------------------------
    # Lifecycle / destructive tests
    # ------------------------------------------------------------------

    def test_tls_delete_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test that requests return 500 after the TLS external auth policy is deleted.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            v_s_route_setup.vs_host,
            tls=True,
        )

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_tls_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"Before delete: {resp1.status_code}")

        delete_policy(kube_apis.custom_objects, policy_names[0], v_s_route_setup.route_m.namespace)
        wait_before_test()

        resp2 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"After delete: {resp2.status_code}")

        assert_vsr_status(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
            "Warning",
            expected_messages=[f"{v_s_route_setup.route_m.namespace}/{policy_names[0]} is missing"],
        )

        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[0], v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[1], v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[2], v_s_route_setup.route_m.namespace)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )

        assert resp1.status_code == 200
        assert "Request ID:" in resp1.text
        assert resp2.status_code == 500

    def test_tls_delete_backend(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test that requests fail after the TLS external auth backend service is deleted.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src],
            v_s_route_setup.vs_host,
            tls=True,
        )

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_tls_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"Before delete: {resp1.status_code}")

        print("Delete TLS external auth backend")
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, v_s_route_setup.route_m.namespace)
        wait_before_test()

        resp2 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"After delete: {resp2.status_code}")

        # Clean up (backend already deleted above)
        delete_policy(kube_apis.custom_objects, policy_names[0], v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[0], v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[1], v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[2], v_s_route_setup.route_m.namespace)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )

        assert resp1.status_code == 200
        assert "Request ID:" in resp1.text
        assert resp2.status_code == 500

    # ------------------------------------------------------------------
    # Override / precedence test
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("vs_src", [ext_auth_vs_tls_route_override_src, ext_auth_vs_tls_spec_override_src])
    def test_tls_policy_override_vs_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        vs_src,
    ):
        """
        Test that a TLS policy on VSR subroute takes precedence over a TLS policy
        specified at VS spec or VS route level.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_names, policy_names, headers = setup_ext_auth(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [ext_auth_pol_tls_full_src, ext_auth_pol_tls_full_multi_src],
            v_s_route_setup.vs_host,
            tls=True,
        )

        print(f"Patch vsr with TLS multi policy: {ext_auth_vsr_tls_multi_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            ext_auth_vsr_tls_multi_src,
            v_s_route_setup.route_m.namespace,
        )
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            vs_src,
            v_s_route_setup.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            v_s_route_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(f"Status: {resp.status_code}")

        delete_policy(kube_apis.custom_objects, policy_names[0], v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, policy_names[1], v_s_route_setup.route_m.namespace)
        delete_items_from_yaml(kube_apis, ext_auth_tls_backend_src, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[0], v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[1], v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_names[2], v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            std_vs_src,
            v_s_route_setup.namespace,
        )

        # The subroute TLS policy (tls-multi) should take precedence over VS-level TLS policy (tls).
        # Both reference the same auth backend, so request succeeds with valid creds.
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

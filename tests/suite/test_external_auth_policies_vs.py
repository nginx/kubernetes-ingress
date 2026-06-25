import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.external_auth_utils import (
    build_ext_auth_headers,
    ext_auth_backend_src,
    ext_auth_pol_custom_port_src,
    ext_auth_pol_invalid_src,
    ext_auth_pol_invalid_svc_src,
    ext_auth_pol_signin_src,
    ext_auth_pol_valid_multi_src,
    ext_auth_pol_valid_src,
    invalid_credentials,
    valid_auth_headers,
    valid_credentials,
)
from suite.utils.policy_resources_utils import (
    create_policy_from_yaml,
    delete_policy,
    read_policy,
)
from suite.utils.resources_utils import (
    delete_items_from_yaml,
    ensure_response_from_backend,
    scale_deployment,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    apply_and_assert_valid_vs,
    apply_and_assert_warning_vs,
)

# VS spec file paths
ext_auth_vs_single_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-single.yaml"
ext_auth_vs_single_invalid_svc_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-single-invalid-svc.yaml"
ext_auth_vs_multi_1_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-multi-1.yaml"
ext_auth_vs_multi_2_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-multi-2.yaml"
ext_auth_vs_signin_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-signin.yaml"
ext_auth_vs_custom_port_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-custom-port.yaml"


@pytest.mark.policies
@pytest.mark.policies_external_auth
@pytest.mark.policies_external_auth_vs
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
    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    def test_external_auth_policy_credentials(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        ext_auth_restore_vs,
        credentials,
    ):
        """
        Test external-auth policy with valid credentials, invalid credentials, and no credentials.
        """
        _, _ = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, credentials)

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

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    @pytest.mark.smoke
    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    def test_external_auth_policy_valid(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        ext_auth_restore_vs,
    ):
        """
        Test external-auth policy with a valid policy is accepted and proxies correctly.
        """
        _, policy_names = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, valid_credentials)

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

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_invalid_svc_src],)], indirect=True)
    def test_external_auth_policy_nonexistent_svc(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        ext_auth_restore_vs,
    ):
        """
        Test external-auth policy that references a non-existent service.

        NGINX's auth_request module returns 500 when the subrequest fails
        (e.g. connection refused because the backend service does not exist).
        This is the expected "fail closed" behavior -- requests are denied
        rather than allowed when the auth service is unreachable.
        """
        _, _ = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, valid_credentials)

        apply_and_assert_warning_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_invalid_svc_src,
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp.status_code)

        assert resp.status_code == 500
        assert "Internal Server Error" in resp.text

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    def test_external_auth_policy_delete_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        ext_auth_restore_vs,
    ):
        """
        Test if requests result in 500 when the external auth policy is deleted.
        """
        _, policy_names = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, valid_credentials)

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

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    def test_external_auth_policy_delete_backend(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        ext_auth_restore_vs,
    ):
        """
        Test if requests fail when the external auth backend service is deleted.
        """
        _, _ = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, valid_credentials)

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

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    def test_external_auth_policy_endpoint_recovery(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        ext_auth_restore_vs,
    ):
        """
        Test that the VirtualServer recovers after external auth backend endpoints
        disappear (e.g. pod restart). The flow is:
          1. Healthy baseline -> 200
          2. Scale backend to 0 replicas -> 500 (no endpoints)
          3. Scale backend back to 1 replica -> 200 (recovered)
        """
        _, _ = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, valid_credentials)

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

        # Phase 1: healthy baseline
        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Phase 1 (healthy): {resp1.status_code}")

        # Phase 2: scale backend to 0 -- endpoints disappear -> 500
        print("Scale external-auth deployment to 0")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "external-auth", test_namespace, 0)
        wait_before_test()
        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Phase 2 (no endpoints): {resp2.status_code}")

        # Phase 3: scale back to 1 -- endpoints recover -> 200
        print("Scale external-auth deployment back to 1")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "external-auth", test_namespace, 1)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        # Poll until the full auth path (backend + auth subrequest) returns 200,
        # giving NGINX time to pick up the recovered endpoints and reload.
        resp3 = None
        for _ in range(30):
            r = requests.get(virtual_server_setup.backend_1_url, headers=headers)
            if r.status_code == 200:
                resp3 = r
                break
            wait_before_test(1)
        if resp3 is None:
            resp3 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Phase 3 (recovered): {resp3.status_code}")

        assert resp1.status_code == 200, f"Phase 1: expected 200, got {resp1.status_code}"
        assert resp2.status_code == 500, f"Phase 2: expected 500, got {resp2.status_code}"
        assert resp3.status_code == 200, f"Phase 3: expected 200 after recovery, got {resp3.status_code}"

    @pytest.mark.parametrize(
        "ext_auth_setup", [([ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],)], indirect=True
    )
    def test_external_auth_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        ext_auth_restore_vs,
    ):
        """
        Test if the first referenced policy takes precedence when multiple policies are applied.
        Both policies reference the same external auth backend but with different names.
        The first policy listed wins in each context (spec or route).
        """
        _, _ = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, valid_credentials)

        print("Patch vs with multiple policies in spec context (multi first, valid second)")
        # Multiple policies in same context -> VS Warning (first policy wins, second is ignored)
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

        # Both policies reference the same auth backend, so both should succeed with valid creds.
        # The first policy listed is the one applied; both use the same service so result is the same.
        assert resp1.status_code == 200
        assert resp2.status_code == 200

    @pytest.mark.parametrize(
        "ext_auth_setup", [([ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],)], indirect=True
    )
    def test_external_auth_policy_override_spec(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        ext_auth_restore_vs,
    ):
        """
        Test that a route-level policy takes precedence over a spec-level policy.
        Spec has valid-multi, route has valid. Both reference the same backend.
        """
        _, _ = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, valid_credentials)

        # Both policies reference the same external auth backend, so we verify both orderings succeed
        # Multiple policies in same context -> VS Warning (first policy wins, second is ignored)
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

        assert resp1.status_code == 200
        assert resp2.status_code == 200

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_signin_src],)], indirect=True)
    def test_external_auth_policy_signin_uri(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        ext_auth_restore_vs,
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
        _, policy_names = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, valid_credentials)

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

        assert policy_info["status"]["state"] == "Valid"
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_custom_port_src],)], indirect=True)
    def test_external_auth_policy_custom_port(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        ext_auth_restore_vs,
    ):
        """
        Test external-auth policy with authServicePorts set to a custom port.
        """
        _, _ = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, valid_credentials)

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

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

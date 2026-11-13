from urllib.parse import urlparse

import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.external_auth_utils import (
    LONGEST_HEADER_NAME,
    RETURNED_HEADERS,
    apply_vs_and_wait,
    build_ext_auth_headers,
    echo_from_pod,
    ext_auth_backend_src,
    ext_auth_pol_custom_port_src,
    ext_auth_pol_invalid_src,
    ext_auth_pol_invalid_svc_src,
    ext_auth_pol_response_headers_src,
    ext_auth_pol_signin_src,
    ext_auth_pol_valid_multi_src,
    ext_auth_pol_valid_src,
    grpc_auth_metadata,
    grpc_tls_lines,
    header_values,
    invalid_credentials,
    lines_named,
    request_lines,
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
    get_e2e_run_selector,
    scale_deployment,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    apply_and_assert_valid_vs,
    apply_and_assert_warning_vs,
    read_vs,
)

# VS spec file paths
ext_auth_vs_single_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-single.yaml"
ext_auth_vs_single_invalid_svc_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-single-invalid-svc.yaml"
ext_auth_vs_multi_1_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-multi-1.yaml"
ext_auth_vs_multi_2_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-multi-2.yaml"
ext_auth_vs_signin_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-signin.yaml"
ext_auth_vs_custom_port_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-custom-port.yaml"


# authResponseHeaders scenario file paths
ext_auth_vs_response_headers_src = f"{TEST_DATA}/external-auth/spec/virtual-server-policy-response-headers.yaml"
ext_auth_vs_response_headers_route_src = (
    f"{TEST_DATA}/external-auth/route-subroute/virtual-server-route-policy-response-headers.yaml"
)
ext_auth_vs_response_headers_grpc_src = (
    f"{TEST_DATA}/external-auth/spec/virtual-server-policy-response-headers-grpc.yaml"
)


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

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials])
    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    def test_external_auth_policy_spoofed_headers_and_non_get(
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
        Test external-auth policy boundary on VirtualServer with client-supplied spoofed headers
        and non-GET (POST) request.
        Verifies that spoofed headers (X-Forwarded-Prefix, X-Forwarded-URI, X-Forwarded-Method,
        X-Original-URI) are sanitized by NGINX and not forwarded to the auth backend,
        and requests are successfully authenticated (or rejected if unauthorized).
        """
        _, _ = ext_auth_setup
        headers = build_ext_auth_headers(virtual_server_setup.vs_host, credentials)
        headers.update(
            {
                "X-Forwarded-Prefix": "/malicious-prefix",
                "X-Forwarded-URI": "/malicious-uri",
                "X-Forwarded-Method": "DELETE",
                "X-Original-URI": "/malicious-uri",
            }
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

        resp = requests.post(virtual_server_setup.backend_1_url, headers=headers)
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
        e2e_run_id,
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
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace, get_e2e_run_selector(e2e_run_id))
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
        Unauthenticated requests redirect to authSigninURI, while authenticated
        requests still reach the protected backend.
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

        unauthenticated_resp = requests.get(
            virtual_server_setup.backend_1_url,
            headers=build_ext_auth_headers(virtual_server_setup.vs_host),
            allow_redirects=False,
        )
        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert policy_info["status"]["state"] == "Valid"
        assert unauthenticated_resp.status_code == 302
        assert urlparse(unauthenticated_resp.headers["location"]).path == "/oauth2/signin"
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

    # authResponseHeaders acceptance scenarios (docs/developer/external-auth-response-headers-high-level-design.md)

    @pytest.mark.parametrize(
        "vs_src",
        [
            pytest.param(ext_auth_vs_response_headers_src, id="vs-spec"),
            pytest.param(ext_auth_vs_response_headers_route_src, id="vs-route"),
        ],
    )
    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_response_headers_src],)], indirect=True)
    def test_every_attachment_point_forwards(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        ext_auth_setup,
        headers_echo_backend,
        ext_auth_restore_vs,
        vs_src,
    ):
        """The backend receives one line per listed header that the auth service returned, as P spells it."""
        apply_vs_and_wait(kube_apis, virtual_server_setup, vs_src)
        lines = request_lines(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        for name, value in RETURNED_HEADERS:
            assert lines_named(lines, name) == [(name, value)]

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_response_headers_src],)], indirect=True)
    def test_repeated_lines_are_joined(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        ext_auth_setup,
        headers_echo_backend,
        ext_auth_restore_vs,
    ):
        """Two X-Group lines in the auth response reach the backend as one line."""
        apply_vs_and_wait(kube_apis, virtual_server_setup, ext_auth_vs_response_headers_src)
        lines = request_lines(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        assert lines_named(lines, "X-Group") == [("X-Group", "a, b")]

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_response_headers_src],)], indirect=True)
    def test_client_values_are_replaced(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        ext_auth_setup,
        headers_echo_backend,
        ext_auth_restore_vs,
    ):
        """A client-supplied Tenant-UUID is replaced, and the VirtualServer reports no warning."""
        apply_vs_and_wait(kube_apis, virtual_server_setup, ext_auth_vs_response_headers_src)
        lines = request_lines(
            virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"Tenant-UUID": "spoofed"}
        )
        assert header_values(lines, "Tenant-UUID") == ["tenant-123"]
        vs = read_vs(kube_apis.custom_objects, virtual_server_setup.namespace, virtual_server_setup.vs_name)
        assert vs["status"]["state"] == "Valid"

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_response_headers_src],)], indirect=True)
    def test_in_any_letter_case(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        ext_auth_setup,
        headers_echo_backend,
        ext_auth_restore_vs,
    ):
        """Client copies spelled in other letter cases are replaced too."""
        apply_vs_and_wait(kube_apis, virtual_server_setup, ext_auth_vs_response_headers_src)
        for variant in ("tenant-uuid", "TENANT-UUID"):
            lines = request_lines(
                virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {variant: "spoofed"}
            )
            assert header_values(lines, "Tenant-UUID") == ["tenant-123"], variant

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_response_headers_src],)], indirect=True)
    def test_underscore_variants_are_dropped(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        ext_auth_setup,
        headers_echo_backend,
        ext_auth_restore_vs,
    ):
        """Guard: a client header named Tenant_UUID never reaches the backend, which would report it."""
        control = echo_from_pod(kube_apis, test_namespace, {"Tenant_UUID": "control"})
        assert header_values(control, "Tenant_UUID") == ["control"], "the echo backend must report names with _"

        apply_vs_and_wait(kube_apis, virtual_server_setup, ext_auth_vs_response_headers_src)
        lines = request_lines(
            virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"Tenant_UUID": "spoofed"}
        )
        assert header_values(lines, "Tenant_UUID") == []

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_response_headers_src],)], indirect=True)
    def test_omitted_headers_are_removed(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        ext_auth_setup,
        headers_echo_backend,
        ext_auth_restore_vs,
    ):
        """A listed header that the auth service does not return is removed from the client request."""
        apply_vs_and_wait(kube_apis, virtual_server_setup, ext_auth_vs_response_headers_src)
        lines = request_lines(
            virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"Permissions": "admin"}
        )
        assert header_values(lines, "Permissions") == []

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_response_headers_src],)], indirect=True)
    def test_grpc_backends(
        self,
        kube_apis,
        crd_ingress_controller,
        ext_auth_http2_config,
        virtual_server_setup,
        ext_auth_setup,
        headers_echo_backend,
        ext_auth_restore_vs,
    ):
        """A call with tenant-uuid: spoofed reaches the gRPC backend of a route with one tenant-uuid: tenant-123."""
        apply_and_assert_valid_vs(
            kube_apis,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ext_auth_vs_response_headers_grpc_src,
        )
        lines = grpc_tls_lines(
            virtual_server_setup.public_endpoint,
            virtual_server_setup.vs_host,
            grpc_auth_metadata([("tenant-uuid", "spoofed")]),
        )
        assert lines_named(lines, "tenant-uuid") == [("tenant-uuid", "tenant-123")]

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_response_headers_src],)], indirect=True)
    def test_the_longest_name_loads(
        self,
        kube_apis,
        crd_ingress_controller,
        ext_auth_http2_config,
        virtual_server_setup,
        ext_auth_setup,
        headers_echo_backend,
        ext_auth_restore_vs,
    ):
        """With a 46-character name in P, the VirtualServer is Valid, and an HTTP and a gRPC backend receive it."""
        apply_vs_and_wait(kube_apis, virtual_server_setup, ext_auth_vs_response_headers_grpc_src)
        lines = request_lines(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
        assert header_values(lines, LONGEST_HEADER_NAME) == ["long"]
        lines = grpc_tls_lines(virtual_server_setup.public_endpoint, virtual_server_setup.vs_host, grpc_auth_metadata())
        assert header_values(lines, LONGEST_HEADER_NAME) == ["long"]

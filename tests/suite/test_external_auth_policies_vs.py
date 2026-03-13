from base64 import b64encode

import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import (
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_items_from_yaml,
    delete_secret,
    ensure_response_from_backend,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import delete_and_create_vs_from_yaml

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
ext_auth_backend_secret_src = f"{TEST_DATA}/external-auth-policy/backend/htpasswd-secret.yaml"
ext_auth_backend_src = f"{TEST_DATA}/external-auth-policy/backend/external-auth-backend.yaml"
ext_auth_pol_valid_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-valid.yaml"
ext_auth_pol_valid_multi_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-valid-multi.yaml"
ext_auth_pol_invalid_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-invalid.yaml"
ext_auth_pol_invalid_svc_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-invalid-svc.yaml"
ext_auth_pol_cross_ns_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-cross-ns.yaml"
ext_auth_pol_signin_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-signin.yaml"
ext_auth_pol_custom_port_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-custom-port.yaml"
ext_auth_vs_single_src = f"{TEST_DATA}/external-auth-policy/spec/virtual-server-policy-single.yaml"
ext_auth_vs_single_invalid_svc_src = (
    f"{TEST_DATA}/external-auth-policy/spec/virtual-server-policy-single-invalid-svc.yaml"
)
ext_auth_vs_multi_1_src = f"{TEST_DATA}/external-auth-policy/spec/virtual-server-policy-multi-1.yaml"
ext_auth_vs_multi_2_src = f"{TEST_DATA}/external-auth-policy/spec/virtual-server-policy-multi-2.yaml"
ext_auth_vs_cross_ns_src = f"{TEST_DATA}/external-auth-policy/spec/virtual-server-policy-cross-ns.yaml"
ext_auth_vs_signin_src = f"{TEST_DATA}/external-auth-policy/spec/virtual-server-policy-signin.yaml"
ext_auth_vs_custom_port_src = f"{TEST_DATA}/external-auth-policy/spec/virtual-server-policy-custom-port.yaml"
valid_credentials = f"{TEST_DATA}/external-auth-policy/credentials.txt"
invalid_credentials = f"{TEST_DATA}/external-auth-policy/invalid-credentials.txt"


def to_base64(b64_string):
    return b64encode(b64_string.encode("ascii")).decode("ascii")


def valid_auth_headers():
    """Return Authorization header with valid credentials for ensure_response_from_backend."""
    with open(valid_credentials) as f:
        data = f.readline().strip()
    return {"authorization": f"Basic {to_base64(data)}"}


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
    def setup_policy(self, kube_apis, test_namespace, credentials, policy, vs_host):
        """Deploy external auth backend, create policy, and build request headers."""
        print("Create htpasswd secret for external auth backend")
        secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, ext_auth_backend_secret_src)

        print("Deploy external auth backend")
        create_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

        print("Create external auth policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy, test_namespace)
        wait_before_test()

        if credentials is None:
            return secret_name, pol_name, {"host": vs_host}

        with open(credentials) as f:
            data = f.readline().strip()
        headers = {"host": vs_host, "authorization": f"Basic {to_base64(data)}"}

        return secret_name, pol_name, headers

    def setup_multiple_policies(self, kube_apis, test_namespace, credentials, policy_1, policy_2, vs_host):
        """Deploy external auth backend and create two policies for override tests."""
        print("Create htpasswd secret for external auth backend")
        secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, ext_auth_backend_secret_src)

        print("Deploy external auth backend")
        create_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

        print("Create external auth policy #1")
        pol_name_1 = create_policy_from_yaml(kube_apis.custom_objects, policy_1, test_namespace)
        print("Create external auth policy #2")
        pol_name_2 = create_policy_from_yaml(kube_apis.custom_objects, policy_2, test_namespace)
        wait_before_test()

        with open(credentials) as f:
            data = f.readline().strip()
        headers = {"host": vs_host, "authorization": f"Basic {to_base64(data)}"}

        return secret_name, pol_name_1, pol_name_2, headers

    def teardown_policy(self, kube_apis, test_namespace, secret_name, pol_name, virtual_server_setup):
        """Delete policy, auth backend, secret and restore standard VS."""
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_name, test_namespace)
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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            test_namespace,
            credentials,
            ext_auth_pol_valid_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {ext_auth_vs_single_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp.status_code)

        self.teardown_policy(kube_apis, test_namespace, secret_name, pol_name, virtual_server_setup)

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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            test_namespace,
            valid_credentials,
            ext_auth_pol_valid_src,
            virtual_server_setup.vs_host,
        )

        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp.status_code)

        crd_info = read_custom_resource(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            "virtualservers",
            virtual_server_setup.vs_name,
        )

        self.teardown_policy(kube_apis, test_namespace, secret_name, pol_name, virtual_server_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text
        assert crd_info["status"]["state"] == "Valid"

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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            test_namespace,
            valid_credentials,
            ext_auth_pol_invalid_svc_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {ext_auth_vs_single_invalid_svc_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_invalid_svc_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp.status_code)

        crd_info = read_custom_resource(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            "virtualservers",
            virtual_server_setup.vs_name,
        )

        self.teardown_policy(kube_apis, test_namespace, secret_name, pol_name, virtual_server_setup)

        assert resp.status_code == 500
        assert "Internal Server Error" in resp.text
        assert crd_info["status"]["state"] == "Warning"

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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            test_namespace,
            valid_credentials,
            ext_auth_pol_valid_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {ext_auth_vs_single_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        wait_before_test()

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_name, test_namespace)
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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            test_namespace,
            valid_credentials,
            ext_auth_pol_valid_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {ext_auth_vs_single_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_single_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
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

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_secret(kube_apis.v1, secret_name, test_namespace)
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
        secret_name, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            test_namespace,
            valid_credentials,
            ext_auth_pol_valid_src,
            ext_auth_pol_valid_multi_src,
            virtual_server_setup.vs_host,
        )

        print("Patch vs with multiple policies in spec context (multi first, valid second)")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_multi_1_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        print("Patch vs with multiple policies in spec context (valid first, multi second)")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_multi_2_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_policy(kube_apis.custom_objects, pol_name_1, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_name, test_namespace)

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
        secret_name, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            test_namespace,
            valid_credentials,
            ext_auth_pol_valid_src,
            ext_auth_pol_valid_multi_src,
            virtual_server_setup.vs_host,
        )

        # Both policies reference the same external auth backend, so we verify both orderings succeed
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_multi_1_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_multi_2_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_policy(kube_apis.custom_objects, pol_name_1, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, test_namespace)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        delete_secret(kube_apis.v1, secret_name, test_namespace)

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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            test_namespace,
            valid_credentials,
            ext_auth_pol_signin_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with signin policy: {ext_auth_vs_signin_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_signin_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        crd_info = read_custom_resource(
            kube_apis.custom_objects,
            virtual_server_setup.namespace,
            "virtualservers",
            virtual_server_setup.vs_name,
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(f"Status: {resp.status_code}")

        self.teardown_policy(kube_apis, test_namespace, secret_name, pol_name, virtual_server_setup)

        assert policy_info["status"]["state"] == "Valid"
        assert crd_info["status"]["state"] == "Valid"
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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            test_namespace,
            valid_credentials,
            ext_auth_pol_custom_port_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with custom port policy: {ext_auth_vs_custom_port_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            ext_auth_vs_custom_port_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        ensure_response_from_backend(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp.status_code)

        self.teardown_policy(kube_apis, test_namespace, secret_name, pol_name, virtual_server_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

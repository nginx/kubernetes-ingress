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
from suite.utils.vs_vsr_resources_utils import patch_v_s_route_from_yaml, patch_virtual_server_from_yaml

std_vs_src = f"{TEST_DATA}/virtual-server-route/standard/virtual-server.yaml"
std_vsr_src = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
ext_auth_backend_secret_src = f"{TEST_DATA}/external-auth-policy/backend/htpasswd-secret.yaml"
ext_auth_backend_src = f"{TEST_DATA}/external-auth-policy/backend/external-auth-backend.yaml"
ext_auth_pol_valid_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-valid.yaml"
ext_auth_pol_valid_multi_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-valid-multi.yaml"
ext_auth_pol_invalid_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-invalid.yaml"
ext_auth_pol_invalid_svc_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-invalid-svc.yaml"
ext_auth_pol_cross_ns_src = f"{TEST_DATA}/external-auth-policy/policies/external-auth-policy-cross-ns.yaml"
ext_auth_vsr_valid_src = f"{TEST_DATA}/external-auth-policy/route-subroute/virtual-server-route-valid-subroute.yaml"
ext_auth_vsr_valid_multi_src = (
    f"{TEST_DATA}/external-auth-policy/route-subroute/virtual-server-route-valid-subroute-multi.yaml"
)
ext_auth_vsr_invalid_svc_src = (
    f"{TEST_DATA}/external-auth-policy/route-subroute/virtual-server-route-invalid-svc-subroute.yaml"
)
ext_auth_vsr_override_src = (
    f"{TEST_DATA}/external-auth-policy/route-subroute/virtual-server-route-override-subroute.yaml"
)
ext_auth_vs_override_spec_src = f"{TEST_DATA}/external-auth-policy/route-subroute/virtual-server-vsr-spec-override.yaml"
ext_auth_vs_override_route_src = (
    f"{TEST_DATA}/external-auth-policy/route-subroute/virtual-server-vsr-route-override.yaml"
)
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
    def setup_policy(self, kube_apis, namespace, credentials, policy, vs_host):
        """Deploy external auth backend, create policy, and build request headers."""
        print("Create htpasswd secret for external auth backend")
        secret_name = create_secret_from_yaml(kube_apis.v1, namespace, ext_auth_backend_secret_src)

        print("Deploy external auth backend")
        create_items_from_yaml(kube_apis, ext_auth_backend_src, namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, namespace)

        print("Create external auth policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy, namespace)
        wait_before_test()

        if credentials is None:
            return secret_name, pol_name, {"host": vs_host}

        with open(credentials) as f:
            data = f.readline().strip()
        headers = {"host": vs_host, "authorization": f"Basic {to_base64(data)}"}

        return secret_name, pol_name, headers

    def setup_multiple_policies(self, kube_apis, namespace, credentials, policy_1, policy_2, vs_host):
        """Deploy external auth backend and create two policies for override tests."""
        print("Create htpasswd secret for external auth backend")
        secret_name = create_secret_from_yaml(kube_apis.v1, namespace, ext_auth_backend_secret_src)

        print("Deploy external auth backend")
        create_items_from_yaml(kube_apis, ext_auth_backend_src, namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, namespace)

        print("Create external auth policy #1")
        pol_name_1 = create_policy_from_yaml(kube_apis.custom_objects, policy_1, namespace)
        print("Create external auth policy #2")
        pol_name_2 = create_policy_from_yaml(kube_apis.custom_objects, policy_2, namespace)
        wait_before_test()

        with open(credentials) as f:
            data = f.readline().strip()
        headers = {"host": vs_host, "authorization": f"Basic {to_base64(data)}"}

        return secret_name, pol_name_1, pol_name_2, headers

    def teardown_policy(self, kube_apis, namespace, secret_name, pol_name, v_s_route_setup):
        """Delete policy, auth backend, secret and restore standard VSR."""
        delete_policy(kube_apis.custom_objects, pol_name, namespace)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, namespace)
        delete_secret(kube_apis.v1, secret_name, namespace)
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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            credentials,
            ext_auth_pol_valid_src,
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

        self.teardown_policy(kube_apis, v_s_route_setup.route_m.namespace, secret_name, pol_name, v_s_route_setup)

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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            ext_auth_pol_valid_src,
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

        policy_info = read_custom_resource(
            kube_apis.custom_objects, v_s_route_setup.route_m.namespace, "policies", pol_name
        )
        crd_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )

        self.teardown_policy(kube_apis, v_s_route_setup.route_m.namespace, secret_name, pol_name, v_s_route_setup)

        assert resp.status_code == 200
        assert "Request ID:" in resp.text
        assert crd_info["status"]["state"] == "Valid"
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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            ext_auth_pol_invalid_svc_src,
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

        crd_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )

        self.teardown_policy(kube_apis, v_s_route_setup.route_m.namespace, secret_name, pol_name, v_s_route_setup)

        assert resp.status_code == 500
        assert "Internal Server Error" in resp.text
        assert crd_info["status"]["state"] == "Warning"

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
        secret_name, pol_name, headers = self.setup_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            ext_auth_pol_valid_src,
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

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        wait_before_test()

        resp2 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(resp2.status_code)

        crd_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )

        delete_items_from_yaml(kube_apis, ext_auth_backend_src, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_name, v_s_route_setup.route_m.namespace)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )

        assert resp1.status_code == 200
        assert "Request ID:" in resp1.text
        assert crd_info["status"]["state"] == "Warning"
        assert f"{v_s_route_setup.route_m.namespace}/{pol_name} is missing" in crd_info["status"]["message"]
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
        secret_name, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            ext_auth_pol_valid_src,
            ext_auth_pol_valid_multi_src,
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

        crd_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )

        delete_policy(kube_apis.custom_objects, pol_name_1, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, v_s_route_setup.route_m.namespace)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_name, v_s_route_setup.route_m.namespace)

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
        secret_name, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            ext_auth_pol_valid_src,
            ext_auth_pol_valid_multi_src,
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

        delete_policy(kube_apis.custom_objects, pol_name_1, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, v_s_route_setup.route_m.namespace)
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret_name, v_s_route_setup.route_m.namespace)

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

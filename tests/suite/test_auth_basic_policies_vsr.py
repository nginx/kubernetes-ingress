from base64 import b64encode

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import create_secret_from_yaml, delete_secret, wait_before_test
from suite.utils.vs_vsr_resources_utils import patch_v_s_route_from_yaml, patch_virtual_server_from_yaml

std_vs_src = f"{TEST_DATA}/virtual-server-route/standard/virtual-server.yaml"
std_vsr_src = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
htpasswd_sec_valid_src = f"{TEST_DATA}/auth-basic-policy/secret/htpasswd-secret-valid.yaml"
htpasswd_sec_valid_opaque_src = f"{TEST_DATA}/auth-basic-policy/secret/htpasswd-secret-valid-opaque.yaml"
htpasswd_sec_invalid_src = f"{TEST_DATA}/auth-basic-policy/secret/htpasswd-secret-invalid.yaml"
htpasswd_sec_valid_empty_src = f"{TEST_DATA}/auth-basic-policy/secret/htpasswd-secret-valid-empty.yaml"
auth_basic_pol_valid_src = f"{TEST_DATA}/auth-basic-policy/policies/auth-basic-policy-valid.yaml"
auth_basic_pol_multi_src = f"{TEST_DATA}/auth-basic-policy/policies/auth-basic-policy-valid-multi.yaml"
auth_basic_pol_invalid_src = f"{TEST_DATA}/auth-basic-policy/policies/auth-basic-policy-invalid.yaml"
auth_basic_pol_invalid_sec_src = f"{TEST_DATA}/auth-basic-policy/policies/auth-basic-policy-invalid-secret.yaml"
auth_basic_vsr_invalid_src = f"{TEST_DATA}/auth-basic-policy/route-subroute/virtual-server-route-invalid-subroute.yaml"
auth_basic_vsr_invalid_sec_src = (
    f"{TEST_DATA}/auth-basic-policy/route-subroute/virtual-server-route-invalid-subroute-secret.yaml"
)
auth_basic_vsr_override_src = (
    f"{TEST_DATA}/auth-basic-policy/route-subroute/virtual-server-route-override-subroute.yaml"
)
auth_basic_vsr_valid_src = f"{TEST_DATA}/auth-basic-policy/route-subroute/virtual-server-route-valid-subroute.yaml"
auth_basic_vsr_valid_multi_src = (
    f"{TEST_DATA}/auth-basic-policy/route-subroute/virtual-server-route-valid-subroute-multi.yaml"
)
auth_basic_vs_override_spec_src = f"{TEST_DATA}/auth-basic-policy/route-subroute/virtual-server-vsr-spec-override.yaml"
auth_basic_vs_override_route_src = (
    f"{TEST_DATA}/auth-basic-policy/route-subroute/virtual-server-vsr-route-override.yaml"
)
valid_credentials = f"{TEST_DATA}/auth-basic-policy/credentials.txt"
invalid_credentials = f"{TEST_DATA}/auth-basic-policy/invalid-credentials.txt"


def to_base64(b64_string):
    return b64encode(b64_string.encode("ascii")).decode("ascii")


@pytest.mark.policies
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
class TestAuthBasicPoliciesVsr:
    def setup_single_policy(self, kube_apis, namespace, credentials, secret, policy, vs_host):
        print(f"Create htpasswd secret")
        secret_name = create_secret_from_yaml(kube_apis.v1, namespace, secret)

        print(f"Create auth basic policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy, namespace)

        wait_before_test()

        # generate header without auth
        if credentials == None:
            return secret_name, pol_name, {"host": vs_host}

        with open(credentials) as file:
            data = file.readline().strip()
        headers = {"host": vs_host, "authorization": f"Basic {to_base64(data)}"}

        return secret_name, pol_name, headers

    def setup_multiple_policies(self, kube_apis, namespace, credentials, secret_list, policy_1, policy_2, vs_host):
        print(f"Create {len(secret_list)} htpasswd secrets")
        # secret_name = create_secret_from_yaml(kube_apis.v1, namespace, secret)
        secret_name_list = []
        for secret in secret_list:
            secret_name_list.append(create_secret_from_yaml(kube_apis.v1, namespace, secret))

        print(f"Create auth basic policy #1")
        pol_name_1 = create_policy_from_yaml(kube_apis.custom_objects, policy_1, namespace)
        print(f"Create auth basic policy #2")
        pol_name_2 = create_policy_from_yaml(kube_apis.custom_objects, policy_2, namespace)

        wait_before_test()
        with open(credentials) as file:
            data = file.readline().strip()
        headers = {"host": vs_host, "authorization": f"Basic {to_base64(data)}"}

        return secret_name_list, pol_name_1, pol_name_2, headers

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_auth_basic_policy_credentials(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        credentials,
    ):
        """
        Test auth-basic-policy with no credentials, valid credentials and invalid credentials
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            credentials,
            htpasswd_sec_valid_src,
            auth_basic_pol_valid_src,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {auth_basic_vsr_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            auth_basic_vsr_valid_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        resp = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(resp.status_code)

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret, v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert f"Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert f"Authorization Required" in resp.text

    @pytest.mark.parametrize(
        "htpasswd_secret", [htpasswd_sec_valid_src, htpasswd_sec_valid_opaque_src, htpasswd_sec_invalid_src]
    )
    def test_auth_basic_policy_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        htpasswd_secret,
    ):
        """
        Test auth-basic-policy with a valid and an invalid secret
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        if htpasswd_secret in (htpasswd_sec_valid_src, htpasswd_sec_valid_opaque_src):
            pol = auth_basic_pol_valid_src
            vsr = auth_basic_vsr_valid_src
        elif htpasswd_secret == htpasswd_sec_invalid_src:
            pol = auth_basic_pol_invalid_sec_src
            vsr = auth_basic_vsr_invalid_sec_src
        else:
            pytest.fail(f"Not a valid case or parameter")

        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            htpasswd_secret,
            pol,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {pol}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            vsr,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers=headers,
        )
        print(resp.status_code)

        crd_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret, v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )

        if htpasswd_secret in (htpasswd_sec_valid_src, htpasswd_sec_valid_opaque_src):
            assert resp.status_code == 200
            assert f"Request ID:" in resp.text
            assert crd_info["status"]["state"] == "Valid"
        elif htpasswd_secret == htpasswd_sec_invalid_src:
            assert resp.status_code == 500
            assert f"Internal Server Error" in resp.text
            assert crd_info["status"]["state"] == "Warning"
        else:
            pytest.fail(f"Not a valid case or parameter")

    @pytest.mark.smoke
    @pytest.mark.parametrize("policy", [auth_basic_pol_valid_src, auth_basic_pol_invalid_src])
    def test_auth_basic_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        policy,
    ):
        """
        Test auth-basic-policy with a valid and an invalid policy
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        if policy == auth_basic_pol_valid_src:
            vsr = auth_basic_vsr_valid_src
        elif policy == auth_basic_pol_invalid_src:
            vsr = auth_basic_vsr_invalid_src
        else:
            pytest.fail(f"Not a valid case or parameter")

        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            htpasswd_sec_valid_src,
            policy,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {policy}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            vsr,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

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
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret, v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )

        if policy == auth_basic_pol_valid_src:
            assert resp.status_code == 200
            assert f"Request ID:" in resp.text
            assert crd_info["status"]["state"] == "Valid"
            assert (
                policy_info["status"]
                and policy_info["status"]["reason"] == "AddedOrUpdated"
                and policy_info["status"]["state"] == "Valid"
            )
        elif policy == auth_basic_pol_invalid_src:
            assert resp.status_code == 500
            assert f"Internal Server Error" in resp.text
            assert crd_info["status"]["state"] == "Warning"
            assert (
                policy_info["status"]
                and policy_info["status"]["reason"] == "Rejected"
                and policy_info["status"]["state"] == "Invalid"
            )
        else:
            pytest.fail(f"Not a valid case or parameter")

    def test_auth_basic_policy_delete_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test if requests result in 500 when secret is deleted
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            htpasswd_sec_valid_src,
            auth_basic_pol_valid_src,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {auth_basic_pol_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            auth_basic_vsr_valid_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        resp1 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers=headers,
        )
        print(resp1.status_code)

        delete_secret(kube_apis.v1, secret, v_s_route_setup.route_m.namespace)
        resp2 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers=headers,
        )
        print(resp2.status_code)
        crd_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        assert resp1.status_code == 200
        assert f"Request ID:" in resp1.text
        assert crd_info["status"]["state"] == "Warning"
        assert (
            f"references an invalid secret {v_s_route_setup.route_m.namespace}/{secret}: secret doesn't exist or of an unsupported type"
            in crd_info["status"]["message"]
        )
        assert resp2.status_code == 500
        assert f"Internal Server Error" in resp2.text

    def test_auth_basic_policy_delete_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test if requests result in 500 when policy is deleted
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            htpasswd_sec_valid_src,
            auth_basic_pol_valid_src,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {auth_basic_pol_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            auth_basic_vsr_valid_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        resp1 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers=headers,
        )
        print(resp1.status_code)
        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)

        resp2 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers=headers,
        )
        print(resp2.status_code)
        crd_info = read_custom_resource(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            "virtualserverroutes",
            v_s_route_setup.route_m.name,
        )
        delete_secret(kube_apis.v1, secret, v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        assert resp1.status_code == 200
        assert f"Request ID:" in resp1.text
        assert crd_info["status"]["state"] == "Warning"
        assert f"{v_s_route_setup.route_m.namespace}/{pol_name} is missing" in crd_info["status"]["message"]
        assert resp2.status_code == 500
        assert f"Internal Server Error" in resp2.text

    def test_auth_basic_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test if first reference to a policy in the same context(subroute) takes precedence,
        i.e. in this case, policy with empty htpasswd over policy with htpasswd.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_list, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [htpasswd_sec_valid_src, htpasswd_sec_valid_empty_src],
            auth_basic_pol_valid_src,
            auth_basic_pol_multi_src,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policies: {auth_basic_pol_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            auth_basic_vsr_override_src,
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
        delete_policy(kube_apis.custom_objects, pol_name_1, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, v_s_route_setup.route_m.namespace)
        for secret in secret_list:
            delete_secret(kube_apis.v1, secret, v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        assert resp.status_code == 401
        assert f"Authorization Required" in resp.text
        assert f"Multiple basic auth policies in the same context is not valid." in crd_info["status"]["message"]

    @pytest.mark.parametrize("vs_src", [auth_basic_vs_override_route_src, auth_basic_vs_override_spec_src])
    def test_auth_basic_policy_override_vs_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        vs_src,
    ):
        """
        Test if policy specified in vsr:subroute (policy without $httptoken) takes preference over policy specified in:
        1. vs:spec (policy with $httptoken)
        2. vs:route (policy with $httptoken)
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret_list, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_credentials,
            [htpasswd_sec_valid_src, htpasswd_sec_valid_empty_src],
            auth_basic_pol_valid_src,
            auth_basic_pol_multi_src,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policies: {auth_basic_pol_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            auth_basic_vsr_valid_multi_src,
            v_s_route_setup.route_m.namespace,
        )
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            vs_src,
            v_s_route_setup.namespace,
        )
        wait_before_test()

        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers=headers,
        )
        print(resp.status_code)

        delete_policy(kube_apis.custom_objects, pol_name_1, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, v_s_route_setup.route_m.namespace)
        for secret in secret_list:
            delete_secret(kube_apis.v1, secret, v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, v_s_route_setup.vs_name, std_vs_src, v_s_route_setup.namespace
        )
        assert resp.status_code == 401
        assert f"Authorization Required" in resp.text

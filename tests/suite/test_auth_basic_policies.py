from base64 import b64encode

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import create_secret_from_yaml, delete_secret, wait_before_test
from suite.utils.vs_vsr_resources_utils import delete_and_create_vs_from_yaml

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
htpasswd_sec_valid_src = f"{TEST_DATA}/auth-basic-policy/secret/htpasswd-secret-valid.yaml"
htpasswd_sec_valid_opaque_src = f"{TEST_DATA}/auth-basic-policy/secret/htpasswd-secret-valid-opaque.yaml"
htpasswd_sec_invalid_src = f"{TEST_DATA}/auth-basic-policy/secret/htpasswd-secret-invalid.yaml"
htpasswd_sec_valid_empty_src = f"{TEST_DATA}/auth-basic-policy/secret/htpasswd-secret-valid-empty.yaml"
auth_basic_pol_valid_src = f"{TEST_DATA}/auth-basic-policy/policies/auth-basic-policy-valid.yaml"
auth_basic_pol_multi_src = f"{TEST_DATA}/auth-basic-policy/policies/auth-basic-policy-valid-multi.yaml"
auth_basic_vs_single_src = f"{TEST_DATA}/auth-basic-policy/spec/virtual-server-policy-single.yaml"
auth_basic_vs_single_invalid_pol_src = (
    f"{TEST_DATA}/auth-basic-policy/spec/virtual-server-policy-single-invalid-pol.yaml"
)
auth_basic_vs_multi_1_src = f"{TEST_DATA}/auth-basic-policy/spec/virtual-server-policy-multi-1.yaml"
auth_basic_vs_multi_2_src = f"{TEST_DATA}/auth-basic-policy/spec/virtual-server-policy-multi-2.yaml"
auth_basic_pol_invalid_src = f"{TEST_DATA}/auth-basic-policy/policies/auth-basic-policy-invalid.yaml"
auth_basic_pol_invalid_sec_src = f"{TEST_DATA}/auth-basic-policy/policies/auth-basic-policy-invalid-secret.yaml"
auth_basic_vs_single_invalid_sec_src = (
    f"{TEST_DATA}/auth-basic-policy/spec/virtual-server-policy-single-invalid-secret.yaml"
)
auth_basic_vs_override_route = f"{TEST_DATA}/auth-basic-policy/route-subroute/virtual-server-override-route.yaml"
auth_basic_vs_override_spec_route_1 = (
    f"{TEST_DATA}/auth-basic-policy/route-subroute/virtual-server-override-spec-route-1.yaml"
)
auth_basic_vs_override_spec_route_2 = (
    f"{TEST_DATA}/auth-basic-policy/route-subroute/virtual-server-override-spec-route-2.yaml"
)
valid_credentials_list = [
    f"{TEST_DATA}/auth-basic-policy/credentials.txt",
    f"{TEST_DATA}/auth-basic-policy/credentials2.txt",
]
invalid_credentials_list = [
    f"{TEST_DATA}/auth-basic-policy/invalid-credentials.txt",
    f"{TEST_DATA}/auth-basic-policy/invalid-credentials-no-pwd.txt",
    f"{TEST_DATA}/auth-basic-policy/invalid-credentials-no-user.txt",
    f"{TEST_DATA}/auth-basic-policy/invalid-credentials-pwd.txt",
    f"{TEST_DATA}/auth-basic-policy/invalid-credentials-user.txt",
]
valid_credentials = valid_credentials_list[0]


def to_base64(b64_string):
    return b64encode(b64_string.encode("ascii")).decode("ascii")


@pytest.mark.policies
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
class TestAuthBasicPolicies:
    def setup_single_policy(self, kube_apis, test_namespace, credentials, secret, policy, vs_host):
        print(f"Create htpasswd secret")
        secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, secret)

        print(f"Create auth basic policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy, test_namespace)
        wait_before_test()

        # generate header without auth
        if credentials == None:
            return secret_name, pol_name, {"host": vs_host}

        with open(credentials) as file:
            data = file.readline().strip()
        headers = {"host": vs_host, "authorization": f"Basic {to_base64(data)}"}

        return secret_name, pol_name, headers

    def setup_multiple_policies(self, kube_apis, test_namespace, credentials, secret_list, policy_1, policy_2, vs_host):
        print(f"Create {len(secret_list)} htpasswd secrets")
        # secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, secret)
        secret_name_list = []
        for secret in secret_list:
            secret_name_list.append(create_secret_from_yaml(kube_apis.v1, test_namespace, secret))

        print(f"Create auth basic policy #1")
        pol_name_1 = create_policy_from_yaml(kube_apis.custom_objects, policy_1, test_namespace)
        print(f"Create auth basic policy #2")
        pol_name_2 = create_policy_from_yaml(kube_apis.custom_objects, policy_2, test_namespace)
        wait_before_test()

        with open(credentials) as file:
            data = file.readline().strip()
        headers = {"host": vs_host, "authorization": f"Basic {to_base64(data)}"}

        return secret_name_list, pol_name_1, pol_name_2, headers

    @pytest.mark.parametrize("credentials", valid_credentials_list + invalid_credentials_list + [None])
    def test_auth_basic_policy_credentials(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        credentials,
    ):
        """
        Test auth-basic-policy with no credentials, valid credentials and invalid credentials
        """
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            test_namespace,
            credentials,
            htpasswd_sec_valid_src,
            auth_basic_pol_valid_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {auth_basic_vs_single_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            auth_basic_vs_single_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp.status_code)

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_secret(kube_apis.v1, secret, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        if credentials in valid_credentials_list:
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
        virtual_server_setup,
        test_namespace,
        htpasswd_secret,
    ):
        """
        Test auth-basic-policy with a valid and an invalid secret
        """
        if htpasswd_secret in (htpasswd_sec_valid_src, htpasswd_sec_valid_opaque_src):
            pol = auth_basic_pol_valid_src
            vs = auth_basic_vs_single_src
        elif htpasswd_secret == htpasswd_sec_invalid_src:
            pol = auth_basic_pol_invalid_sec_src
            vs = auth_basic_vs_single_invalid_sec_src
        else:
            pytest.fail("Invalid configuration")
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            test_namespace,
            valid_credentials,
            htpasswd_secret,
            pol,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {pol}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs,
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
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_secret(kube_apis.v1, secret, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
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
        virtual_server_setup,
        test_namespace,
        policy,
    ):
        """
        Test auth-basic-policy with a valid and an invalid policy
        """
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            test_namespace,
            valid_credentials,
            htpasswd_sec_valid_src,
            policy,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {policy}")
        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        if policy == auth_basic_pol_valid_src:
            vs_src = auth_basic_vs_single_src
            assert (
                policy_info["status"]
                and policy_info["status"]["reason"] == "AddedOrUpdated"
                and policy_info["status"]["state"] == "Valid"
            )
        elif policy == auth_basic_pol_invalid_src:
            vs_src = auth_basic_vs_single_invalid_pol_src
            assert (
                policy_info["status"]
                and policy_info["status"]["reason"] == "Rejected"
                and policy_info["status"]["state"] == "Invalid"
            )
        else:
            pytest.fail("Invalid configuration")

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_src,
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
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_secret(kube_apis.v1, secret, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        if policy == auth_basic_pol_valid_src:
            assert resp.status_code == 200
            assert f"Request ID:" in resp.text
            assert crd_info["status"]["state"] == "Valid"
        elif policy == auth_basic_pol_invalid_src:
            assert resp.status_code == 500
            assert f"Internal Server Error" in resp.text
            assert crd_info["status"]["state"] == "Warning"
        else:
            pytest.fail(f"Not a valid case or parameter")

    def test_auth_basic_policy_delete_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test if requests result in 500 when secret is deleted
        """
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            test_namespace,
            valid_credentials,
            htpasswd_sec_valid_src,
            auth_basic_pol_valid_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {auth_basic_pol_valid_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            auth_basic_vs_single_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        delete_secret(kube_apis.v1, secret, test_namespace)
        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    def test_auth_basic_policy_delete_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test if requests result in 500 when policy is deleted
        """
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            test_namespace,
            valid_credentials,
            htpasswd_sec_valid_src,
            auth_basic_pol_valid_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {auth_basic_pol_valid_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            auth_basic_vs_single_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_secret(kube_apis.v1, secret, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    def test_auth_basic_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test if first reference to a policy in the same context takes precedence
        """
        secret_list, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            test_namespace,
            valid_credentials,
            [htpasswd_sec_valid_src, htpasswd_sec_valid_empty_src],
            auth_basic_pol_valid_src,
            auth_basic_pol_multi_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with multiple policy in spec context")
        print(f"Patch vs with policy in order: {auth_basic_pol_multi_src} and {auth_basic_pol_valid_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            auth_basic_vs_multi_1_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        print(f"Patch vs with policy in order: {auth_basic_pol_valid_src} and {auth_basic_pol_multi_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            auth_basic_vs_multi_2_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        print(f"Patch vs with multiple policy in route context")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            auth_basic_vs_override_route,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp3 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp3.status_code)

        delete_policy(kube_apis.custom_objects, pol_name_1, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, test_namespace)
        for secret in secret_list:
            delete_secret(kube_apis.v1, secret, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 401  # 401 unauthorized, since no credentials are attached to policy in spec context
        assert resp2.status_code == 200
        assert (
            resp3.status_code == 401
        )  # 401 unauthorized, since no credentials are attached to policy in route context

    def test_auth_basic_policy_override_spec(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test if policy reference in route takes precedence over policy in spec
        """
        secret_list, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            test_namespace,
            valid_credentials,
            [htpasswd_sec_valid_src, htpasswd_sec_valid_empty_src],
            auth_basic_pol_valid_src,
            auth_basic_pol_multi_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with invalid policy in route and valid policy in spec")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            auth_basic_vs_override_spec_route_1,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        print(f"Patch vs with valid policy in route and invalid policy in spec")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            auth_basic_vs_override_spec_route_2,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_policy(kube_apis.custom_objects, pol_name_1, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, test_namespace)
        for secret in secret_list:
            delete_secret(kube_apis.v1, secret, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 401  # 401 unauthorized, since no credentials are attached to policy
        assert resp2.status_code == 200

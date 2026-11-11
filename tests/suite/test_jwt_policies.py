import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import create_secret_from_yaml, delete_secret, wait_before_test
from suite.utils.vs_vsr_resources_utils import delete_and_create_vs_from_yaml

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
jwk_sec_valid_src = f"{TEST_DATA}/jwt-policy/secret/jwk-secret-valid.yaml"
jwk_sec_valid_opaque_src = f"{TEST_DATA}/jwt-policy/secret/jwk-secret-valid-opaque.yaml"
jwk_sec_invalid_src = f"{TEST_DATA}/jwt-policy/secret/jwk-secret-invalid.yaml"
jwt_pol_valid_src = f"{TEST_DATA}/jwt-policy/policies/jwt-policy-valid.yaml"
jwt_pol_multi_src = f"{TEST_DATA}/jwt-policy/policies/jwt-policy-valid-multi.yaml"
jwt_vs_single_src = f"{TEST_DATA}/jwt-policy/spec/virtual-server-policy-single.yaml"
jwt_vs_single_invalid_pol_src = f"{TEST_DATA}/jwt-policy/spec/virtual-server-policy-single-invalid-pol.yaml"
jwt_vs_multi_1_src = f"{TEST_DATA}/jwt-policy/spec/virtual-server-policy-multi-1.yaml"
jwt_vs_multi_2_src = f"{TEST_DATA}/jwt-policy/spec/virtual-server-policy-multi-2.yaml"
jwt_pol_invalid_src = f"{TEST_DATA}/jwt-policy/policies/jwt-policy-invalid.yaml"
jwt_pol_invalid_sec_src = f"{TEST_DATA}/jwt-policy/policies/jwt-policy-invalid-secret.yaml"
jwt_vs_single_invalid_sec_src = f"{TEST_DATA}/jwt-policy/spec/virtual-server-policy-single-invalid-secret.yaml"
jwt_vs_override_route = f"{TEST_DATA}/jwt-policy/route-subroute/virtual-server-override-route.yaml"
jwt_vs_override_spec_route_1 = f"{TEST_DATA}/jwt-policy/route-subroute/virtual-server-override-spec-route-1.yaml"
jwt_vs_override_spec_route_2 = f"{TEST_DATA}/jwt-policy/route-subroute/virtual-server-override-spec-route-2.yaml"
valid_token = f"{TEST_DATA}/jwt-policy/token.jwt"
invalid_token = f"{TEST_DATA}/jwt-policy/invalid-token.jwt"


@pytest.mark.skip_for_nginx_oss
@pytest.mark.policies
@pytest.mark.policies_jwt
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
class TestJWTPolicies:
    def setup_single_policy(self, kube_apis, test_namespace, token, secret, policy, vs_host):
        print(f"Create jwk secret")
        secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, secret)

        print(f"Create jwt policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy, test_namespace)
        wait_before_test()

        with open(token) as file:
            data = file.readline().strip()
        headers = {"host": vs_host, "token": data}

        return secret_name, pol_name, headers

    def setup_multiple_policies(self, kube_apis, test_namespace, token, secret, policy_1, policy_2, vs_host):
        print(f"Create jwk secret")
        secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, secret)

        print(f"Create jwt policy #1")
        pol_name_1 = create_policy_from_yaml(kube_apis.custom_objects, policy_1, test_namespace)
        print(f"Create jwt policy #2")
        pol_name_2 = create_policy_from_yaml(kube_apis.custom_objects, policy_2, test_namespace)

        wait_before_test()
        with open(token) as file:
            data = file.readline().strip()
        headers = {"host": vs_host, "token": data}

        return secret_name, pol_name_1, pol_name_2, headers

    @pytest.mark.parametrize("token", [valid_token, invalid_token])
    def test_jwt_policy_token(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        token,
    ):
        """
        Test jwt-policy with no token, valid token and invalid token
        """
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            test_namespace,
            token,
            jwk_sec_valid_src,
            jwt_pol_valid_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {jwt_vs_single_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_vs_single_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp1 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
        )
        print(resp1.status_code)

        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_secret(kube_apis.v1, secret, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 401
        assert f"401 Authorization Required" in resp1.text

        if token == valid_token:
            assert resp2.status_code == 200
            assert f"Request ID:" in resp2.text
        else:
            assert resp2.status_code == 401
            assert f"Authorization Required" in resp2.text

    @pytest.mark.parametrize("jwk_secret", [jwk_sec_valid_src, jwk_sec_valid_opaque_src, jwk_sec_invalid_src])
    def test_jwt_policy_secret(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        jwk_secret,
    ):
        """
        Test jwt-policy with a valid and an invalid secret
        """
        if jwk_secret in (jwk_sec_valid_src, jwk_sec_valid_opaque_src):
            pol = jwt_pol_valid_src
            vs = jwt_vs_single_src
        elif jwk_secret == jwk_sec_invalid_src:
            pol = jwt_pol_invalid_sec_src
            vs = jwt_vs_single_invalid_sec_src
        else:
            pytest.fail("Invalid configuration")
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            test_namespace,
            valid_token,
            jwk_secret,
            pol,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {jwt_vs_single_src}")
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

        if jwk_secret in (jwk_sec_valid_src, jwk_sec_valid_opaque_src):
            assert resp.status_code == 200
            assert f"Request ID:" in resp.text
            assert crd_info["status"]["state"] == "Valid"
        elif jwk_secret == jwk_sec_invalid_src:
            assert resp.status_code == 500
            assert f"Internal Server Error" in resp.text
            assert crd_info["status"]["state"] == "Warning"
        else:
            pytest.fail(f"Not a valid case or parameter")

    @pytest.mark.smoke
    @pytest.mark.parametrize("policy", [jwt_pol_valid_src, jwt_pol_invalid_src])
    def test_jwt_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        policy,
    ):
        """
        Test jwt-policy with a valid and an invalid policy
        """
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            test_namespace,
            valid_token,
            jwk_sec_valid_src,
            policy,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {policy}")
        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        if policy == jwt_pol_valid_src:
            vs_src = jwt_vs_single_src
            assert (
                policy_info["status"]
                and policy_info["status"]["reason"] == "AddedOrUpdated"
                and policy_info["status"]["state"] == "Valid"
            )
        elif policy == jwt_pol_invalid_src:
            vs_src = jwt_vs_single_invalid_pol_src
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

        if policy == jwt_pol_valid_src:
            assert resp.status_code == 200
            assert f"Request ID:" in resp.text
            assert crd_info["status"]["state"] == "Valid"
        elif policy == jwt_pol_invalid_src:
            assert resp.status_code == 500
            assert f"Internal Server Error" in resp.text
            assert crd_info["status"]["state"] == "Warning"
        else:
            pytest.fail(f"Not a valid case or parameter")

    def test_jwt_policy_delete_secret(
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
            valid_token,
            jwk_sec_valid_src,
            jwt_pol_valid_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {jwt_pol_valid_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_vs_single_src,
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

    def test_jwt_policy_delete_policy(
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
            valid_token,
            jwk_sec_valid_src,
            jwt_pol_valid_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with policy: {jwt_pol_valid_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_vs_single_src,
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

    def test_jwt_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test if first reference to a policy in the same context takes precedence
        """
        secret, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            test_namespace,
            valid_token,
            jwk_sec_valid_src,
            jwt_pol_valid_src,
            jwt_pol_multi_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with multiple policy in spec context")
        print(f"Patch vs with policy in order: {jwt_pol_multi_src} and {jwt_pol_valid_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_vs_multi_1_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        print(f"Patch vs with policy in order: {jwt_pol_valid_src} and {jwt_pol_multi_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_vs_multi_2_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        print(f"Patch vs with multiple policy in route context")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_vs_override_route,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp3 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp3.status_code)

        delete_policy(kube_apis.custom_objects, pol_name_1, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, test_namespace)
        delete_secret(kube_apis.v1, secret, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 401  # 401 unauthorized, since no token is attached to policy in spec context
        assert resp2.status_code == 200
        assert resp3.status_code == 401  # 401 unauthorized, since no token is attached to policy in route context

    def test_jwt_policy_override_spec(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test if policy reference in route takes precedence over policy in spec
        """
        secret, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            test_namespace,
            valid_token,
            jwk_sec_valid_src,
            jwt_pol_valid_src,
            jwt_pol_multi_src,
            virtual_server_setup.vs_host,
        )

        print(f"Patch vs with invalid policy in route and valid policy in spec")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_vs_override_spec_route_1,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp1 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp1.status_code)

        print(f"Patch vs with valid policy in route and invalid policy in spec")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_vs_override_spec_route_2,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp2 = requests.get(virtual_server_setup.backend_1_url, headers=headers)
        print(resp2.status_code)

        delete_policy(kube_apis.custom_objects, pol_name_1, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, test_namespace)
        delete_secret(kube_apis.v1, secret, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 401  # 401 unauthorized, since no token is attached to policy
        assert resp2.status_code == 200

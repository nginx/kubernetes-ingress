import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import create_secret_from_yaml, delete_secret, wait_before_test
from suite.utils.vs_vsr_resources_utils import patch_v_s_route_from_yaml, patch_virtual_server_from_yaml

std_vs_src = f"{TEST_DATA}/virtual-server-route/standard/virtual-server.yaml"
std_vsr_src = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
jwk_sec_valid_src = f"{TEST_DATA}/jwt-policy/secret/jwk-secret-valid.yaml"
jwk_sec_valid_opaque_src = f"{TEST_DATA}/jwt-policy/secret/jwk-secret-valid-opaque.yaml"
jwk_sec_invalid_src = f"{TEST_DATA}/jwt-policy/secret/jwk-secret-invalid.yaml"
jwt_pol_valid_src = f"{TEST_DATA}/jwt-policy/policies/jwt-policy-valid.yaml"
jwt_pol_multi_src = f"{TEST_DATA}/jwt-policy/policies/jwt-policy-valid-multi.yaml"
jwt_pol_invalid_src = f"{TEST_DATA}/jwt-policy/policies/jwt-policy-invalid.yaml"
jwt_pol_invalid_sec_src = f"{TEST_DATA}/jwt-policy/policies/jwt-policy-invalid-secret.yaml"
jwt_vsr_invalid_src = f"{TEST_DATA}/jwt-policy/route-subroute/virtual-server-route-invalid-subroute.yaml"
jwt_vsr_invalid_sec_src = f"{TEST_DATA}/jwt-policy/route-subroute/virtual-server-route-invalid-subroute-secret.yaml"
jwt_vsr_override_src = f"{TEST_DATA}/jwt-policy/route-subroute/virtual-server-route-override-subroute.yaml"
jwt_vsr_valid_src = f"{TEST_DATA}/jwt-policy/route-subroute/virtual-server-route-valid-subroute.yaml"
jwt_vsr_valid_multi_src = f"{TEST_DATA}/jwt-policy/route-subroute/virtual-server-route-valid-subroute-multi.yaml"
jwt_vs_override_spec_src = f"{TEST_DATA}/jwt-policy/route-subroute/virtual-server-vsr-spec-override.yaml"
jwt_vs_override_route_src = f"{TEST_DATA}/jwt-policy/route-subroute/virtual-server-vsr-route-override.yaml"
valid_token = f"{TEST_DATA}/jwt-policy/token.jwt"
invalid_token = f"{TEST_DATA}/jwt-policy/invalid-token.jwt"


@pytest.mark.skip_for_nginx_oss
@pytest.mark.policies
@pytest.mark.policies_jwt
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
class TestJWTPoliciesVsr:
    def setup_single_policy(self, kube_apis, namespace, token, secret, policy, vs_host):
        print(f"Create jwk secret")
        secret_name = create_secret_from_yaml(kube_apis.v1, namespace, secret)

        print(f"Create jwt policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy, namespace)

        wait_before_test()
        with open(token) as file:
            data = file.readline().strip()
        headers = {"host": vs_host, "token": data}

        return secret_name, pol_name, headers

    def setup_multiple_policies(self, kube_apis, namespace, token, secret, policy_1, policy_2, vs_host):
        print(f"Create jwk secret")
        secret_name = create_secret_from_yaml(kube_apis.v1, namespace, secret)

        print(f"Create jwt policy #1")
        pol_name_1 = create_policy_from_yaml(kube_apis.custom_objects, policy_1, namespace)
        print(f"Create jwt policy #2")
        pol_name_2 = create_policy_from_yaml(kube_apis.custom_objects, policy_2, namespace)

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
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        token,
    ):
        """
        Test jwt-policy with no token, valid token and invalid token
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            token,
            jwk_sec_valid_src,
            jwt_pol_valid_src,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {jwt_vsr_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            jwt_vsr_valid_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

        resp1 = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers={"host": v_s_route_setup.vs_host},
        )
        print(resp1.status_code)

        resp2 = requests.get(f"{req_url}{v_s_route_setup.route_m.paths[0]}", headers=headers)
        print(resp2.status_code)

        delete_policy(kube_apis.custom_objects, pol_name, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret, v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
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
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        jwk_secret,
    ):
        """
        Test jwt-policy with a valid and an invalid secret
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        if jwk_secret in (jwk_sec_valid_src, jwk_sec_valid_opaque_src):
            pol = jwt_pol_valid_src
            vsr = jwt_vsr_valid_src
        elif jwk_secret == jwk_sec_invalid_src:
            pol = jwt_pol_invalid_sec_src
            vsr = jwt_vsr_invalid_sec_src
        else:
            pytest.fail(f"Not a valid case or parameter")

        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_token,
            jwk_secret,
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
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
        policy,
    ):
        """
        Test jwt-policy with a valid and an invalid policy
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        if policy == jwt_pol_valid_src:
            vsr = jwt_vsr_valid_src
        elif policy == jwt_pol_invalid_src:
            vsr = jwt_vsr_invalid_src
        else:
            pytest.fail(f"Not a valid case or parameter")

        secret, pol_name, headers = self.setup_single_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_token,
            jwk_sec_valid_src,
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

        resp = requests.get(
            f"{req_url}{v_s_route_setup.route_m.paths[0]}",
            headers=headers,
        )
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

        if policy == jwt_pol_valid_src:
            assert resp.status_code == 200
            assert f"Request ID:" in resp.text
            assert crd_info["status"]["state"] == "Valid"
            assert (
                policy_info["status"]
                and policy_info["status"]["reason"] == "AddedOrUpdated"
                and policy_info["status"]["state"] == "Valid"
            )
        elif policy == jwt_pol_invalid_src:
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

    def test_jwt_policy_delete_secret(
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
            valid_token,
            jwk_sec_valid_src,
            jwt_pol_valid_src,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {jwt_pol_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            jwt_vsr_valid_src,
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

    def test_jwt_policy_delete_policy(
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
            valid_token,
            jwk_sec_valid_src,
            jwt_pol_valid_src,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policy: {jwt_pol_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            jwt_vsr_valid_src,
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

    def test_jwt_policy_override(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test if first reference to a policy in the same context(subroute) takes precedence,
        i.e. in this case, policy without $httptoken over policy with $httptoken.
        """
        req_url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}"
        secret, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_token,
            jwk_sec_valid_src,
            jwt_pol_valid_src,
            jwt_pol_multi_src,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policies: {jwt_pol_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            jwt_vsr_override_src,
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
        delete_policy(kube_apis.custom_objects, pol_name_1, v_s_route_setup.route_m.namespace)
        delete_policy(kube_apis.custom_objects, pol_name_2, v_s_route_setup.route_m.namespace)
        delete_secret(kube_apis.v1, secret, v_s_route_setup.route_m.namespace)

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        assert resp.status_code == 401
        assert f"Authorization Required" in resp.text
        assert f"Multiple jwt policies in the same context is not valid." in crd_info["status"]["message"]

    @pytest.mark.parametrize("vs_src", [jwt_vs_override_route_src, jwt_vs_override_spec_src])
    def test_jwt_policy_override_vs_vsr(
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
        secret, pol_name_1, pol_name_2, headers = self.setup_multiple_policies(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            valid_token,
            jwk_sec_valid_src,
            jwt_pol_valid_src,
            jwt_pol_multi_src,
            v_s_route_setup.vs_host,
        )

        print(f"Patch vsr with policies: {jwt_pol_valid_src}")
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            jwt_vsr_valid_multi_src,
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

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.jwt_authorization_utils import (
    AuthzScenario,
    echoed_header,
    get_with_token,
    headers_app_type,
    read_token,
    vs_manifest,
    wait_for_jwt_policy,
)
from suite.utils.policy_resources_utils import apply_and_wait_for_valid_policy, create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import create_secret_from_yaml, delete_secret, wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server,
    delete_and_create_vs_from_yaml,
    delete_virtual_server,
)

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
                "app_type": headers_app_type,
            },
        )
    ],
    indirect=True,
)
class TestJWTAuthorizationPolicies:
    """
    Claim authorization (spec.jwt.authorization). Authentication failures return 401, claim failures
    return authorization.errorCode (default 403).
    """

    def apply_vs(self, kube_apis, virtual_server_setup, spec_policy=None, route_policy=None):
        vs = vs_manifest(std_vs_src, spec_policy, route_policy)
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace)
        create_virtual_server(kube_apis.custom_objects, vs, virtual_server_setup.namespace)
        wait_for_jwt_policy(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)

    def restore_vs(self, kube_apis, virtual_server_setup):
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

    def statuses(self, kube_apis, virtual_server_setup, policy, tokens, route_level=False):
        """Apply one policy and return {token_name: status_code} for every token (None means no token)."""
        with AuthzScenario(kube_apis, virtual_server_setup.namespace, [policy]) as scenario:
            pol = scenario.policy_names[0]
            if route_level:
                self.apply_vs(kube_apis, virtual_server_setup, route_policy=pol)
            else:
                self.apply_vs(kube_apis, virtual_server_setup, spec_policy=pol)
            url, host = virtual_server_setup.backend_1_url, virtual_server_setup.vs_host
            try:
                return {token: get_with_token(url, host, token).status_code for token in tokens}
            finally:
                self.restore_vs(kube_apis, virtual_server_setup)

    @pytest.mark.parametrize("route_level", [False, True])
    def test_authentication_and_claims(self, kube_apis, crd_ingress_controller, virtual_server_setup, route_level):
        """
        No token and an invalid token return 401 before any claim is checked. A token that carries the
        claims returns 200. Tokens with missing, wrong or too few claims return 403.
        """
        got = self.statuses(
            kube_apis,
            virtual_server_setup,
            "policy-claims",
            [None, "noclaims", "basic", "array", "guest", "wrong-case", "expired"],
            route_level,
        )
        assert got[None] == 401
        assert got["expired"] == 401
        assert got["basic"] == 200
        # noclaims: nothing to match; array: no scope or role; guest: no scope; wrong-case: wrong issuer
        for token in ["noclaims", "array", "guest", "wrong-case"]:
            assert got[token] == 403, f"token {token}: {got}"

    def test_invalid_signature_returns_401(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        with AuthzScenario(kube_apis, virtual_server_setup.namespace, ["policy-claims"]) as scenario:
            self.apply_vs(kube_apis, virtual_server_setup, spec_policy=scenario.policy_names[0])
            try:
                resp = requests.get(
                    virtual_server_setup.backend_1_url,
                    headers={"host": virtual_server_setup.vs_host, "token": read_token(invalid_token)},
                    timeout=5,
                )
            finally:
                self.restore_vs(kube_apis, virtual_server_setup)
        assert resp.status_code == 401

    def test_contains_on_array_and_negated_nested_claim(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        """
        Contains matches an array claim (aud) and a nested array (realm_access.roles). A negated Contains
        fails when the value is present, and when the claim is missing altogether.
        """
        got = self.statuses(
            kube_apis,
            virtual_server_setup,
            "policy-array-negate",
            ["array", "guest", "basic", "noclaims"],
        )
        assert got["array"] == 200
        assert got["guest"] == 403  # roles contain guest
        assert got["basic"] == 403  # no realm_access claim: a value check never passes on a missing claim
        assert got["noclaims"] == 403

    def test_exact_and_regex_are_case_sensitive(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        got = self.statuses(
            kube_apis,
            virtual_server_setup,
            "policy-case-sensitive",
            ["basic", "wrong-case", "noclaims"],
        )
        assert got["basic"] == 200
        assert got["wrong-case"] == 403  # iss, role and the email regex all differ only by case
        assert got["noclaims"] == 403

    def test_present_and_negated_present(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        """
        Present with negate requires the claim to be absent, and is the only check that accepts a missing
        claim. A negated value check still fails on a missing claim.
        """
        got = self.statuses(
            kube_apis,
            virtual_server_setup,
            "policy-present-negate",
            ["basic", "guest", "noclaims"],
        )
        assert got["basic"] == 200  # iss matches, act absent, role is admin and not guest
        assert got["guest"] == 403  # role is guest
        assert got["noclaims"] == 403  # iss is missing

    def test_require_any_and_all(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        """
        require: Any at the policy level with a rule that requires All and a rule that requires Any.
        """
        got = self.statuses(
            kube_apis,
            virtual_server_setup,
            "policy-any-all",
            ["basic", "array", "guest", "wrong-case", "noclaims"],
        )
        assert got["basic"] == 200  # first rule: iss and role=admin
        assert got["array"] == 200  # second rule: roles contain staff
        assert got["guest"] == 403
        assert got["wrong-case"] == 403
        assert got["noclaims"] == 403

    def test_error_code_401(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        """errorCode: 401 makes claim failures return 401 instead of the default 403."""
        got = self.statuses(
            kube_apis,
            virtual_server_setup,
            "policy-error-code-401",
            ["basic", "guest", "noclaims"],
        )
        assert got["basic"] == 200
        assert got["guest"] == 401
        assert got["noclaims"] == 401

    def test_proxy_set_header_reaches_upstream(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        """The claim values named in proxySetHeader are received by the upstream."""
        with AuthzScenario(kube_apis, virtual_server_setup.namespace, ["policy-headers"]) as scenario:
            self.apply_vs(kube_apis, virtual_server_setup, spec_policy=scenario.policy_names[0])
            try:
                resp = get_with_token(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, "basic")
                spoofed = get_with_token(
                    virtual_server_setup.backend_1_url,
                    virtual_server_setup.vs_host,
                    "basic",
                    extra_headers={"X-Role": "spoofed", "X-Token-Scope": "spoofed"},
                )
            finally:
                self.restore_vs(kube_apis, virtual_server_setup)

        assert resp.status_code == 200
        assert echoed_header(resp, "X-Token-Scope") == "openid orders:read"
        assert echoed_header(resp, "X-Role") == "admin"
        # A client cannot set a header that a policy forwards: the claim value replaces it.
        assert spoofed.status_code == 200
        assert echoed_header(spoofed, "X-Token-Scope") == "openid orders:read"
        assert echoed_header(spoofed, "X-Role") == "admin"

    def test_claim_with_newline_does_not_inject_a_header(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        """
        A signed claim that contains a line break must not add a second upstream header. The sanitizing
        map turns it into an empty value, which proxy_set_header drops.
        """
        with AuthzScenario(kube_apis, virtual_server_setup.namespace, ["policy-header-sanitize"]) as scenario:
            self.apply_vs(kube_apis, virtual_server_setup, spec_policy=scenario.policy_names[0])
            try:
                url, host = virtual_server_setup.backend_1_url, virtual_server_setup.vs_host
                resp = get_with_token(url, host, "header-injection")
            finally:
                self.restore_vs(kube_apis, virtual_server_setup)

        # The scope claim is present, so the request passes and reaches the upstream.
        assert resp.status_code == 200
        assert echoed_header(resp, "X-Injected") == ""
        assert echoed_header(resp, "X-Token-Scope") == ""

    def test_route_policy_replaces_spec_policy(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        """
        The route policy only needs sub=carol. A token that fails the spec policy but has sub=carol passes
        on the route, and a token that passes the spec policy fails the route policy: the route's
        requirement replaces the spec's.
        """
        policies = ["policy-claims", "policy-route-override"]
        with AuthzScenario(kube_apis, virtual_server_setup.namespace, policies) as scenario:
            spec_pol, route_pol = scenario.policy_names
            self.apply_vs(kube_apis, virtual_server_setup, spec_policy=spec_pol, route_policy=route_pol)
            url_1, url_2 = virtual_server_setup.backend_1_url, virtual_server_setup.backend_2_url
            host = virtual_server_setup.vs_host
            try:
                guest = get_with_token(url_1, host, "guest")
                basic = get_with_token(url_1, host, "basic")
                other_route = get_with_token(url_2, host, "basic")
            finally:
                self.restore_vs(kube_apis, virtual_server_setup)

        assert guest.status_code == 200  # sub=carol
        assert basic.status_code == 403  # passes the spec policy, fails the route policy
        assert other_route.status_code == 200  # the second route inherits the spec policy

    def test_route_policy_without_authorization_is_not_gated_by_spec_policy(
        self, kube_apis, crd_ingress_controller, virtual_server_setup
    ):
        """
        The spec policy requires claims. A route that has its own JWT policy without authorization only
        needs a valid signature, so the inherited auth_jwt_require must not apply to it.
        """
        namespace = virtual_server_setup.namespace
        with AuthzScenario(kube_apis, namespace, ["policy-claims"]) as scenario:
            plain_name = apply_and_wait_for_valid_policy(kube_apis, namespace, jwt_pol_valid_src)
            spec_pol = scenario.policy_names[0]
            self.apply_vs(kube_apis, virtual_server_setup, spec_policy=spec_pol, route_policy=plain_name)
            url_1, url_2 = virtual_server_setup.backend_1_url, virtual_server_setup.backend_2_url
            host = virtual_server_setup.vs_host
            try:
                guarded = get_with_token(url_2, host, "noclaims")
                route = get_with_token(url_1, host, "noclaims")
                route_bad = get_with_token(url_1, host, None)
            finally:
                self.restore_vs(kube_apis, virtual_server_setup)
                delete_policy(kube_apis.custom_objects, plain_name, virtual_server_setup.namespace)

        assert guarded.status_code == 403  # inherits the spec policy, no claims
        assert route.status_code == 200  # own policy, valid signature, no claim requirement
        assert route_bad.status_code == 401  # still authenticated

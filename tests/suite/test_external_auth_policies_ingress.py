import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.external_auth_utils import (
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

# ---------------------------------------------------------------------------
# Ingress manifest paths
# ---------------------------------------------------------------------------

# Standard (single) Ingress variants
ext_auth_ing_standard_src = f"{TEST_DATA}/external-auth/ingress/standard/ext-auth-ingress.yaml"
ext_auth_ing_standard_invalid_svc_src = f"{TEST_DATA}/external-auth/ingress/standard-invalid-svc/ext-auth-ingress.yaml"
ext_auth_ing_standard_signin_src = f"{TEST_DATA}/external-auth/ingress/standard-signin/ext-auth-ingress.yaml"
ext_auth_ing_standard_custom_port_src = f"{TEST_DATA}/external-auth/ingress/standard-custom-port/ext-auth-ingress.yaml"
ext_auth_ing_standard_multi_src = f"{TEST_DATA}/external-auth/ingress/standard-multi/ext-auth-ingress.yaml"

# Mergeable Ingress variants
ext_auth_ing_mergeable_src = f"{TEST_DATA}/external-auth/ingress/mergeable/ext-auth-ingress.yaml"
ext_auth_ing_mergeable_invalid_svc_src = (
    f"{TEST_DATA}/external-auth/ingress/mergeable-invalid-svc/ext-auth-ingress.yaml"
)
ext_auth_ing_minion_policy_src = f"{TEST_DATA}/external-auth/ingress/minion-policy/ext-auth-ingress.yaml"
ext_auth_ing_mergeable_override_src = f"{TEST_DATA}/external-auth/ingress/mergeable-override/ext-auth-ingress.yaml"


# ============================================================================
# HTTP (non-TLS) External Auth Policies on Ingress
# ============================================================================


@pytest.mark.policies
@pytest.mark.policies_external_auth
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        {
            "type": "complete",
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-leader-election=false",
                f"-enable-prometheus-metrics",
            ],
        },
    ],
    indirect=True,
)
class TestExternalAuthPoliciesIngress:
    # ------------------------------------------------------------------
    # Valid policy tests
    # ------------------------------------------------------------------

    @pytest.mark.smoke
    def test_external_auth_policy_valid_standard(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
        kube_apis,
        test_namespace,
    ):
        """
        Test external-auth policy on a standard Ingress with valid credentials.
        Verifies the policy CRD status is Valid and the backend proxies correctly.
        """
        _secret_names, policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_src)

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_external_auth_policy_valid_mergeable(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
        kube_apis,
        test_namespace,
    ):
        """
        Test external-auth policy on a mergeable Ingress (policy on master).
        """
        _secret_names, policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_mergeable_src)

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        ensure_response_from_backend(
            ing.request_url,
            ing.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=True,
        )

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    # ------------------------------------------------------------------
    # Credentials tests
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_external_auth_policy_credentials_standard(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
        credentials,
    ):
        """
        Test external-auth policy on standard Ingress with valid, invalid, and no credentials.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_external_auth_policy_credentials_mergeable(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
        credentials,
    ):
        """
        Test external-auth policy on mergeable Ingress (policy on master)
        with valid, invalid, and no credentials.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_mergeable_src)
        ensure_response_from_backend(
            ing.request_url,
            ing.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=True,
        )

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    def test_external_auth_policy_credentials_minion(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
        credentials,
    ):
        """
        Test external-auth policy on mergeable Ingress with policy on the minion
        (location-level auth) with valid, invalid, and no credentials.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_minion_policy_src)
        ensure_response_from_backend(
            ing.request_url,
            ing.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=True,
        )

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    # ------------------------------------------------------------------
    # CRD validation test
    # ------------------------------------------------------------------

    @pytest.mark.smoke
    def test_external_auth_policy_invalid_rejected_by_crd(
        self,
        kube_apis,
        crd_ingress_controller,
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

    # ------------------------------------------------------------------
    # Non-existent service tests
    # ------------------------------------------------------------------

    def test_external_auth_policy_nonexistent_svc_standard(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy on standard Ingress that references a non-existent service.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_invalid_svc_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_invalid_svc_src)
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 500
        assert "Internal Server Error" in resp.text

    def test_external_auth_policy_nonexistent_svc_mergeable(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy on mergeable Ingress that references a non-existent service.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_invalid_svc_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_mergeable_invalid_svc_src)
        wait_before_test()

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 500
        assert "Internal Server Error" in resp.text

    # ------------------------------------------------------------------
    # Delete policy tests
    # ------------------------------------------------------------------

    def test_external_auth_policy_delete_policy_standard(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that deleting the external auth policy causes HTTP 500 on a standard Ingress.
        """
        _secret_names, policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete: {resp1.status_code}")

        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete: {resp2.status_code}")

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    def test_external_auth_policy_delete_policy_mergeable(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that deleting the external auth policy causes HTTP 500 on a mergeable Ingress.
        """
        _secret_names, policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_mergeable_src)
        ensure_response_from_backend(
            ing.request_url,
            ing.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=True,
        )

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete: {resp1.status_code}")

        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete: {resp2.status_code}")

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    # ------------------------------------------------------------------
    # Delete backend test
    # ------------------------------------------------------------------

    def test_external_auth_policy_delete_backend(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that deleting the external auth backend service causes HTTP 500.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Before delete: {resp1.status_code}")

        print("Delete external auth backend")
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        wait_before_test()

        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"After delete: {resp2.status_code}")

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    # ------------------------------------------------------------------
    # Endpoint recovery test
    # ------------------------------------------------------------------

    def test_external_auth_policy_endpoint_recovery(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that the Ingress recovers after external auth backend endpoints
        disappear (e.g. pod restart). The flow is:
          1. Healthy baseline -> 200
          2. Scale backend to 0 replicas -> 500 (no endpoints)
          3. Scale backend back to 1 replica -> 200 (recovered)
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_valid_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        # Phase 1: healthy baseline
        resp1 = requests.get(ing.request_url, headers=headers)
        print(f"Phase 1 (healthy): {resp1.status_code}")

        # Phase 2: scale backend to 0 -- endpoints disappear -> 500
        print("Scale external-auth deployment to 0")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "external-auth", test_namespace, 0)
        wait_before_test()
        resp2 = requests.get(ing.request_url, headers=headers)
        print(f"Phase 2 (no endpoints): {resp2.status_code}")

        # Phase 3: scale back to 1 -- endpoints recover -> 200
        print("Scale external-auth deployment back to 1")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "external-auth", test_namespace, 1)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        # Poll until the full auth path (backend + auth subrequest) returns 200,
        # giving NGINX time to pick up the recovered endpoints and reload.
        resp3 = None
        for _ in range(30):
            r = requests.get(ing.request_url, headers=headers)
            if r.status_code == 200:
                resp3 = r
                break
            wait_before_test(1)
        if resp3 is None:
            resp3 = requests.get(ing.request_url, headers=headers)
        print(f"Phase 3 (recovered): {resp3.status_code}")

        assert resp1.status_code == 200, f"Phase 1: expected 200, got {resp1.status_code}"
        assert resp2.status_code == 500, f"Phase 2: expected 500, got {resp2.status_code}"
        assert resp3.status_code == 200, f"Phase 3: expected 200 after recovery, got {resp3.status_code}"
        assert "Request ID:" in resp3.text

    # ------------------------------------------------------------------
    # Override / precedence tests
    # ------------------------------------------------------------------

    def test_external_auth_policy_override(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that when multiple policies are referenced in the nginx.org/policies
        annotation, the first listed policy takes precedence.
        Both policies reference the same auth backend, so the request should succeed.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_multi_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    def test_external_auth_policy_master_vs_minion_override(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test that a policy on the minion takes precedence over a policy on the master
        for the minion's path. Master has 'valid-multi', minion has 'valid'.
        Both reference the same backend, so the request should succeed.
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_mergeable_override_src)
        ensure_response_from_backend(
            ing.request_url,
            ing.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=True,
        )

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    # ------------------------------------------------------------------
    # Signin URI test
    # ------------------------------------------------------------------

    def test_external_auth_policy_signin_uri(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy with authSigninURI set on a standard Ingress.
        Verifies the policy is accepted as Valid and authenticated requests pass through.
        """
        _secret_names, policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_signin_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_signin_src)

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert policy_info["status"]["state"] == "Valid"
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    # ------------------------------------------------------------------
    # Custom port test
    # ------------------------------------------------------------------

    def test_external_auth_policy_custom_port(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy with authServicePorts set to a custom port (8080).
        """
        _secret_names, _policy_names, headers = ext_auth_setup(
            valid_credentials,
            [ext_auth_pol_custom_port_src],
            "ext-auth-ingress.example.com",
        )
        ing = ext_auth_ingress(ext_auth_ing_standard_custom_port_src)
        ensure_response_from_backend(ing.request_url, ing.ingress_host, additional_headers=valid_auth_headers())

        resp = requests.get(ing.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

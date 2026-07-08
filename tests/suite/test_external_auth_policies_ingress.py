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

EXT_AUTH_HOST = "ext-auth-ingress.example.com"

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
    @pytest.mark.smoke
    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    @pytest.mark.parametrize(
        "ext_auth_ingress,check404",
        [
            pytest.param(ext_auth_ing_standard_src, False, id="standard"),
            pytest.param(ext_auth_ing_mergeable_src, True, id="mergeable"),
        ],
        indirect=["ext_auth_ingress"],
    )
    def test_external_auth_policy_valid(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
        check404,
        kube_apis,
        test_namespace,
    ):
        """
        Test external-auth policy on standard and mergeable Ingresses with valid credentials.
        Verifies the policy CRD status is Valid and the backend proxies correctly.
        """
        _, policy_names = ext_auth_setup
        headers = build_ext_auth_headers(EXT_AUTH_HOST, valid_credentials)

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        ensure_response_from_backend(
            ext_auth_ingress.request_url,
            ext_auth_ingress.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=check404,
        )

        resp = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    @pytest.mark.parametrize(
        "ext_auth_ingress,check404",
        [
            pytest.param(ext_auth_ing_standard_src, False, id="standard"),
            pytest.param(ext_auth_ing_mergeable_src, True, id="mergeable"),
        ],
        indirect=["ext_auth_ingress"],
    )
    def test_external_auth_policy_credentials(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
        check404,
        credentials,
    ):
        """
        Test external-auth policy on standard and mergeable Ingresses
        with valid, invalid, and no credentials.
        """
        headers = build_ext_auth_headers(EXT_AUTH_HOST, credentials)
        ensure_response_from_backend(
            ext_auth_ingress.request_url,
            ext_auth_ingress.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=check404,
        )

        resp = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

    @pytest.mark.parametrize("credentials", [valid_credentials, invalid_credentials, None])
    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    @pytest.mark.parametrize("ext_auth_ingress", [ext_auth_ing_minion_policy_src], indirect=True)
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
        headers = build_ext_auth_headers(EXT_AUTH_HOST, credentials)
        ensure_response_from_backend(
            ext_auth_ingress.request_url,
            ext_auth_ingress.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=True,
        )

        resp = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        if credentials == valid_credentials:
            assert resp.status_code == 200
            assert "Request ID:" in resp.text
        else:
            assert resp.status_code == 401
            assert "Authorization Required" in resp.text

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

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_invalid_svc_src],)], indirect=True)
    @pytest.mark.parametrize(
        "ext_auth_ingress",
        [
            pytest.param(ext_auth_ing_standard_invalid_svc_src, id="standard"),
            pytest.param(ext_auth_ing_mergeable_invalid_svc_src, id="mergeable"),
        ],
        indirect=True,
    )
    def test_external_auth_policy_nonexistent_svc(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy on standard and mergeable Ingresses
        that reference a non-existent service.
        """

        headers = build_ext_auth_headers(EXT_AUTH_HOST, valid_credentials)
        wait_before_test()

        resp = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 500
        assert "Internal Server Error" in resp.text

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    @pytest.mark.parametrize(
        "ext_auth_ingress,check404",
        [
            pytest.param(ext_auth_ing_standard_src, False, id="standard"),
            pytest.param(ext_auth_ing_mergeable_src, True, id="mergeable"),
        ],
        indirect=["ext_auth_ingress"],
    )
    def test_external_auth_policy_delete_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        test_namespace,
        ext_auth_setup,
        ext_auth_ingress,
        check404,
    ):
        """
        Test that deleting the external auth policy causes HTTP 500 on standard
        and mergeable Ingresses.
        """
        _, policy_names = ext_auth_setup
        headers = build_ext_auth_headers(EXT_AUTH_HOST, valid_credentials)
        ensure_response_from_backend(
            ext_auth_ingress.request_url,
            ext_auth_ingress.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=check404,
        )

        resp1 = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Before delete: {resp1.status_code}")

        delete_policy(kube_apis.custom_objects, policy_names[0], test_namespace)
        wait_before_test()

        resp2 = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"After delete: {resp2.status_code}")

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    @pytest.mark.parametrize("ext_auth_ingress", [ext_auth_ing_standard_src], indirect=True)
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

        headers = build_ext_auth_headers(EXT_AUTH_HOST, valid_credentials)
        ensure_response_from_backend(
            ext_auth_ingress.request_url,
            ext_auth_ingress.ingress_host,
            additional_headers=valid_auth_headers(),
        )

        resp1 = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Before delete: {resp1.status_code}")

        print("Delete external auth backend")
        delete_items_from_yaml(kube_apis, ext_auth_backend_src, test_namespace)
        wait_before_test()

        resp2 = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"After delete: {resp2.status_code}")

        assert resp1.status_code == 200
        assert resp2.status_code == 500

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_valid_src],)], indirect=True)
    @pytest.mark.parametrize("ext_auth_ingress", [ext_auth_ing_standard_src], indirect=True)
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

        headers = build_ext_auth_headers(EXT_AUTH_HOST, valid_credentials)
        ensure_response_from_backend(
            ext_auth_ingress.request_url,
            ext_auth_ingress.ingress_host,
            additional_headers=valid_auth_headers(),
        )

        # Phase 1: healthy baseline
        resp1 = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Phase 1 (healthy): {resp1.status_code}")

        # Phase 2: scale backend to 0 -- endpoints disappear -> 500
        print("Scale external-auth deployment to 0")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "external-auth", test_namespace, 0)
        wait_before_test()
        resp2 = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Phase 2 (no endpoints): {resp2.status_code}")

        # Phase 3: scale back to 1 -- endpoints recover -> 200
        print("Scale external-auth deployment back to 1")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "external-auth", test_namespace, 1)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        # Poll until the full auth path (backend + auth subrequest) returns 200,
        # giving NGINX time to pick up the recovered endpoints and reload.
        resp3 = None
        for _ in range(30):
            r = requests.get(ext_auth_ingress.request_url, headers=headers)
            if r.status_code == 200:
                resp3 = r
                break
            wait_before_test(1)
        if resp3 is None:
            resp3 = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Phase 3 (recovered): {resp3.status_code}")

        assert resp1.status_code == 200, f"Phase 1: expected 200, got {resp1.status_code}"
        assert resp2.status_code == 500, f"Phase 2: expected 500, got {resp2.status_code}"
        assert resp3.status_code == 200, f"Phase 3: expected 200 after recovery, got {resp3.status_code}"
        assert "Request ID:" in resp3.text

    @pytest.mark.parametrize(
        "ext_auth_setup",
        [([ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],)],
        indirect=True,
    )
    @pytest.mark.parametrize("ext_auth_ingress", [ext_auth_ing_standard_multi_src], indirect=True)
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

        headers = build_ext_auth_headers(EXT_AUTH_HOST, valid_credentials)
        ensure_response_from_backend(
            ext_auth_ingress.request_url,
            ext_auth_ingress.ingress_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.parametrize(
        "ext_auth_setup",
        [([ext_auth_pol_valid_src, ext_auth_pol_valid_multi_src],)],
        indirect=True,
    )
    @pytest.mark.parametrize("ext_auth_ingress", [ext_auth_ing_mergeable_override_src], indirect=True)
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

        headers = build_ext_auth_headers(EXT_AUTH_HOST, valid_credentials)
        ensure_response_from_backend(
            ext_auth_ingress.request_url,
            ext_auth_ingress.ingress_host,
            additional_headers=valid_auth_headers(),
            check404=True,
        )

        resp = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_signin_src],)], indirect=True)
    @pytest.mark.parametrize("ext_auth_ingress", [ext_auth_ing_standard_signin_src], indirect=True)
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
        _, policy_names = ext_auth_setup
        headers = build_ext_auth_headers(EXT_AUTH_HOST, valid_credentials)

        policy_info = read_policy(kube_apis.custom_objects, test_namespace, policy_names[0])
        ensure_response_from_backend(
            ext_auth_ingress.request_url,
            ext_auth_ingress.ingress_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert policy_info["status"]["state"] == "Valid"
        assert resp.status_code == 200
        assert "Request ID:" in resp.text

    @pytest.mark.parametrize("ext_auth_setup", [([ext_auth_pol_custom_port_src],)], indirect=True)
    @pytest.mark.parametrize("ext_auth_ingress", [ext_auth_ing_standard_custom_port_src], indirect=True)
    def test_external_auth_policy_custom_port(
        self,
        crd_ingress_controller,
        ext_auth_setup,
        ext_auth_ingress,
    ):
        """
        Test external-auth policy with authServicePorts set to a custom port (8080).
        """

        headers = build_ext_auth_headers(EXT_AUTH_HOST, valid_credentials)
        ensure_response_from_backend(
            ext_auth_ingress.request_url,
            ext_auth_ingress.ingress_host,
            additional_headers=valid_auth_headers(),
        )

        resp = requests.get(ext_auth_ingress.request_url, headers=headers)
        print(f"Status: {resp.status_code}")

        assert resp.status_code == 200
        assert "Request ID:" in resp.text

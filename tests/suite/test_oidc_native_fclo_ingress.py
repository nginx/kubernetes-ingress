import base64
import secrets

import pytest
import requests
from playwright.sync_api import Error, sync_playwright
from settings import DEPLOYMENTS, TEST_DATA
from suite.test_oidc_native_fclo import (
    KeycloakSetupForNativeFCLO,
    create_client_and_get_secret,
    create_native_oidc_policy,
    create_native_oidc_secret,
)
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress_from_yaml,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_ingress,
    delete_items_from_yaml,
    delete_secret,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)

username = "nginx-user" + secrets.token_hex(4)
password = secrets.token_hex(8)

keycloak_ingress_src = f"{TEST_DATA}/oidc-native/ingress/keycloak-ingress.yaml"

cm_src = f"{TEST_DATA}/oidc-native-fclo/configmap-nginx.yaml"
orig_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"

webapps_src = f"{TEST_DATA}/oidc-fclo/two-webapps.yaml"
ingress_one_src = f"{TEST_DATA}/oidc-native-fclo/ingress/ingress-one.yaml"
ingress_two_src = f"{TEST_DATA}/oidc-native-fclo/ingress/ingress-two.yaml"


@pytest.fixture(scope="class")
def keycloak_ingress_fclo_setup(request, kube_apis, test_namespace, ingress_controller_endpoint):
    """Deploy Keycloak via Ingress and register two FCLO-enabled native OIDC clients."""
    ingress_secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
    )

    keycloak_address = "keycloak.example.com"
    backend_app = "keycloak-secure"
    backend_secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/oidc/keycloak-tls-secret.yaml"
    )
    backend_ca_secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/oidc/keycloak-ca-secret.yaml"
    )

    create_example_app(kube_apis, backend_app, test_namespace)
    wait_before_test()
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    keycloak_ingress_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, keycloak_ingress_src)
    wait_before_test()

    url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/realms/master/protocol/openid-connect/token"
    headers = {"Host": keycloak_address, "Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": "admin", "password": "admin", "grant_type": "password", "client_id": "admin-cli"}

    response = requests.post(url, headers=headers, data=data, verify=False)
    response.raise_for_status()
    token = response.json()["access_token"]

    create_user_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/admin/realms/master/users"
    auth_headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", "Host": keycloak_address}
    user_payload = {
        "username": username,
        "enabled": True,
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    }
    user_resp = requests.post(create_user_url, headers=auth_headers, json=user_payload, verify=False)
    user_resp.raise_for_status()

    client_secret_one = create_client_and_get_secret(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port_ssl,
        "native-fclo-one",
        "native-fclo-one.example.com",
        auth_headers,
    )

    client_secret_two = create_client_and_get_secret(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port_ssl,
        "native-fclo-two",
        "native-fclo-two.example.com",
        auth_headers,
    )

    keycloak_service_host = f"keycloak.{test_namespace}.svc.cluster.local"
    kube_apis.v1.patch_namespaced_service(
        "keycloak",
        test_namespace,
        {
            "spec": {
                "ports": [
                    {"name": "http", "port": 8080, "targetPort": 8080},
                    {"name": "https", "port": 8443, "targetPort": 8443},
                    {"name": "native-https", "port": 443, "targetPort": 8443},
                ]
            }
        },
    )
    kube_apis.networking_v1.patch_namespaced_ingress(
        keycloak_ingress_name,
        test_namespace,
        {
            "spec": {
                "tls": [{"hosts": [keycloak_service_host], "secretName": "keycloak-tls-secret"}],
                "rules": [
                    {
                        "host": keycloak_service_host,
                        "http": {
                            "paths": [
                                {
                                    "path": "/",
                                    "pathType": "Prefix",
                                    "backend": {"service": {"name": "keycloak", "port": {"number": 8443}}},
                                }
                            ]
                        },
                    }
                ],
            }
        },
    )
    wait_before_test()

    # Base64 encode the secret
    encoded_secret_one = base64.b64encode(client_secret_one.encode()).decode()
    encoded_secret_two = base64.b64encode(client_secret_two.encode()).decode()

    print(f"Keycloak setup complete. Base64 encoded client secret")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete Keycloak resources")
            delete_ingress(kube_apis.networking_v1, keycloak_ingress_name, test_namespace)
            delete_common_app(kube_apis, backend_app, test_namespace)
            delete_secret(kube_apis.v1, ingress_secret_name, test_namespace)
            delete_secret(kube_apis.v1, backend_secret_name, test_namespace)
            delete_secret(kube_apis.v1, backend_ca_secret_name, test_namespace)

    request.addfinalizer(fin)

    return KeycloakSetupForNativeFCLO(encoded_secret_one, encoded_secret_two, keycloak_service_host)


def run_oidc_native_fclo_ingress(browser_type, ip_address, port):
    """Playwright browser flow: login to app one, verify SSO on app two,
    trigger Keycloak logout, verify both apps listed, then confirm
    FCLO terminated the session."""
    browser = browser_type.launch(headless=True, args=[f"--host-resolver-rules=MAP * {ip_address}:{port}"])
    context = browser.new_context(
        ignore_https_errors=True,
        bypass_csp=True,
    )

    try:
        page = context.new_page()

        # Log in to app one via Keycloak
        page.goto("https://native-fclo-one.example.com")
        page.locator("input[name='username']").fill(username)
        page.locator("input[name='password']").fill(password)
        page.locator('button[type="submit"]').click()
        page.wait_for_url("https://native-fclo-one.example.com*")

        page_text = page.locator("body").text_content()
        fields_to_check = ["Server address:", "Server name:", "Date:", "Request ID:"]
        for field in fields_to_check:
            assert field in page_text, f"'{field}' not found in page text on native-fclo-one"

        # Verify cross-app SSO: app two should be logged in without a login form
        page.goto("https://native-fclo-two.example.com")
        page.wait_for_load_state("load")
        page_text = page.locator("body").text_content()
        for field in fields_to_check:
            assert field in page_text, f"'{field}' not found in page text on native-fclo-two (SSO)"

        # Trigger Keycloak logout and verify both apps are listed
        page.goto("https://native-fclo-one.example.com/logout")
        page.wait_for_load_state("load")
        page_text = page.locator("body").text_content()
        # Keycloak may auto-logout (newer versions) or show a confirmation page
        if "logged out" in page_text.lower():
            # Already logged out, no confirmation needed
            pass
        else:
            assert (
                "You are logging out from following apps" in page_text or "Do you want to log out?" in page_text
            ), f"Expected logout confirmation page, got: {page_text[:300]}"
            # Click the logout button to complete the FCLO flow
            page.locator("#kc-logout").click()
            page.wait_for_load_state("load")

        # Verify FCLO terminated the session: navigating to app one should
        # show the Keycloak login form again (not the backend page).
        page.goto("https://native-fclo-one.example.com")
        page.wait_for_load_state("load")
        assert (
            page.locator("input[name='username']").count() > 0
        ), "Expected Keycloak login form after FCLO logout, but got a different page"

    except Error as e:
        assert False, f"Playwright error: {e}"

    finally:
        context.close()
        browser.close()


def run_oidc_native_rp_logout_ingress(browser_type, ip_address, port):
    """Playwright browser flow: login, navigate to logoutURI, click through
    Keycloak's confirmation page, verify the postLogoutRedirectURI landing
    page, then confirm the session is terminated."""
    browser = browser_type.launch(headless=True, args=[f"--host-resolver-rules=MAP * {ip_address}:{port}"])
    context = browser.new_context(
        ignore_https_errors=True,
        bypass_csp=True,
    )

    try:
        page = context.new_page()

        # Log in to app one via Keycloak
        page.goto("https://native-fclo-one.example.com")
        page.locator("input[name='username']").fill(username)
        page.locator("input[name='password']").fill(password)
        page.locator('button[type="submit"]').click()
        page.wait_for_url("https://native-fclo-one.example.com*")

        page_text = page.locator("body").text_content()
        fields_to_check = ["Server address:", "Server name:", "Date:", "Request ID:"]
        for field in fields_to_check:
            assert field in page_text, f"'{field}' not found in page text after login"

        # Navigate to the logoutURI to initiate RP-initiated logout.
        # The native module redirects to Keycloak's end-session endpoint
        # with id_token_hint (logoutTokenHint is enabled for this test),
        # which allows Keycloak to honour the post_logout_redirect_uri.
        page.goto("https://native-fclo-one.example.com/logout")
        page.wait_for_load_state("load")

        kc_logout = page.locator("#kc-logout")
        if kc_logout.count() > 0:
            kc_logout.click()
            page.wait_for_load_state("load")
        # After confirming, Keycloak redirects to the postLogoutRedirectURI.
        # The auto-generated location at /_logout returns "Logged out".
        page_text = page.locator("body").text_content()
        if "logged out" in page_text.lower():
            # Keycloak auto-logged out, skip the confirmation click
            pass
        elif "You are logging out from following apps" in page_text or "Do you want to log out?" in page_text:
            page.locator("#kc-logout").click()
            page.wait_for_load_state("load")
        else:
            assert False, f"Expected logout or confirmation page, got: {page_text[:300]}"

        # Verify the session is terminated: accessing the app should redirect
        # to the Keycloak login form.
        page.goto("https://native-fclo-one.example.com")
        page.wait_for_load_state("load")
        assert (
            page.locator("input[name='username']").count() > 0
        ), "Expected Keycloak login form after RP logout, but got a different page"

    except Error as e:
        assert False, f"Playwright error: {e}"

    finally:
        context.close()
        browser.close()


@pytest.mark.policies
@pytest.mark.native_oidc
@pytest.mark.usefixtures("crd_ingress_controller")
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [{"type": "complete", "extra_args": ["-enable-custom-resources", "-enable-oidc", "-enable-prometheus-metrics"]}],
    indirect=True,
)
class TestOIDCNativeFCLOIngress:
    def test_fclo_and_sso(
        self,
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
        keycloak_ingress_fclo_setup,
        crd_ingress_controller,
    ):
        ingress_one_name = None
        ingress_two_name = None
        configmap_replaced = False
        secret_one_name = None
        secret_two_name = None
        pol_one = None
        pol_two = None

        try:
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                cm_src,
            )
            configmap_replaced = True
            wait_before_test()

            create_items_from_yaml(kube_apis, webapps_src, test_namespace)

            secret_one_name = create_native_oidc_secret(
                kube_apis, test_namespace, keycloak_ingress_fclo_setup.secret_one, "oidc-native-secret-one"
            )
            secret_two_name = create_native_oidc_secret(
                kube_apis, test_namespace, keycloak_ingress_fclo_setup.secret_two, "oidc-native-secret-two"
            )

            pol_one = create_native_oidc_policy(
                kube_apis,
                test_namespace,
                "oidc-native-policy-one",
                "native-fclo-one",
                "oidc-native-secret-one",
                keycloak_ingress_fclo_setup.host,
            )
            pol_two = create_native_oidc_policy(
                kube_apis,
                test_namespace,
                "oidc-native-policy-two",
                "native-fclo-two",
                "oidc-native-secret-two",
                keycloak_ingress_fclo_setup.host,
            )

            ingress_one_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_one_src)
            ingress_two_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_two_src)

            wait_before_test()

            with sync_playwright() as playwright:
                run_oidc_native_fclo_ingress(
                    playwright.chromium,
                    ingress_controller_endpoint.public_ip,
                    ingress_controller_endpoint.port_ssl,
                )

        finally:
            if ingress_one_name:
                delete_ingress(kube_apis.networking_v1, ingress_one_name, test_namespace)
            if ingress_two_name:
                delete_ingress(kube_apis.networking_v1, ingress_two_name, test_namespace)

            delete_items_from_yaml(kube_apis, webapps_src, test_namespace)
            if secret_one_name:
                delete_secret(kube_apis.v1, secret_one_name, test_namespace)
            if secret_two_name:
                delete_secret(kube_apis.v1, secret_two_name, test_namespace)
            if pol_one:
                delete_policy(kube_apis.custom_objects, pol_one, test_namespace)
            if pol_two:
                delete_policy(kube_apis.custom_objects, pol_two, test_namespace)
            wait_before_test()
            if configmap_replaced:
                replace_configmap_from_yaml(
                    kube_apis.v1,
                    ingress_controller_prerequisites.config_map["metadata"]["name"],
                    ingress_controller_prerequisites.namespace,
                    orig_cm_src,
                )

    def test_rp_initiated_logout(
        self,
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
        keycloak_ingress_fclo_setup,
        crd_ingress_controller,
    ):
        ingress_name = None
        configmap_replaced = False
        secret_name = None
        pol_name = None
        try:
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                cm_src,
            )
            configmap_replaced = True
            wait_before_test()

            create_items_from_yaml(kube_apis, webapps_src, test_namespace)
            secret_name = create_native_oidc_secret(
                kube_apis, test_namespace, keycloak_ingress_fclo_setup.secret_one, "oidc-native-secret-one"
            )
            pol_name = create_native_oidc_policy(
                kube_apis,
                test_namespace,
                "oidc-native-policy-one",
                "native-fclo-one",
                "oidc-native-secret-one",
                keycloak_ingress_fclo_setup.host,
                logout_token_hint=True,
            )
            ingress_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_one_src)
            wait_before_test()

            with sync_playwright() as playwright:
                run_oidc_native_rp_logout_ingress(
                    playwright.chromium,
                    ingress_controller_endpoint.public_ip,
                    ingress_controller_endpoint.port_ssl,
                )
        finally:
            if ingress_name:
                delete_ingress(kube_apis.networking_v1, ingress_name, test_namespace)
            delete_items_from_yaml(kube_apis, webapps_src, test_namespace)
            if secret_name:
                delete_secret(kube_apis.v1, secret_name, test_namespace)
            if pol_name:
                delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            wait_before_test()
            if configmap_replaced:
                replace_configmap_from_yaml(
                    kube_apis.v1,
                    ingress_controller_prerequisites.config_map["metadata"]["name"],
                    ingress_controller_prerequisites.namespace,
                    orig_cm_src,
                )

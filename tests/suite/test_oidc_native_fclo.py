import base64
import secrets
import time

import pytest
import requests
from playwright.sync_api import Error, sync_playwright


def wait_for_login_page(page, url, max_retries=6, timeout_per_try=5000):
    """Navigate to url and wait for Keycloak login form, retrying if NGINX or Keycloak is reloading."""
    last_error = None
    for attempt in range(max_retries):
        try:
            page.goto(url)
            page.wait_for_selector("input[name='username']", timeout=timeout_per_try)
            return
        except Error as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(2)
    raise Error(
        f"Failed to load login page at {url} after {max_retries} attempts (current URL: {page.url}): {last_error}"
    )


from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_secret,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
)

username = "nginx-user-" + secrets.token_hex(4)
password = secrets.token_hex(8)

# Keycloak VirtualServer (reused from the oidc test data)
keycloak_vs_src = f"{TEST_DATA}/oidc/virtual-server-idp.yaml"

# Backend webapp deployments (reused from the NJS FCLO test data)
webapps_src = f"{TEST_DATA}/oidc-fclo/two-webapps.yaml"

# VirtualServers for the two native OIDC FCLO apps
webapp_vs_one_src = f"{TEST_DATA}/oidc-native-fclo/virtual-server-one.yaml"
webapp_vs_two_src = f"{TEST_DATA}/oidc-native-fclo/virtual-server-two.yaml"

# ConfigMap enabling zone-sync + debug logging
cm_src = f"{TEST_DATA}/oidc-native-fclo/configmap-nginx.yaml"
orig_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"


class KeycloakSetupForNativeFCLO:
    """
    Attributes:
        secret_one (str): Base64-encoded client secret for native-fclo-one.
        secret_two (str): Base64-encoded client secret for native-fclo-two.
        host (str): In-cluster Keycloak service hostname.
    """

    def __init__(self, secret_one, secret_two, host):
        self.secret_one = secret_one
        self.secret_two = secret_two
        self.host = host


def get_create_client_payload(name, host):
    """Keycloak client registration payload with front-channel logout enabled."""
    return {
        "clientId": name,
        "name": f"{name} client name",
        "redirectUris": [f"https://{host}/*", f"https://{host}:443/*"],
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "publicClient": False,
        "frontchannelLogout": True,
        "attributes": {
            "post.logout.redirect.uris": f"https://{host}/*##https://{host}:443/*",
            "frontchannel.logout.url": f"https://{host}/front_channel_logout",
        },
        "protocol": "openid-connect",
    }


def create_client_and_get_secret(ip, port, name, host, headers):
    """Register a Keycloak client with FCLO and return its client secret."""
    create_url = f"https://{ip}:{port}/admin/realms/master/clients"
    payload = get_create_client_payload(name, host)
    response = requests.post(create_url, headers=headers, json=payload, verify=False)
    response.raise_for_status()

    # Retrieve client UUID
    get_client_url = f"https://{ip}:{port}/admin/realms/master/clients?clientId={name}&first=1"
    response = requests.get(get_client_url, headers=headers, verify=False)
    response.raise_for_status()
    client_uuid = response.json()[0]["id"]

    # Retrieve client secret
    get_secret_url = f"https://{ip}:{port}/admin/realms/master/clients/{client_uuid}/client-secret"
    response = requests.get(get_secret_url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()["value"]


def create_native_oidc_secret(kube_apis, namespace, encoded_secret, name):
    """Create a K8s Secret of type nginx.org/oidc with the given client secret."""
    return create_secret(
        kube_apis.v1,
        namespace,
        {"metadata": {"name": name}, "type": "nginx.org/oidc", "data": {"client-secret": encoded_secret}},
    )


def create_native_oidc_policy(
    kube_apis, namespace, name, client_id, secret_name, keycloak_host, *, logout_token_hint=False
):
    """Create an oidcNative Policy with FCLO, logout, and post-logout settings."""
    policy = {
        "apiVersion": "k8s.nginx.org/v1",
        "kind": "Policy",
        "metadata": {"name": name},
        "spec": {
            "oidcNative": {
                "issuer": f"https://{keycloak_host}/realms/master",
                "configURL": f"https://{keycloak_host}/realms/master/.well-known/openid-configuration",
                "sslName": keycloak_host,
                "clientID": client_id,
                "clientSecret": secret_name,
                "scope": "openid profile",
                "sslVerify": False,
                "frontChannelLogoutURI": "/front_channel_logout",
                "logoutURI": "/logout",
                "postLogoutRedirectURI": "/_logout",
                "logoutTokenHint": logout_token_hint,
            }
        },
    }
    kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", namespace, "policies", policy)
    return name


@pytest.fixture(scope="class")
def keycloak_setup(request, kube_apis, test_namespace, ingress_controller_endpoint):
    """Deploy keycloak-secure and register two FCLO-enabled native OIDC clients."""

    # TLS secret shared by the webapp VirtualServers
    vs_secret_name = create_secret_from_yaml(
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
    keycloak_vs_name = create_virtual_server_from_yaml(kube_apis.custom_objects, keycloak_vs_src, test_namespace)
    wait_before_test()

    # Get admin token
    url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/realms/master/protocol/openid-connect/token"
    headers = {"Host": keycloak_address, "Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": "admin", "password": "admin", "grant_type": "password", "client_id": "admin-cli"}
    response = requests.post(url, headers=headers, data=data, verify=False)
    response.raise_for_status()
    token = response.json()["access_token"]

    # Create test user
    create_user_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/admin/realms/master/users"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", "Host": keycloak_address}
    user_payload = {
        "username": username,
        "enabled": True,
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    }
    response = requests.post(create_user_url, headers=headers, json=user_payload, verify=False)
    response.raise_for_status()

    # Register two FCLO-enabled clients
    ip = ingress_controller_endpoint.public_ip
    port = ingress_controller_endpoint.port_ssl
    client_secret_one = create_client_and_get_secret(
        ip, port, "native-fclo-one", "native-fclo-one.example.com", headers
    )
    client_secret_two = create_client_and_get_secret(
        ip, port, "native-fclo-two", "native-fclo-two.example.com", headers
    )

    # Native OIDC follows endpoints advertised in discovery metadata. Make the
    # Keycloak service name routable for both NGINX's in-cluster proxy and the
    # Playwright host mapping, while preserving the existing HTTP service port.
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
    kube_apis.custom_objects.patch_namespaced_custom_object(
        "k8s.nginx.org",
        "v1",
        test_namespace,
        "virtualservers",
        keycloak_vs_name,
        {"spec": {"host": keycloak_service_host}},
    )
    wait_before_test()

    encoded_secret_one = base64.b64encode(client_secret_one.encode()).decode()
    encoded_secret_two = base64.b64encode(client_secret_two.encode()).decode()

    print("Keycloak FCLO setup complete")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete Keycloak FCLO resources")
            delete_virtual_server(kube_apis.custom_objects, keycloak_vs_name, test_namespace)
            delete_common_app(kube_apis, backend_app, test_namespace)
            if backend_secret_name != "":
                delete_secret(kube_apis.v1, backend_secret_name, test_namespace)
            if backend_ca_secret_name != "":
                delete_secret(kube_apis.v1, backend_ca_secret_name, test_namespace)
            delete_secret(kube_apis.v1, vs_secret_name, test_namespace)

    request.addfinalizer(fin)

    return KeycloakSetupForNativeFCLO(encoded_secret_one, encoded_secret_two, keycloak_service_host)


def run_oidc_native_fclo(browser_type, ip_address, port):
    """Playwright browser flow: login to app one, verify SSO on app two,
    trigger Keycloak logout, verify both apps listed, then confirm
    FCLO terminated the session."""
    browser = browser_type.launch(headless=True, args=[f"--host-resolver-rules=MAP * {ip_address}:{port}"])
    context = browser.new_context(
        ignore_https_errors=True,
        bypass_csp=True,  # Keycloak's invisible FCLO iframe would be blocked by its own CSP
    )

    try:
        page = context.new_page()

        # Log in to app one via Keycloak
        wait_for_login_page(page, "https://native-fclo-one.example.com")
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
        logout_fields = [
            "You are logging out from following apps",
            "native-fclo-one client name",
            "native-fclo-two client name",
        ]
        for field in logout_fields:
            assert field in page_text, f"'{field}' not found on keycloak logout page"

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


def run_oidc_native_rp_logout(browser_type, ip_address, port):
    """Playwright browser flow: login, navigate to logoutURI, click through
    Keycloak's confirmation page, verify the postLogoutRedirectURI landing
    page, then confirm the session is terminated."""
    browser = browser_type.launch(headless=True, args=[f"--host-resolver-rules=MAP * {ip_address}:{port}"])
    context = browser.new_context(
        ignore_https_errors=True,
        bypass_csp=True,  # Keycloak may render FCLO iframes during the logout flow
    )

    try:
        page = context.new_page()

        # Log in to app one via Keycloak
        wait_for_login_page(page, "https://native-fclo-one.example.com")
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

        # Keycloak shows a confirmation page; click the logout button.
        page.locator("#kc-logout").click()
        page.wait_for_load_state("load")

        # After confirming, Keycloak redirects to the postLogoutRedirectURI.
        # The auto-generated location at /_logout returns "Logged out".
        page_text = page.locator("body").text_content()
        assert "Logged out" in page_text, f"Expected 'Logged out' on post-logout page, got: {page_text[:200]}"

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


@pytest.mark.native_oidc
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        {
            "type": "complete",
            "extra_args": [
                "-enable-oidc",
            ],
        }
    ],
    indirect=True,
)
class TestOIDCNativeFCLO:
    def test_fclo_and_sso(
        self,
        request,
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        test_namespace,
        keycloak_setup,
    ):
        """Front-channel logout across two native OIDC relying parties.

        1. Log in to native-fclo-one via Keycloak.
        2. Navigate to native-fclo-two -- SSO session carries over (no re-login).
        3. Trigger Keycloak logout via app one's logoutURI.
        4. Verify the logout page lists both clients.
        5. Click logout and confirm FCLO terminated sessions on both apps.
        """
        # Deploy backend webapps (reused from NJS FCLO tests)
        create_items_from_yaml(kube_apis, webapps_src, test_namespace)

        secret_one_name = create_native_oidc_secret(
            kube_apis, test_namespace, keycloak_setup.secret_one, "oidc-native-secret-one"
        )
        secret_two_name = create_native_oidc_secret(
            kube_apis, test_namespace, keycloak_setup.secret_two, "oidc-native-secret-two"
        )

        pol_one = create_native_oidc_policy(
            kube_apis,
            test_namespace,
            "oidc-native-policy-one",
            "native-fclo-one",
            "oidc-native-secret-one",
            keycloak_setup.host,
        )
        pol_two = create_native_oidc_policy(
            kube_apis,
            test_namespace,
            "oidc-native-policy-two",
            "native-fclo-two",
            "oidc-native-secret-two",
            keycloak_setup.host,
        )

        wait_before_test()

        vs_one_name = create_virtual_server_from_yaml(kube_apis.custom_objects, webapp_vs_one_src, test_namespace)
        vs_two_name = create_virtual_server_from_yaml(kube_apis.custom_objects, webapp_vs_two_src, test_namespace)

        # Update ConfigMap to enable zone-sync and debug logging
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_src,
        )
        wait_before_test()

        try:
            with sync_playwright() as playwright:
                run_oidc_native_fclo(
                    playwright.chromium,
                    ingress_controller_endpoint.public_ip,
                    ingress_controller_endpoint.port_ssl,
                )
        finally:
            delete_virtual_server(kube_apis.custom_objects, vs_one_name, test_namespace)
            delete_virtual_server(kube_apis.custom_objects, vs_two_name, test_namespace)
            delete_policy(kube_apis.custom_objects, pol_one, test_namespace)
            delete_policy(kube_apis.custom_objects, pol_two, test_namespace)
            delete_secret(kube_apis.v1, secret_one_name, test_namespace)
            delete_secret(kube_apis.v1, secret_two_name, test_namespace)
            delete_items_from_yaml(kube_apis, webapps_src, test_namespace)
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                orig_cm_src,
            )

    def test_rp_initiated_logout(
        self,
        request,
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        test_namespace,
        keycloak_setup,
    ):
        """RP-initiated logout via the native OIDC logoutURI.

        1. Log in to native-fclo-one via Keycloak.
        2. Navigate to /logout (logoutURI) -- the native module redirects to
           Keycloak's end-session endpoint.
        3. Keycloak processes the logout and redirects to /_logout
           (postLogoutRedirectURI).
        4. Verify the post-logout page shows "Logged out".
        5. Confirm the session is terminated (next access shows login form).
        """
        # Deploy backend webapps
        create_items_from_yaml(kube_apis, webapps_src, test_namespace)

        secret_one_name = create_native_oidc_secret(
            kube_apis, test_namespace, keycloak_setup.secret_one, "oidc-native-secret-one"
        )

        pol_one = create_native_oidc_policy(
            kube_apis,
            test_namespace,
            "oidc-native-policy-one",
            "native-fclo-one",
            "oidc-native-secret-one",
            keycloak_setup.host,
            logout_token_hint=True,
        )

        wait_before_test()

        vs_one_name = create_virtual_server_from_yaml(kube_apis.custom_objects, webapp_vs_one_src, test_namespace)

        # Update ConfigMap to enable zone-sync and debug logging
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_src,
        )
        wait_before_test()

        try:
            with sync_playwright() as playwright:
                run_oidc_native_rp_logout(
                    playwright.chromium,
                    ingress_controller_endpoint.public_ip,
                    ingress_controller_endpoint.port_ssl,
                )
        finally:
            delete_virtual_server(kube_apis.custom_objects, vs_one_name, test_namespace)
            delete_policy(kube_apis.custom_objects, pol_one, test_namespace)
            delete_secret(kube_apis.v1, secret_one_name, test_namespace)
            delete_items_from_yaml(kube_apis, webapps_src, test_namespace)
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                orig_cm_src,
            )

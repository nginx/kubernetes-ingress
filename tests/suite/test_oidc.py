import base64
import secrets

import pytest
import requests
import yaml
from playwright.sync_api import Error, sync_playwright
from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret,
    create_secret_from_yaml,
    delete_common_app,
    delete_secret,
    delete_service,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
    patch_virtual_server_from_yaml,
)

username = "nginx-user-" + secrets.token_hex(4)
password = secrets.token_hex(8)
keycloak_src = f"{TEST_DATA}/oidc/keycloak.yaml"
keycloak_vs_src = f"{TEST_DATA}/oidc/virtual-server-idp.yaml"
oidc_secret_src = f"{TEST_DATA}/oidc/client-secret.yaml"
oidc_pol_src = f"{TEST_DATA}/oidc/oidc.yaml"
pkce_pol_src = f"{TEST_DATA}/oidc/pkce.yaml"
oidc_vs_src = f"{TEST_DATA}/oidc/virtual-server.yaml"
orig_vs_src = f"{TEST_DATA}/virtual-server-tls/standard/virtual-server.yaml"
cm_src = f"{TEST_DATA}/oidc/nginx-config.yaml"
cm_zs_src = f"{TEST_DATA}/oidc/nginx-config-zs.yaml"
orig_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"
svc_src = f"{TEST_DATA}/oidc/nginx-ingress-headless.yaml"


class KeycloakSetup:
    """
    Attributes:
        secret (str):
    """

    def __init__(self, secret):
        self.secret = secret


@pytest.fixture(scope="class")
def keycloak_setup(request, kube_apis, test_namespace, ingress_controller_endpoint, virtual_server_setup):

    # Create Keycloak resources and setup Keycloak idp

    secret_name = create_secret_from_yaml(
        kube_apis.v1, virtual_server_setup.namespace, f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
    )
    keycloak_address = "keycloak.example.com"
    create_example_app(kube_apis, "keycloak", test_namespace)
    wait_before_test()
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    keycloak_vs_name = create_virtual_server_from_yaml(kube_apis.custom_objects, keycloak_vs_src, test_namespace)
    wait_before_test()

    # Get token
    url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/realms/master/protocol/openid-connect/token"
    headers = {"Host": keycloak_address, "Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": "admin", "password": "admin", "grant_type": "password", "client_id": "admin-cli"}

    response = requests.post(url, headers=headers, data=data, verify=False)
    token = response.json()["access_token"]

    # Create a user and set credentials
    create_user_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/admin/realms/master/users"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", "Host": keycloak_address}
    user_payload = {
        "username": username,
        "enabled": True,
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    }
    response = requests.post(create_user_url, headers=headers, json=user_payload, verify=False)

    # Create client "nginx-plus-pkce" for the pkce test
    create_pkce_client_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/admin/realms/master/clients"
    pkce_client_payload = {
        "clientId": "nginx-plus-pkce",
        "redirectUris": ["https://virtual-server-tls.example.com:443/_codexch"],
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "publicClient": True,
        "attributes": {
            "post.logout.redirect.uris": "https://virtual-server-tls.example.com:443/*",
            "pkce.code.challenge.method": "S256",
        },
        "protocol": "openid-connect",
    }
    pkce_client_resp = requests.post(create_pkce_client_url, headers=headers, json=pkce_client_payload, verify=False)
    pkce_client_resp.raise_for_status()

    # Create client "nginx-plus" and get secret
    create_client_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/realms/master/clients-registrations/default"
    client_payload = {
        "clientId": "nginx-plus",
        "redirectUris": ["https://virtual-server-tls.example.com:443/_codexch"],
        "attributes": {"post.logout.redirect.uris": "https://virtual-server-tls.example.com:443/*"},
    }
    client_resp = requests.post(create_client_url, headers=headers, json=client_payload, verify=False)
    client_resp.raise_for_status()
    secret = client_resp.json().get("secret")

    # Base64 encode the secret
    encoded_secret = base64.b64encode(secret.encode()).decode()

    print(f"Keycloak setup complete. Base64 encoded client secret")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete Keycloak resources")
            delete_virtual_server(kube_apis.custom_objects, keycloak_vs_name, test_namespace)
            delete_common_app(kube_apis, "keycloak", test_namespace)
            delete_secret(kube_apis.v1, secret_name, test_namespace)

    request.addfinalizer(fin)

    return KeycloakSetup(encoded_secret)


@pytest.mark.oidc
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-oidc",
                ],
            },
            {"example": "virtual-server-tls", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestOIDC:
    @pytest.mark.parametrize("configmap", [cm_src, cm_zs_src])
    @pytest.mark.parametrize("oidcYaml", [oidc_pol_src, pkce_pol_src])
    def test_oidc(
        self,
        request,
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        test_namespace,
        virtual_server_setup,
        keycloak_setup,
        configmap,
        oidcYaml,
    ):
        print(f"Create oidc secret")
        with open(oidc_secret_src) as f:
            secret_data = yaml.safe_load(f)
        secret_data["data"]["client-secret"] = keycloak_setup.secret
        secret_name = create_secret(kube_apis.v1, test_namespace, secret_data)

        print(f"Create oidc policy")
        with open(oidcYaml) as f:
            doc = yaml.safe_load(f)
        pol = doc["metadata"]["name"]
        doc["spec"]["oidc"]["tokenEndpoint"] = doc["spec"]["oidc"]["tokenEndpoint"].replace("default", test_namespace)
        doc["spec"]["oidc"]["jwksURI"] = doc["spec"]["oidc"]["jwksURI"].replace("default", test_namespace)
        kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", test_namespace, "policies", doc)
        print(f"Policy created with name {pol}")
        wait_before_test()

        print(f"Create virtual server")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, oidc_vs_src, test_namespace
        )
        wait_before_test()
        print(f"Update nginx configmap")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            configmap,
        )
        wait_before_test()

        if configmap == cm_src:
            print(f"Create headless service")
            create_items_from_yaml(kube_apis, svc_src, ingress_controller_prerequisites.namespace)

        with sync_playwright() as playwright:
            run_oidc(playwright.chromium, ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port_ssl)

        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_src,
        )
        delete_secret(kube_apis.v1, secret_name, test_namespace)
        delete_policy(kube_apis.custom_objects, pol, test_namespace)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, orig_vs_src, test_namespace
        )
        if configmap == cm_src:
            with open(svc_src) as f:
                headless_svc = yaml.safe_load(f)
            headless_name = headless_svc["metadata"]["name"]
            delete_service(kube_apis.v1, headless_name, ingress_controller_prerequisites.namespace)


def run_oidc(browser_type, ip_address, port):

    browser = browser_type.launch(headless=True, args=[f"--host-resolver-rules=MAP * {ip_address}:{port}"])
    context = browser.new_context(ignore_https_errors=True)

    try:
        page = context.new_page()

        page.goto("https://virtual-server-tls.example.com")
        page.wait_for_selector('input[name="username"]')
        page.fill('input[name="username"]', username)
        page.wait_for_selector('input[name="password"]', timeout=5000)
        page.fill('input[name="password"]', password)

        with page.expect_navigation():
            page.click('input[type="submit"]')
        page.wait_for_load_state("load")
        page_text = page.text_content("body")
        fields_to_check = [
            "Server address:",
            "Server name:",
            "Date:",
            "Request ID:",
        ]
        for field in fields_to_check:
            assert field in page_text, f"'{field}' not found in page text"

    except Error as e:
        assert False, f"Error: {e}"

    finally:
        context.close()
        browser.close()

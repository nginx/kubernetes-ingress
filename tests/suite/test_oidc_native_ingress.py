import base64
import secrets

import pytest
import requests
import yaml
from playwright.sync_api import Error, sync_playwright
from settings import DEPLOYMENTS, TEST_DATA
from suite.test_oidc_native import KeycloakSetup  # noqa: F401
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress_from_yaml,
    create_items_from_yaml,
    create_secret,
    create_secret_from_yaml,
    delete_common_app,
    delete_ingress,
    delete_items_from_yaml,
    delete_secret,
    delete_service,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)

username = "nginx-user-" + secrets.token_hex(4)
password = secrets.token_hex(8)

keycloak_ingress_src = f"{TEST_DATA}/oidc-native/ingress/keycloak-ingress.yaml"
oidc_native_secret_src = f"{TEST_DATA}/oidc-native/client-secret.yaml"
oidc_native_pol_src = f"{TEST_DATA}/oidc-native/oidc-native.yaml"
pkce_pol_src = f"{TEST_DATA}/oidc-native/pkce.yaml"

ingress_src = f"{TEST_DATA}/oidc-native/ingress/oidc-native-policy-ingress.yaml"
orig_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"

cm_src = f"{TEST_DATA}/oidc/nginx-config.yaml"
cm_zs_src = f"{TEST_DATA}/oidc/nginx-config-zs.yaml"
svc_src = f"{TEST_DATA}/oidc/nginx-ingress-headless.yaml"


def get_oidc_native_policy_file(oidc_type):
    return oidc_native_pol_src if oidc_type == "standard" else pkce_pol_src


def run_oidc_native_ingress(browser_type, ip_address, port, target_host="https://oidc-native.example.com"):
    browser = browser_type.launch(headless=True, args=[f"--host-resolver-rules=MAP * {ip_address}:{port}"])
    context = browser.new_context(ignore_https_errors=True)

    try:
        page = context.new_page()

        # 1. Navigate to Ingress hostname
        page.goto(target_host)

        # 2. Fill Keycloak login form
        page.locator("input[name='username']").fill(username)
        page.locator("input[name='password']").fill(password)
        page.locator('button[type="submit"]').click()

        # 3. Wait for redirect back to oidc-native.example.com
        page.wait_for_url(f"{target_host}/*")

        # 4. Verify simple app response content
        page_text = page.locator("body").text_content()
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


@pytest.fixture(scope="class")
def keycloak_ingress_setup(request, kube_apis, test_namespace, ingress_controller_endpoint):
    """
    Sets up Keycloak IdP using purely Ingress resources (no VirtualServer).
    """
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

    # Create client "nginx-plus-pkce" for the pkce test
    create_pkce_client_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/admin/realms/master/clients"
    pkce_client_payload = {
        "clientId": "nginx-plus-pkce",
        "redirectUris": ["https://oidc-native.example.com/*"],
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "publicClient": True,
        "attributes": {
            "post.logout.redirect.uris": "https://oidc-native.example.com/*",
            "pkce.code.challenge.method": "S256",
        },
        "protocol": "openid-connect",
    }
    pkce_client_resp = requests.post(
        create_pkce_client_url, headers=auth_headers, json=pkce_client_payload, verify=False
    )
    pkce_client_resp.raise_for_status()

    create_client_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/realms/master/clients-registrations/default"
    client_payload = {
        "clientId": "nginx-plus",
        "redirectUris": ["https://oidc-native.example.com/*"],
        "attributes": {"post.logout.redirect.uris": "https://oidc-native.example.com/*"},
    }
    client_resp = requests.post(create_client_url, headers=auth_headers, json=client_payload, verify=False)
    client_resp.raise_for_status()
    secret = client_resp.json().get("secret")

    # Make Keycloak in-cluster service host routable for NGINX Native OIDC discovery
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

    encoded_secret = base64.b64encode(secret.encode()).decode()

    print(f"Keycloak setup complete. Base64 encoded client secret")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete Keycloak resources")
            delete_ingress(kube_apis.networking_v1, keycloak_ingress_name, test_namespace)
            delete_common_app(kube_apis, backend_app, test_namespace)
            delete_secret(kube_apis.v1, backend_secret_name, test_namespace)
            delete_secret(kube_apis.v1, backend_ca_secret_name, test_namespace)
            delete_secret(kube_apis.v1, ingress_secret_name, test_namespace)

    request.addfinalizer(fin)
    return KeycloakSetup(encoded_secret, keycloak_service_host)


@pytest.mark.policies
@pytest.mark.native_oidc
@pytest.mark.usefixtures("crd_ingress_controller")
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        {
            "type": "complete",
            "extra_args": [
                "-enable-custom-resources",
                "-enable-oidc",
                "-enable-prometheus-metrics",
            ],
        }
    ],
    indirect=True,
)
class TestOIDCNativeIngress:

    @pytest.mark.parametrize("configmap", [cm_src, cm_zs_src])
    @pytest.mark.parametrize("oidcYaml", ["standard", "pkce"])
    def test_oidc_native_ingress(
        self,
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        test_namespace,
        keycloak_ingress_setup,
        configmap,
        oidcYaml,
    ):
        secret_name = None
        pol_name = None
        ingress_name = None
        backend_deployed = False
        configmap_replaced = False
        headless_name = None

        try:
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                configmap,
            )
            configmap_replaced = True
            wait_before_test()

            if configmap == cm_src:
                create_items_from_yaml(kube_apis, svc_src, ingress_controller_prerequisites.namespace)
                with open(svc_src) as f:
                    headless_name = yaml.safe_load(f)["metadata"]["name"]

            create_items_from_yaml(kube_apis, f"{TEST_DATA}/common/backend1.yaml", test_namespace)
            create_items_from_yaml(kube_apis, f"{TEST_DATA}/common/backend1-svc.yaml", test_namespace)
            backend_deployed = True
            wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

            with open(oidc_native_secret_src) as f:
                secret_data = yaml.safe_load(f)
            secret_data["data"]["client-secret"] = keycloak_ingress_setup.secret
            secret_name = create_secret(kube_apis.v1, test_namespace, secret_data)

            policy_file = get_oidc_native_policy_file(oidcYaml)
            with open(policy_file) as f:
                doc = yaml.safe_load(f)

            doc["metadata"]["name"] = "oidc-native-policy"
            doc["spec"]["oidcNative"]["issuer"] = f"https://{keycloak_ingress_setup.host}/realms/master"
            doc["spec"]["oidcNative"][
                "configURL"
            ] = f"https://{keycloak_ingress_setup.host}/realms/master/.well-known/openid-configuration"
            doc["spec"]["oidcNative"]["sslName"] = keycloak_ingress_setup.host

            pol_name = doc["metadata"]["name"]
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", test_namespace, "policies", doc
            )
            wait_before_test()

            ingress_name = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, ingress_src)
            wait_before_test()

            with sync_playwright() as playwright:
                run_oidc_native_ingress(
                    playwright.chromium,
                    ingress_controller_endpoint.public_ip,
                    ingress_controller_endpoint.port_ssl,
                )

        finally:
            if ingress_name:
                delete_ingress(kube_apis.networking_v1, ingress_name, test_namespace)
            if backend_deployed:
                delete_items_from_yaml(kube_apis, f"{TEST_DATA}/common/backend1.yaml", test_namespace)
                delete_items_from_yaml(kube_apis, f"{TEST_DATA}/common/backend1-svc.yaml", test_namespace)
            if pol_name:
                delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            if secret_name:
                delete_secret(kube_apis.v1, secret_name, test_namespace)
            wait_before_test()
            if headless_name:
                delete_service(kube_apis.v1, headless_name, ingress_controller_prerequisites.namespace)
            if configmap_replaced:
                replace_configmap_from_yaml(
                    kube_apis.v1,
                    ingress_controller_prerequisites.config_map["metadata"]["name"],
                    ingress_controller_prerequisites.namespace,
                    orig_cm_src,
                )

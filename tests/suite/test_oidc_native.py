import base64
import secrets

import pytest
import requests
import yaml
from playwright.sync_api import Error, sync_playwright
from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.custom_assertions import assert_vs_status
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret,
    create_secret_from_yaml,
    delete_common_app,
    delete_secret,
    delete_service,
    get_first_pod_name,
    get_vs_nginx_template_conf,
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
keycloak_vs_src = f"{TEST_DATA}/oidc/virtual-server-idp.yaml"
oidc_native_secret_src = f"{TEST_DATA}/oidc-native/client-secret.yaml"
oidc_native_pol_src = {
    "http": f"{TEST_DATA}/oidc-native/oidc-native.yaml",
    "https": f"{TEST_DATA}/oidc-native/oidc-native-tls.yaml",
}
pkce_pol_src = {"http": f"{TEST_DATA}/oidc-native/pkce.yaml", "https": f"{TEST_DATA}/oidc-native/pkce-tls.yaml"}
oidc_native_vs_src = f"{TEST_DATA}/oidc-native/virtual-server.yaml"
orig_vs_src = f"{TEST_DATA}/virtual-server-tls/standard/virtual-server.yaml"
cm_src = f"{TEST_DATA}/oidc/nginx-config.yaml"
cm_zs_src = f"{TEST_DATA}/oidc/nginx-config-zs.yaml"
orig_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"
svc_src = f"{TEST_DATA}/oidc/nginx-ingress-headless.yaml"


class KeycloakSetup:
    """
    Attributes:
        secret (str):
        host (str):
    """

    def __init__(self, secret, host):
        self.secret = secret
        self.host = host


@pytest.fixture(scope="class")
def keycloak_setup(request, kube_apis, test_namespace, ingress_controller_endpoint, virtual_server_setup):

    # Create Keycloak resources and setup Keycloak idp

    vs_secret_name = create_secret_from_yaml(
        kube_apis.v1, virtual_server_setup.namespace, f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
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

    # Get token
    url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/realms/master/protocol/openid-connect/token"
    headers = {"Host": keycloak_address, "Content-Type": "application/x-www-form-urlencoded"}
    data = {"username": "admin", "password": "admin", "grant_type": "password", "client_id": "admin-cli"}

    response = requests.post(url, headers=headers, data=data, verify=False)
    response.raise_for_status()
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
    response.raise_for_status()

    # Create client "nginx-plus-pkce" for the pkce test (using wildcard for dynamic native callback url paths)
    create_pkce_client_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/admin/realms/master/clients"
    pkce_client_payload = {
        "clientId": "nginx-plus-pkce",
        "redirectUris": ["https://virtual-server-tls.example.com/*"],
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "publicClient": True,
        "attributes": {
            "post.logout.redirect.uris": "https://virtual-server-tls.example.com/*",
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
        "redirectUris": ["https://virtual-server-tls.example.com/*"],
        "attributes": {"post.logout.redirect.uris": "https://virtual-server-tls.example.com/*"},
    }
    client_resp = requests.post(create_client_url, headers=headers, json=client_payload, verify=False)
    client_resp.raise_for_status()
    secret = client_resp.json().get("secret")

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

    # Base64 encode the secret
    encoded_secret = base64.b64encode(secret.encode()).decode()

    print(f"Keycloak setup complete. Base64 encoded client secret")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete Keycloak resources")
            delete_virtual_server(kube_apis.custom_objects, keycloak_vs_name, test_namespace)
            delete_common_app(kube_apis, backend_app, test_namespace)
            if backend_secret_name != "":
                delete_secret(kube_apis.v1, backend_secret_name, test_namespace)
            if backend_ca_secret_name != "":
                delete_secret(kube_apis.v1, backend_ca_secret_name, test_namespace)
            delete_secret(kube_apis.v1, vs_secret_name, test_namespace)

    request.addfinalizer(fin)

    return KeycloakSetup(encoded_secret, keycloak_service_host)


@pytest.mark.native_oidc
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup, keycloak_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-oidc",
                ],
            },
            {"example": "virtual-server-tls", "app_type": "simple"},
            {},
        ),
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-oidc",
                    "-enable-config-safety",
                ],
            },
            {"example": "virtual-server-tls", "app_type": "simple"},
            {},
        ),
    ],
    indirect=True,
    ids=["https_without_config_safety", "https_with_config_safety"],
)
class TestOIDCNative:
    """
    Full browser login flow, mirroring TestOIDCHttp in test_oidc.py.

    Uses the sslVerify: false policy variant only. The sslVerify: true +
    trustedCertSecret variant cannot complete a real browser flow in this
    environment: native OIDC couples the browser-facing issuer and the
    in-cluster backchannel to a single hostname (unlike NJS OIDC, which
    splits authEndpoint/tokenEndpoint independently), so the shipped
    Keycloak cert's SAN can never match the service-DNS hostname used for
    discovery. See TestOIDCNativeTrustedCA for the equivalent config-level
    coverage of that variant.
    """

    @pytest.mark.parametrize("configmap", [cm_src, cm_zs_src])
    @pytest.mark.parametrize("oidcYaml", ["standard", "pkce"])
    def test_oidc_native(
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
        run_test(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            virtual_server_setup,
            keycloak_setup,
            configmap,
            oidcYaml,
        )


def run_test(
    kube_apis,
    ingress_controller_endpoint,
    ingress_controller_prerequisites,
    test_namespace,
    virtual_server_setup,
    keycloak_setup,
    configmap,
    oidcYaml,
):
    # Order matters. NGINX cannot change the `sync` flag of an existing shared
    # memory zone across a reload -- it fails with "the \"sync\" flag of
    # shared memory zone ... had previously a different state" and rejects
    # the config. The native OIDC session zone is declared with `sync` only
    # when ConfigMap zone-sync is enabled, so:
    #   - the ConfigMap must reach its final state BEFORE the policy/VS
    #     create the zone, and
    #   - the zone must be gone (VS/policy deleted) BEFORE the ConfigMap is
    #     restored to its original state.
    # NJS OIDC is unaffected because its keyval zones are static in
    # nginx.conf, gated only on the static -enable-oidc flag.
    secret_name = None
    pol = None
    vs_patched = False
    configmap_replaced = False
    headless_name = None

    try:
        print("Update nginx configmap")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            configmap,
        )
        configmap_replaced = True
        wait_before_test()

        if configmap == cm_src:
            print("Create headless service")
            create_items_from_yaml(kube_apis, svc_src, ingress_controller_prerequisites.namespace)
            with open(svc_src) as f:
                headless_name = yaml.safe_load(f)["metadata"]["name"]

        print("Create oidc-native secret")
        with open(oidc_native_secret_src) as f:
            secret_data = yaml.safe_load(f)
        secret_data["data"]["client-secret"] = keycloak_setup.secret
        secret_name = create_secret(kube_apis.v1, test_namespace, secret_data)

        policy_file = get_oidc_native_policy_file(oidcYaml)
        print(f"Create oidc-native policy from file {policy_file}")
        with open(policy_file) as f:
            doc = yaml.safe_load(f)
        # Use the service hostname advertised by Keycloak so native OIDC can
        # resolve discovered endpoints inside the cluster.
        doc["spec"]["oidcNative"]["issuer"] = f"https://{keycloak_setup.host}/realms/master"
        doc["spec"]["oidcNative"][
            "configURL"
        ] = f"https://{keycloak_setup.host}/realms/master/.well-known/openid-configuration"
        doc["spec"]["oidcNative"]["sslName"] = keycloak_setup.host
        pol = doc["metadata"]["name"]
        kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", test_namespace, "policies", doc)
        print(f"Policy created with name {pol}")
        wait_before_test()

        print("Create virtual server")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, oidc_native_vs_src, test_namespace
        )
        vs_patched = True
        wait_before_test()

        with sync_playwright() as playwright:
            run_oidc_native(
                playwright.chromium, ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port_ssl
            )
    finally:
        if vs_patched:
            patch_virtual_server_from_yaml(
                kube_apis.custom_objects, virtual_server_setup.vs_name, orig_vs_src, test_namespace
            )
        if pol:
            delete_policy(kube_apis.custom_objects, pol, test_namespace)
        if secret_name:
            delete_secret(kube_apis.v1, secret_name, test_namespace)
        # Give the VS-deletion reload time to settle before the ConfigMap
        # changes, so the zone-removal and the sync-state change don't
        # coalesce into a single reload (see comment above).
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


def get_oidc_native_policy_file(oidcYaml):
    policy_src = oidc_native_pol_src if oidcYaml == "standard" else pkce_pol_src
    return policy_src["http"]


def run_oidc_native(browser_type, ip_address, port):

    browser = browser_type.launch(headless=True, args=[f"--host-resolver-rules=MAP * {ip_address}:{port}"])
    context = browser.new_context(ignore_https_errors=True)

    try:
        page = context.new_page()

        page.goto("https://virtual-server-tls.example.com")

        page.locator("input[name='username']").fill(username)
        page.locator("input[name='password']").fill(password)

        page.locator('button[type="submit"]').click()
        page.wait_for_url("https://virtual-server-tls.example.com")

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


@pytest.mark.native_oidc
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup, keycloak_setup",
    [
        (
            {"type": "complete", "extra_args": ["-enable-oidc"]},
            {"example": "virtual-server-tls", "app_type": "simple"},
            {},
        )
    ],
    indirect=True,
)
class TestOIDCNativeTrustedCA:
    """
    Config-generation coverage for the sslVerify: true + trustedCertSecret
    variant. Asserts NGINX config, not a browser login -- see the docstring
    on TestOIDCNative for why the full flow cannot pass here.
    """

    @pytest.mark.parametrize("oidcYaml", ["standard", "pkce"])
    def test_native_policy_with_trusted_ca_renders_verification(
        self,
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        test_namespace,
        virtual_server_setup,
        keycloak_setup,
        oidcYaml,
    ):
        secret_name = None
        pol = None
        vs_patched = False
        try:
            print("Update nginx configmap")
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                cm_src,
            )
            wait_before_test()

            print("Create oidc-native secret")
            with open(oidc_native_secret_src) as f:
                secret_data = yaml.safe_load(f)
            secret_data["data"]["client-secret"] = keycloak_setup.secret
            secret_name = create_secret(kube_apis.v1, test_namespace, secret_data)

            policy_src = oidc_native_pol_src if oidcYaml == "standard" else pkce_pol_src
            with open(policy_src["https"]) as f:
                doc = yaml.safe_load(f)
            doc["spec"]["oidcNative"]["issuer"] = f"https://{keycloak_setup.host}/realms/master"
            doc["spec"]["oidcNative"][
                "configURL"
            ] = f"https://{keycloak_setup.host}/realms/master/.well-known/openid-configuration"
            doc["spec"]["oidcNative"]["sslName"] = keycloak_setup.host
            doc["spec"]["oidcNative"]["sslVerifyDepth"] = 2
            pol = doc["metadata"]["name"]
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", test_namespace, "policies", doc
            )
            wait_before_test()

            patch_virtual_server_from_yaml(
                kube_apis.custom_objects, virtual_server_setup.vs_name, oidc_native_vs_src, test_namespace
            )
            vs_patched = True
            assert_vs_status(kube_apis, test_namespace, virtual_server_setup.vs_name, "Valid")

            ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
            conf = get_vs_nginx_template_conf(
                kube_apis.v1,
                test_namespace,
                virtual_server_setup.vs_name,
                ic_pod_name,
                ingress_controller_prerequisites.namespace,
            )
            for directive in [
                "ssl_trusted_certificate",
                "proxy_ssl_trusted_certificate",
                "proxy_ssl_verify on;",
                "proxy_ssl_verify_depth 2;",
            ]:
                assert directive in conf, f"expected '{directive}' in generated config"
        finally:
            if vs_patched:
                patch_virtual_server_from_yaml(
                    kube_apis.custom_objects, virtual_server_setup.vs_name, orig_vs_src, test_namespace
                )
            if pol:
                delete_policy(kube_apis.custom_objects, pol, test_namespace)
            if secret_name:
                delete_secret(kube_apis.v1, secret_name, test_namespace)
            wait_before_test()
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                orig_cm_src,
            )

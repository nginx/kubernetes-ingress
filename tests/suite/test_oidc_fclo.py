import base64
import secrets

import pytest
import requests
import yaml
from playwright.sync_api import Error, sync_playwright
from settings import TEST_DATA
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret,
    create_secret_from_yaml,
    delete_common_app,
    delete_secret,
    get_pod_name_that_contains,
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

# Keycloak VirtualServer, reusing the one in the oidc test
keycloak_vs_src = f"{TEST_DATA}/oidc/virtual-server-idp.yaml"

# Client secrets for the two clients created in KeycloakSetupForFCLO fixture
client_secret_one_src = f"{TEST_DATA}/oidc-fclo/secret-client-one.yaml"
client_secret_two_src = f"{TEST_DATA}/oidc-fclo/secret-client-two.yaml"

# OIDC policies for the two clients created in KeycloakSetupForFCLO fixture
oidc_pol_one_src = f"{TEST_DATA}/oidc-fclo/policy-oidc-one.yaml"
oidc_pol_two_src = f"{TEST_DATA}/oidc-fclo/policy-oidc-two.yaml"

# nginx configmap to enable the error log level
cm_src = f"{TEST_DATA}/oidc-fclo/configmap-nginx.yaml"

# webapp deployments
webapps_src = f"{TEST_DATA}/oidc-fclo/two-webapps.yaml"

# virtual servers for the webapps
webapp_vs_one_src = f"{TEST_DATA}/oidc-fclo/virtual-server-one.yaml"
webapp_vs_two_src = f"{TEST_DATA}/oidc-fclo/virtual-server-two.yaml"


class KeycloakSetupForFCLO:
    """
    Attributes:
        secret_one (str):
        secret_two (str):
    """

    def __init__(self, secret_one, secret_two):
        self.secret_one = secret_one
        self.secret_two = secret_two


@pytest.fixture(scope="class")
def keycloak_setup(request, kube_apis, test_namespace, ingress_controller_endpoint):

    # Create Keycloak resources and setup Keycloak idp

    secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/virtual-server-tls/tls-secret.yaml"
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
    response.raise_for_status()

    # Create two fclo clients and get their secrets
    # Client one
    client_secret_one = create_client_and_get_secret(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port_ssl, "fclo-one", headers
    )

    # Client two
    client_secret_two = create_client_and_get_secret(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port_ssl, "fclo-two", headers
    )

    # Base64 encode the secret
    encoded_secret_one = base64.b64encode(client_secret_one.encode()).decode()
    encoded_secret_two = base64.b64encode(client_secret_two.encode()).decode()

    print(f"Keycloak setup complete. Base64 encoded client secret")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete Keycloak resources")
            delete_virtual_server(kube_apis.custom_objects, keycloak_vs_name, test_namespace)
            delete_common_app(kube_apis, "keycloak", test_namespace)
            delete_secret(kube_apis.v1, secret_name, test_namespace)

    request.addfinalizer(fin)

    return KeycloakSetupForFCLO(encoded_secret_one, encoded_secret_two)


@pytest.mark.oidc
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        {
            "type": "complete",
            "extra_args": [
                f"-enable-oidc",
            ],
        }
    ],
    indirect=True,
)
class TestOIDCFCLO:
    def test_oidc(
        self,
        request,
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        test_namespace,
        keycloak_setup,
    ):
        print(f"Deploy the backend apps")
        create_items_from_yaml(kube_apis, webapps_src, test_namespace)

        print(f"Create oidc secret for client one")
        with open(client_secret_one_src) as f:
            secret_data = yaml.safe_load(f)
        secret_data["data"]["client-secret"] = keycloak_setup.secret_one
        secret_one_name = create_secret(kube_apis.v1, test_namespace, secret_data)

        print(f"Create oidc secret for client two")
        with open(client_secret_two_src) as f:
            secret_data = yaml.safe_load(f)
        secret_data["data"]["client-secret"] = keycloak_setup.secret_two
        secret_two_name = create_secret(kube_apis.v1, test_namespace, secret_data)

        pol_one = create_policy(oidc_pol_one_src, kube_apis, test_namespace)
        pol_two = create_policy(oidc_pol_two_src, kube_apis, test_namespace)

        wait_before_test()

        print(f"Creating the virtual servers for the webapps")
        create_virtual_server_from_yaml(kube_apis.custom_objects, webapp_vs_one_src, test_namespace)
        create_virtual_server_from_yaml(kube_apis.custom_objects, webapp_vs_two_src, test_namespace)

        wait_before_test()
        print(f"Update nginx configmap")
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_src,
        )
        wait_before_test()

        with sync_playwright() as playwright:
            run_oidc_fclo(
                playwright.chromium, ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port_ssl
            )

        # Check nginx-ingress logs for two instances to /front_channel_logout
        nic_pod_name = get_pod_name_that_contains(
            kube_apis.v1, ingress_controller_prerequisites.namespace, "nginx-ingress-"
        )

        retry = 0
        count_fclo_initiated = 0
        logs = ""
        expected_fclo_count = 2
        while count_fclo_initiated != expected_fclo_count and retry < 10:
            wait_before_test(1)  # wait one second before retrying

            logs = kube_apis.v1.read_namespaced_pod_log(nic_pod_name, ingress_controller_prerequisites.namespace)

            count_fclo_initiated = logs.count("OIDC Front-Channel Logout initiated for sid:")

            print(f"OIDC FCLO Initiated count in the while loop: {count_fclo_initiated}, retrying... {retry}")
            retry += 1

        assert (
            count_fclo_initiated == expected_fclo_count
        ), f"nginx-ingress logs do not contain OIDC Front-Channel Logout initiated for sid twice, got {count_fclo_initiated}"

        count_get_fclo = logs.count("GET /front_channel_logout?sid=")

        assert (
            count_get_fclo == expected_fclo_count
        ), f"nginx-ingress logs do not contain GET /front_channel_logout?sid= twice, got {count_get_fclo}"

        delete_secret(kube_apis.v1, secret_one_name, test_namespace)
        delete_secret(kube_apis.v1, secret_two_name, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_one, test_namespace)
        delete_policy(kube_apis.custom_objects, pol_two, test_namespace)


def run_oidc_fclo(browser_type, ip_address, port):
    browser = browser_type.launch(headless=True, args=[f"--host-resolver-rules=MAP * {ip_address}:{port}"])
    context = browser.new_context(
        ignore_https_errors=True,
        bypass_csp=True,  # We need this because keycloak's invisible iframe
        # would otherwise be blocked by the CSP headers set by
        # Keycloak itself.
    )

    try:
        page = context.new_page()

        # Log in to keycloak via fclo one

        page.goto("https://fclo-one.example.com")
        page.wait_for_selector('input[name="username"]')
        page.fill('input[name="username"]', username)
        page.wait_for_selector('input[name="password"]', timeout=5000)
        page.fill('input[name="password"]', password)

        page.locator('button[type="submit"]').click()
        page.wait_for_url("https://fclo-one.example.com")

        page_text = page.text_content("body")
        fields_to_check = [
            "Server address:",
            "Server name:",
            "Date:",
            "Request ID:",
        ]
        for field in fields_to_check:
            assert field in page_text, f"'{field}' not found in page text on fclo one"

        # Check that we're also logged in via fclo two
        page.goto("https://fclo-two.example.com")
        page.wait_for_load_state("load")
        page_text = page.text_content("body")

        for field in fields_to_check:
            assert field in page_text, f"'{field}' not found in page text on fclo two"

        # Start the log out process, go to keycloak's logout page
        page.goto("https://keycloak.example.com/realms/master/protocol/openid-connect/logout")
        page.locator("#kc-logout").click()
        page_text = page.text_content("body")
        fields_to_check = [
            "You are logging out from following apps",
            "fclo-one client name",
            "fclo-two client name",
        ]
        for field in fields_to_check:
            assert field in page_text, f"'{field}' not found in keycloak logout page"

    except Error as e:
        assert False, f"Error: {e}"

    finally:
        context.close()
        browser.close()


# Used in the create_client_and_get_secret function
def get_create_client_payload(name):
    return {
        "clientId": f"{name}",
        "name": f"{name} client name",
        "redirectUris": [f"https://{name}.example.com:443/*"],
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "publicClient": False,
        "frontchannelLogout": True,
        "attributes": {
            "post.logout.redirect.uris": f"https://{name}.example.com:443/*",
            "frontchannel.logout.url": f"https://{name}.example.com/front_channel_logout",
        },
        "protocol": "openid-connect",
    }


# Used in the create_client_and_get_secret function
def get_first_client_url(ip, port, name):
    return f"https://{ip}:{port}/admin/realms/master/clients?clientId={name}&first=1"


# Used in the create_client_and_get_secret function
def get_client_secret_url(ip, port, uuid):
    return f"https://{ip}:{port}/admin/realms/master/clients/{uuid}/client-secret"


def create_client_and_get_secret(ip, port, name, headers):
    create_keycloak_client_url = f"https://{ip}:{port}/admin/realms/master/clients"
    payload = get_create_client_payload(name)
    response = requests.post(create_keycloak_client_url, headers=headers, json=payload, verify=False)
    response.raise_for_status()

    # Get client uuid
    get_client_url = get_first_client_url(ip, port, name)
    response = requests.get(get_client_url, headers=headers, verify=False)
    response.raise_for_status()
    client_uuid = response.json()[0]["id"]

    # Get client secret
    get_secret_url = get_client_secret_url(ip, port, client_uuid)
    response = requests.get(get_secret_url, headers=headers, verify=False)
    response.raise_for_status()
    client_secret = response.json()["value"]

    return client_secret


def create_policy(policy_file_path, kube_apis, test_namespace) -> str:
    print(f"Create oidc policy for client one")
    with open(policy_file_path) as f:
        doc = yaml.safe_load(f)
    pol = doc["metadata"]["name"]
    doc["spec"]["oidc"]["tokenEndpoint"] = doc["spec"]["oidc"]["tokenEndpoint"].replace("default", test_namespace)
    doc["spec"]["oidc"]["jwksURI"] = doc["spec"]["oidc"]["jwksURI"].replace("default", test_namespace)
    kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", test_namespace, "policies", doc)
    print(f"Policy created with name {pol}")

    return pol

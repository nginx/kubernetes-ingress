import base64
import secrets
from copy import deepcopy
from pathlib import Path

import pytest
import requests
import yaml
from kubernetes.client.rest import ApiException
from playwright.sync_api import Error, sync_playwright
from settings import DEPLOYMENTS, TEST_DATA
from suite.utils.custom_assertions import assert_vs_status, assert_vsr_status
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret,
    create_secret_from_yaml,
    delete_common_app,
    delete_namespace,
    delete_secret,
    delete_service,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_v_s_route,
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
    backend_secret_name = ""
    backend_ca_secret_name = ""
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


@pytest.mark.oidc
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
    @pytest.mark.parametrize("configmap", [cm_src, cm_zs_src])
    @pytest.mark.parametrize(
        "oidc_yaml, verify_tls",
        [("standard", False), ("standard", True), ("pkce", False), ("pkce", True)],
    )
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
        oidc_yaml,
        verify_tls,
    ):
        run_test(
            kube_apis,
            ingress_controller_endpoint,
            ingress_controller_prerequisites,
            test_namespace,
            virtual_server_setup,
            keycloak_setup,
            configmap,
            oidc_yaml,
            verify_tls,
        )


def run_test(
    kube_apis,
    ingress_controller_endpoint,
    ingress_controller_prerequisites,
    test_namespace,
    virtual_server_setup,
    keycloak_setup,
    configmap,
    oidc_yaml,
    verify_tls,
):
    secret_name = None
    pol = None
    vs_patched = False
    configmap_replaced = False
    headless_name = None

    try:
        print("Create oidc-native secret")
        with open(oidc_native_secret_src) as f:
            secret_data = yaml.safe_load(f)
        secret_data["data"]["client-secret"] = keycloak_setup.secret
        secret_name = create_secret(kube_apis.v1, test_namespace, secret_data)

        policy_file = get_oidc_native_policy_file(oidc_yaml, verify_tls)
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

        with sync_playwright() as playwright:
            run_oidc_native(
                playwright.chromium, ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port_ssl
            )
    finally:
        if headless_name:
            delete_service(kube_apis.v1, headless_name, ingress_controller_prerequisites.namespace)
        if configmap_replaced:
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                orig_cm_src,
            )
        if vs_patched:
            patch_virtual_server_from_yaml(
                kube_apis.custom_objects, virtual_server_setup.vs_name, orig_vs_src, test_namespace
            )
        if pol:
            delete_policy(kube_apis.custom_objects, pol, test_namespace)
        if secret_name:
            delete_secret(kube_apis.v1, secret_name, test_namespace)


def get_oidc_native_policy_file(oidc_yaml, verify_tls):
    policy_src = oidc_native_pol_src if oidc_yaml == "standard" else pkce_pol_src
    return policy_src["https" if verify_tls else "http"]


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


# The example manifests deliberately use a standalone webapp deployment and
# placeholder hostnames. Materialize them against the suite's TLS/backend
# fixture so the examples are exercised by the same controller instance.
oidc_native_scenarios = Path(__file__).resolve().parents[2] / "examples/custom-resources/oidc-native/test-manifests"
oidc_native_discovery_url = (
    "https://keycloak.{namespace}.svc.cluster.local:8443/realms/master/.well-known/openid-configuration"
)


def load_native_scenario(number):
    paths = list(oidc_native_scenarios.glob(f"test-{number}-*.yaml"))
    assert len(paths) == 1, f"Expected one manifest for scenario {number}, found {paths}"
    with paths[0].open() as manifest:
        return list(yaml.safe_load_all(manifest))


def native_policy(secret_name, name="oidcnative-policy"):
    return {
        "apiVersion": "k8s.nginx.org/v1",
        "kind": "Policy",
        "metadata": {"name": name},
        "spec": {
            "oidcNative": {
                "issuer": "https://keycloak.example.com/realms/master",
                "configURL": oidc_native_discovery_url,
                "sslName": "keycloak.example.com",
                "clientID": "nginx-plus",
                "clientSecret": secret_name,
                "scope": "openid profile",
                "sslVerify": False,
                "postLogoutRedirectURI": "/_logout",
            }
        },
    }


def create_native_secret(kube_apis, namespace, encoded_secret, name="oidcnative-secret"):
    return create_secret(
        kube_apis.v1,
        namespace,
        {"metadata": {"name": name}, "type": "nginx.org/oidc", "data": {"client-secret": encoded_secret}},
    )


def configure_scenario_document(document, namespace, suffix):
    document = deepcopy(document)
    metadata = document.setdefault("metadata", {})
    metadata.pop("namespace", None)
    kind = document["kind"]
    if kind == "VirtualServer":
        original_name = metadata["name"]
        metadata["name"] = f"oidc-native-{suffix}-{original_name}"
        document["spec"]["host"] = f"oidc-native-{suffix}-{original_name}.example.com"
        for upstream in document["spec"].get("upstreams", []):
            upstream["service"] = "backend1-svc"
        for route in document["spec"].get("routes", []):
            if "route" in route:
                route_name = route["route"].split("/")[-1]
                route["route"] = f"{namespace}/oidc-native-{suffix}-{route_name}"
    elif kind == "VirtualServerRoute":
        original_name = metadata["name"]
        metadata["name"] = f"oidc-native-{suffix}-{original_name}"
        vs_name = original_name.removesuffix("-vsr")
        document["spec"]["host"] = f"oidc-native-{suffix}-{vs_name}.example.com"
        for upstream in document["spec"].get("upstreams", []):
            upstream["service"] = "backend1-svc"
    elif kind == "Policy":
        native = document["spec"].get("oidcNative")
        if native:
            native["configURL"] = oidc_native_discovery_url.format(namespace=namespace)
            native["sslName"] = "keycloak.example.com"
        oidc = document["spec"].get("oidc")
        if oidc:
            base = f"https://keycloak.{namespace}.svc.cluster.local:8443/realms/master/protocol/openid-connect"
            oidc.update(
                {
                    "authEndpoint": f"{base}/auth",
                    "tokenEndpoint": f"{base}/token",
                    "jwksURI": f"{base}/certs",
                    "endSessionEndpoint": f"{base}/logout",
                }
            )
    return document


def create_scenario_resources(kube_apis, namespace, keycloak_setup, number):
    """Create one example scenario and return resources for status checks and cleanup."""
    suffix = str(number).replace("a", "a").replace("b", "b")
    resources = {"policies": [], "secrets": [], "virtualservers": [], "virtualserverroutes": []}
    secret_name = create_native_secret(kube_apis, namespace, keycloak_setup.secret)
    resources["secrets"].append(secret_name)
    base_policy = native_policy(secret_name)
    base_policy["spec"]["oidcNative"]["configURL"] = oidc_native_discovery_url.format(namespace=namespace)
    kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", namespace, "policies", base_policy)
    resources["policies"].append(base_policy["metadata"]["name"])

    # Scenario 9 reuses the NJS policy defined by scenario 8a.
    if number == 9:
        njs_secret = create_native_secret(kube_apis, namespace, keycloak_setup.secret, "oidc-njs-secret")
        resources["secrets"].append(njs_secret)
        njs_policy = configure_scenario_document(load_native_scenario("8a")[0], namespace, suffix)
        kube_apis.custom_objects.create_namespaced_custom_object(
            "k8s.nginx.org", "v1", namespace, "policies", njs_policy
        )
        resources["policies"].append(njs_policy["metadata"]["name"])

    for document in load_native_scenario(number):
        if document is None or document["kind"] == "Namespace":
            continue
        document = configure_scenario_document(document, namespace, suffix)
        kind = document["kind"]
        plural = {
            "Policy": "policies",
            "VirtualServer": "virtualservers",
            "VirtualServerRoute": "virtualserverroutes",
        }.get(kind)
        if kind == "Secret":
            # Kubernetes validates TLS data; retain the intentionally wrong type,
            # while providing syntactically valid values for the API server.
            if document["metadata"]["name"] == "test18-wrong-type":
                document["data"] = {"tls.crt": "YQ==", "tls.key": "YQ=="}
            name = create_secret(kube_apis.v1, namespace, document)
            resources["secrets"].append(name)
        elif plural:
            if kind == "Policy" and document["spec"].get("oidc"):
                njs_secret = create_native_secret(kube_apis, namespace, keycloak_setup.secret, "oidc-njs-secret")
                resources["secrets"].append(njs_secret)
            kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", namespace, plural, document)
            resources[plural].append(document["metadata"]["name"])
    return resources


def cleanup_scenario_resources(kube_apis, namespace, resources):
    for name in reversed(resources["virtualserverroutes"]):
        try:
            delete_v_s_route(kube_apis.custom_objects, name, namespace)
        except ApiException as error:
            if error.status != 404:
                raise
    for name in reversed(resources["virtualservers"]):
        try:
            delete_virtual_server(kube_apis.custom_objects, name, namespace)
        except ApiException as error:
            if error.status != 404:
                raise
    for name in reversed(resources["policies"]):
        try:
            delete_policy(kube_apis.custom_objects, name, namespace)
        except ApiException as error:
            if error.status != 404:
                raise
    for name in reversed(resources["secrets"]):
        try:
            delete_secret(kube_apis.v1, name, namespace)
        except ApiException as error:
            if error.status != 404:
                raise


def scenario_response(endpoint, host, path="/", https=True):
    scheme = "https" if https else "http"
    port = endpoint.port_ssl if https else endpoint.port
    return requests.get(
        f"{scheme}://{endpoint.public_ip}:{port}{path}", headers={"Host": host}, verify=False, allow_redirects=False
    )


@pytest.mark.oidc
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
class TestOIDCNativeExampleScenarios:
    @pytest.fixture(autouse=True)
    def configure_oidc_resolver(self, kube_apis, ingress_controller_prerequisites):
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_zs_src,
        )
        wait_before_test()
        yield
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            orig_cm_src,
        )

    @pytest.mark.parametrize("number", [1, 2, 3, 4, 5, 6, 7, "8a", 9, 15])
    def test_valid_policy_placement_scenarios(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_setup,
        number,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, number)
        try:
            wait_before_test()
            for name in resources["virtualservers"]:
                assert_vs_status(kube_apis, test_namespace, name, "Valid")
            for name in resources["virtualserverroutes"]:
                assert_vsr_status(kube_apis, test_namespace, name, "Valid")

            # Scenarios 1, 2, 3 and 15 explicitly distinguish protected and open paths.
            if number in (1, 2, 3, 15):
                vs = read_custom_resource(
                    kube_apis.custom_objects, test_namespace, "virtualservers", resources["virtualservers"][0]
                )
                host = vs["spec"]["host"]
                protected = "/" if number in (1, 2) else ("/vsr/protected" if number == 3 else "/api")
                assert scenario_response(ingress_controller_endpoint, host, protected).status_code == 302
                if number != 1:
                    public = "/public" if number in (2, 3) else "/health"
                    assert scenario_response(ingress_controller_endpoint, host, public).status_code == 200
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    def test_scenario_8b_rejects_njs_and_native_in_one_context(
        self, crd_ingress_controller, virtual_server_setup, kube_apis, test_namespace, keycloak_setup
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, "8a")
        try:
            conflict = configure_scenario_document(load_native_scenario("8b")[0], test_namespace, "8b")
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", test_namespace, "virtualservers", conflict
            )
            resources["virtualservers"].append(conflict["metadata"]["name"])
            assert_vs_status(kube_apis, test_namespace, conflict["metadata"]["name"], "Warning")
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    def test_scenario_10_policy_delete_and_recreate(
        self, crd_ingress_controller, virtual_server_setup, kube_apis, test_namespace, keycloak_setup
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 10)
        try:
            vs_name = resources["virtualservers"][0]
            assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            delete_policy(kube_apis.custom_objects, "oidcnative-policy", test_namespace)
            resources["policies"].remove("oidcnative-policy")
            assert_vs_status(kube_apis, test_namespace, vs_name, "Warning")
            policy = native_policy(resources["secrets"][0])
            policy["spec"]["oidcNative"]["configURL"] = oidc_native_discovery_url.format(namespace=test_namespace)
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", test_namespace, "policies", policy
            )
            resources["policies"].append(policy["metadata"]["name"])
            assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    def test_scenario_11_secret_rotation(
        self, crd_ingress_controller, virtual_server_setup, kube_apis, test_namespace, keycloak_setup
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 1)
        try:
            secret_name = resources["secrets"][0]
            rotated_secret = base64.b64encode(b"rotated-client-secret").decode()
            kube_apis.v1.patch_namespaced_secret(
                secret_name, test_namespace, {"data": {"client-secret": rotated_secret}}
            )
            assert_vs_status(kube_apis, test_namespace, resources["virtualservers"][0], "Valid")
            assert (
                kube_apis.v1.read_namespaced_secret(secret_name, test_namespace).data["client-secret"] == rotated_secret
            )
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    def test_scenario_12_policy_update(
        self, crd_ingress_controller, virtual_server_setup, kube_apis, test_namespace, keycloak_setup
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 1)
        try:
            kube_apis.custom_objects.patch_namespaced_custom_object(
                "k8s.nginx.org",
                "v1",
                test_namespace,
                "policies",
                "oidcnative-policy",
                {"spec": {"oidcNative": {"scope": "openid email"}}},
            )
            assert_vs_status(kube_apis, test_namespace, resources["virtualservers"][0], "Valid")
            policy = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", "oidcnative-policy")
            assert policy["spec"]["oidcNative"]["scope"] == "openid email"
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    @pytest.mark.parametrize("number", [17, 18, 19, 20])
    def test_invalid_secret_references_warn(
        self, crd_ingress_controller, virtual_server_setup, kube_apis, test_namespace, keycloak_setup, number
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, number)
        try:
            assert_vs_status(kube_apis, test_namespace, resources["virtualservers"][0], "Warning")
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    def test_scenario_14_without_tls_redirects(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 14)
        try:
            vs_name = resources["virtualservers"][0]
            vs = assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            assert scenario_response(ingress_controller_endpoint, vs["spec"]["host"], https=False).status_code == 302
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    def test_scenario_21_wrong_secret_key_reaches_the_provider(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 21)
        try:
            vs = assert_vs_status(kube_apis, test_namespace, resources["virtualservers"][0], "Valid")
            response = scenario_response(ingress_controller_endpoint, vs["spec"]["host"])
            assert response.status_code == 302
            assert "keycloak" in response.headers["Location"]
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    @pytest.mark.parametrize("number", [13, 22])
    def test_admission_rejects_invalid_policies(
        self, crd_ingress_controller, virtual_server_setup, keycloak_setup, kube_apis, test_namespace, number
    ):
        for policy in load_native_scenario(number):
            with pytest.raises(ApiException) as error:
                kube_apis.custom_objects.create_namespaced_custom_object(
                    "k8s.nginx.org", "v1", test_namespace, "policies", policy
                )
            assert error.value.status == 422
            with pytest.raises(ApiException) as missing:
                kube_apis.custom_objects.get_namespaced_custom_object(
                    "k8s.nginx.org", "v1", test_namespace, "policies", policy["metadata"]["name"]
                )
            assert missing.value.status == 404

    def test_scenario_16_cross_namespace_policy(
        self, crd_ingress_controller, virtual_server_setup, kube_apis, test_namespace, keycloak_setup
    ):
        policy_namespace = f"{test_namespace}-oidc-policies"
        kube_apis.v1.create_namespace({"metadata": {"name": policy_namespace}})
        resources = {"policies": [], "secrets": [], "virtualservers": [], "virtualserverroutes": []}
        try:
            secret = create_native_secret(kube_apis, policy_namespace, keycloak_setup.secret)
            resources["secrets"].append(secret)
            policy = native_policy(secret, "cross-ns-policy")
            policy["spec"]["oidcNative"]["configURL"] = oidc_native_discovery_url.format(namespace=test_namespace)
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", policy_namespace, "policies", policy
            )
            resources["policies"].append(policy["metadata"]["name"])
            vs = configure_scenario_document(load_native_scenario(16)[3], test_namespace, "16")
            vs["spec"]["policies"][0]["namespace"] = policy_namespace
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", test_namespace, "virtualservers", vs
            )
            resources["virtualservers"].append(vs["metadata"]["name"])
            assert_vs_status(kube_apis, test_namespace, vs["metadata"]["name"], "Valid")
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)
            delete_namespace(kube_apis.v1, policy_namespace)

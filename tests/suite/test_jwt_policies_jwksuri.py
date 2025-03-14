import secrets
from unittest import mock

import pytest
import requests
import yaml
from settings import TEST_DATA
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_secret_from_yaml,
    delete_common_app,
    delete_secret,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_and_create_vs_from_yaml,
    delete_virtual_server,
)

username = "nginx-user-" + secrets.token_hex(4)
password = secrets.token_hex(8)
realm_name = "jwks-example"
std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
jwt_pol_valid_src = f"{TEST_DATA}/jwt-policy-jwksuri/policies/jwt-policy-valid.yaml"
jwt_pol_invalid_src = f"{TEST_DATA}/jwt-policy-jwksuri/policies/jwt-policy-invalid.yaml"
jwt_vs_spec_src = f"{TEST_DATA}/jwt-policy-jwksuri/virtual-server/virtual-server-policy-spec.yaml"
jwt_vs_route_src = f"{TEST_DATA}/jwt-policy-jwksuri/virtual-server/virtual-server-policy-route.yaml"
jwt_spec_and_route_src = f"{TEST_DATA}/jwt-policy-jwksuri/virtual-server/virtual-server-policy-spec-and-route.yaml"
jwt_vs_route_subpath_src = f"{TEST_DATA}/jwt-policy-jwksuri/virtual-server/virtual-server-policy-route-subpath.yaml"
jwt_vs_route_subpath_diff_host_src = (
    f"{TEST_DATA}/jwt-policy-jwksuri/virtual-server/virtual-server-policy-route-subpath-diff-host.yaml"
)
jwt_vs_invalid_pol_spec_src = f"{TEST_DATA}/jwt-policy-jwksuri/virtual-server/virtual-server-invalid-policy-spec.yaml"
jwt_vs_invalid_pol_route_src = f"{TEST_DATA}/jwt-policy-jwksuri/virtual-server/virtual-server-invalid-policy-route.yaml"
jwt_vs_invalid_pol_route_subpath_src = (
    f"{TEST_DATA}/jwt-policy-jwksuri/virtual-server/virtual-server-invalid-policy-route-subpath.yaml"
)
jwt_cm_src = f"{TEST_DATA}/jwt-policy-jwksuri/configmap/nginx-config.yaml"
keycloak_src = f"{TEST_DATA}/oidc/keycloak.yaml"
keycloak_vs_src = f"{TEST_DATA}/oidc/virtual-server-idp.yaml"


class KeycloakSetup:
    """
    Attributes:
        token (str):
    """

    def __init__(self, token):
        self.token = token


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
    admin_token = response.json()["access_token"]

    # Create realm "jwks-example"
    create_realm_url = (
        f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/admin/realms"
    )
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {admin_token}", "Host": keycloak_address}
    payload = {
        "realm": realm_name,
        "enabled": True,
    }
    response = requests.post(create_realm_url, headers=headers, json=payload, verify=False)

    # Create a user and set credentials
    create_user_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/admin/realms/{realm_name}/users"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {admin_token}", "Host": keycloak_address}
    user_payload = {
        "username": username,
        "enabled": True,
        "email": "jwks.user@example.com",
        "emailVerified": True,
        "firstName": "Jwks",
        "lastName": "User",
        "credentials": [{"type": "password", "value": password, "temporary": False}],
        "requiredActions": [],
    }
    response = requests.post(create_user_url, headers=headers, json=user_payload, verify=False)

    # Create a client
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {admin_token}", "Host": keycloak_address}
    create_client_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/admin/realms/{realm_name}/clients"
    client_payload = {
        "clientId": "jwks-client",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "serviceAccountsEnabled": True,
        "authorizationServicesEnabled": True,
        "clientAuthenticatorType": "client-secret",
        "redirectUris": ["*"],
        "webOrigins": ["*"],
        "attributes": {
            "access.token.lifespan": "3600",
            "id.token.lifespan": "3600",
            "service.accounts.enabled": "true",
        },
    }
    client_resp = requests.post(create_client_url, headers=headers, json=client_payload, verify=False)
    if client_resp.status_code not in (200, 201):
        pytest.fail(f"Failed to create client: {client_resp.text}")
    location = client_resp.headers["Location"]
    client_id = location.split("/")[-1]

    # Get the client secret
    get_secret_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/admin/realms/{realm_name}/clients/{client_id}/client-secret"
    secret_resp = requests.get(get_secret_url, headers=headers, verify=False)
    secret = secret_resp.json()["value"]

    data = {
        "grant_type": "password",
        "scope": "openid",
        "client_id": "jwks-client",
        "client_secret": secret,
        "username": username,
        "password": password,
    }
    url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/realms/{realm_name}/protocol/openid-connect/token"
    response = requests.post(
        url,
        headers={"Host": keycloak_address, "Content-Type": "application/x-www-form-urlencoded"},
        data=data,
        verify=False,
    )

    if response.status_code != 200:
        pytest.fail(f"Failed to get token from Keycloak: {response.text}")

    token = response.json().get("access_token")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete Keycloak resources")
            delete_virtual_server(kube_apis.custom_objects, keycloak_vs_name, test_namespace)
            delete_common_app(kube_apis, "keycloak", test_namespace)
            delete_secret(kube_apis.v1, secret_name, test_namespace)

    request.addfinalizer(fin)

    return KeycloakSetup(token)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.policies
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
class TestJWTPoliciesVsJwksuri:
    @pytest.mark.parametrize("jwt_virtual_server", [jwt_vs_spec_src, jwt_vs_route_src, jwt_spec_and_route_src])
    def test_jwt_policy_jwksuri(
        self,
        request,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        keycloak_setup,
        jwt_virtual_server,
    ):
        """
        Test jwt-policy in Virtual Server (spec, route and both at the same time) with keys fetched form Azure
        """
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            jwt_cm_src,
        )
        with open(jwt_pol_valid_src) as f:
            doc = yaml.safe_load(f)
        pol_name = doc["metadata"]["name"]
        doc["spec"]["jwt"]["jwksURI"] = doc["spec"]["jwt"]["jwksURI"].replace("default", test_namespace)
        kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", test_namespace, "policies", doc)
        print(f"Policy created with name {pol_name}")
        wait_before_test()

        print(f"Patch vs with policy: {jwt_virtual_server}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_virtual_server,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp_no_token = mock.Mock()
        resp_no_token.status_code == 502
        counter = 0

        while resp_no_token.status_code != 401 and counter < 20:
            resp_no_token = requests.get(
                virtual_server_setup.backend_1_url,
                headers={"host": virtual_server_setup.vs_host},
            )
            wait_before_test()
            counter += 1

        token = keycloak_setup.token

        resp_valid_token = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "token": token},
            timeout=5,
        )
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        wait_before_test()

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp_no_token.status_code == 401 and f"Authorization Required" in resp_no_token.text
        assert resp_valid_token.status_code == 200 and f"Request ID:" in resp_valid_token.text

    @pytest.mark.parametrize("jwt_virtual_server", [jwt_vs_invalid_pol_spec_src, jwt_vs_invalid_pol_route_src])
    def test_jwt_invalid_policy_jwksuri(
        self,
        request,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        keycloak_setup,
        jwt_virtual_server,
    ):
        """
        Test invalid jwt-policy in Virtual Server (spec and route) with keys fetched form Azure
        """
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            jwt_cm_src,
        )
        with open(jwt_pol_invalid_src) as f:
            doc = yaml.safe_load(f)
        pol_name = doc["metadata"]["name"]
        doc["spec"]["jwt"]["jwksURI"] = doc["spec"]["jwt"]["jwksURI"].replace("default", test_namespace)
        kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", test_namespace, "policies", doc)
        print(f"Policy created with name {pol_name}")
        wait_before_test()

        print(f"Patch vs with policy: {jwt_virtual_server}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_virtual_server,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        resp1 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
        )

        token = keycloak_setup.token

        resp2 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host, "token": token},
            timeout=5,
        )

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp1.status_code == 500 and f"Internal Server Error" in resp1.text
        assert resp2.status_code == 500 and f"Internal Server Error" in resp2.text

    @pytest.mark.parametrize("jwt_virtual_server", [jwt_vs_route_subpath_src])
    def test_jwt_policy_subroute_jwksuri(
        self,
        request,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        keycloak_setup,
        jwt_virtual_server,
    ):
        """
        Test jwt-policy in Virtual Server using subpaths with keys fetched form Azure
        """
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            jwt_cm_src,
        )
        with open(jwt_pol_valid_src) as f:
            doc = yaml.safe_load(f)
        pol_name = doc["metadata"]["name"]
        doc["spec"]["jwt"]["jwksURI"] = doc["spec"]["jwt"]["jwksURI"].replace("default", test_namespace)
        kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", test_namespace, "policies", doc)
        print(f"Policy created with name {pol_name}")
        wait_before_test()

        print(f"Patch vs with policy: {jwt_virtual_server}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_virtual_server,
            virtual_server_setup.namespace,
        )
        resp_no_token = mock.Mock()
        resp_no_token.status_code == 502
        counter = 0

        while resp_no_token.status_code != 401 and counter < 20:
            resp_no_token = requests.get(
                virtual_server_setup.backend_1_url + "/subpath1",
                headers={"host": virtual_server_setup.vs_host},
            )
            wait_before_test()
            counter += 1

        token = keycloak_setup.token

        resp_valid_token = requests.get(
            virtual_server_setup.backend_1_url + "/subpath1",
            headers={"host": virtual_server_setup.vs_host, "token": token},
            timeout=5,
        )

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        wait_before_test()

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert resp_no_token.status_code == 401 and f"Authorization Required" in resp_no_token.text
        assert resp_valid_token.status_code == 200 and f"Request ID:" in resp_valid_token.text

    def test_jwt_policy_subroute_jwksuri_multiple_vs(
        self,
        request,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        keycloak_setup,
        test_namespace,
    ):
        """
        Test jwt-policy applied to two Virtual Servers with different hosts and the same subpaths
        """
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            jwt_cm_src,
        )
        with open(jwt_pol_valid_src) as f:
            doc = yaml.safe_load(f)
        pol_name = doc["metadata"]["name"]
        doc["spec"]["jwt"]["jwksURI"] = doc["spec"]["jwt"]["jwksURI"].replace("default", test_namespace)
        kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", test_namespace, "policies", doc)
        print(f"Policy created with name {pol_name}")
        wait_before_test()

        print(f"Patch first vs with policy: {jwt_vs_route_subpath_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            jwt_vs_route_subpath_src,
            virtual_server_setup.namespace,
        )

        print(f"Create second vs with policy: {jwt_vs_route_subpath_diff_host_src}")
        create_virtual_server_from_yaml(
            kube_apis.custom_objects,
            jwt_vs_route_subpath_diff_host_src,
            virtual_server_setup.namespace,
        )

        wait_before_test()

        resp_1_no_token = mock.Mock()
        resp_1_no_token.status_code == 502

        resp_2_no_token = mock.Mock()
        resp_2_no_token.status_code == 502
        counter = 0

        while resp_1_no_token.status_code != 401 and counter < 20:
            resp_1_no_token = requests.get(
                virtual_server_setup.backend_1_url + "/subpath1",
                headers={"host": virtual_server_setup.vs_host},
            )
            wait_before_test()
            counter += 1

        counter = 0

        while resp_2_no_token.status_code != 401 and counter < 20:
            resp_2_no_token = requests.get(
                virtual_server_setup.backend_1_url + "/subpath1",
                headers={"host": "virtual-server-2.example.com"},
            )
            wait_before_test()
            counter += 1

        token = keycloak_setup.token

        resp_1_valid_token = requests.get(
            virtual_server_setup.backend_1_url + "/subpath1",
            headers={"host": virtual_server_setup.vs_host, "token": token},
            timeout=5,
        )

        resp_2_valid_token = requests.get(
            virtual_server_setup.backend_1_url + "/subpath1",
            headers={"host": "virtual-server-2.example.com", "token": token},
            timeout=5,
        )

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        wait_before_test()

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        delete_virtual_server(
            kube_apis.custom_objects,
            "virtual-server-2",
            virtual_server_setup.namespace,
        )

        assert resp_1_no_token.status_code == 401 and f"Authorization Required" in resp_1_no_token.text
        assert resp_1_valid_token.status_code == 200 and f"Request ID:" in resp_1_valid_token.text

        assert resp_2_no_token.status_code == 401 and f"Authorization Required" in resp_2_no_token.text
        assert resp_2_valid_token.status_code == 200 and f"Request ID:" in resp_2_valid_token.text

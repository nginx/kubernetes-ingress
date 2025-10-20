import pytest
import requests
from settings import TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_secret,
    ensure_connection_to_public_endpoint,
    is_secret_present,
    replace_secret,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml


class JWTAuthMergeableSetup:
    """
    Encapsulate JWT Auth Mergeable Minions Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        ingress_host (str): a hostname from Ingress resource
        master_secret_name (str):
        minion_secret_name (str):
        tokens ([]): a list of tokens for testing
    """

    def __init__(self, public_endpoint: PublicEndpoint, ingress_host, master_secret_name, minion_secret_name, tokens):
        self.public_endpoint = public_endpoint
        self.ingress_host = ingress_host
        self.master_secret_name = master_secret_name
        self.minion_secret_name = minion_secret_name
        self.tokens = tokens


@pytest.fixture(scope="class")
def jwt_auth_setup(
    request, kube_apis, ingress_controller_endpoint, ingress_controller, test_namespace
) -> JWTAuthMergeableSetup:
    tokens = {"master": get_token_from_file("master"), "minion": get_token_from_file("minion")}
    master_secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/jwt-auth-mergeable/jwt-master-secret.yaml"
    )
    minion_secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/jwt-auth-mergeable/jwt-minion-secret.yaml"
    )
    print("------------------------- Deploy JWT Auth Mergeable Minions Example -----------------------------------")
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/jwt-auth-mergeable/mergeable/jwt-auth-ingress.yaml", test_namespace)
    ingress_host = get_first_ingress_host_from_yaml(f"{TEST_DATA}/jwt-auth-mergeable/mergeable/jwt-auth-ingress.yaml")
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port, ingress_controller_endpoint.port_ssl
    )
    wait_before_test(2)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete Master Secret:")
            if is_secret_present(kube_apis.v1, master_secret_name, test_namespace):
                delete_secret(kube_apis.v1, master_secret_name, test_namespace)

            print("Delete Minion Secret:")
            if is_secret_present(kube_apis.v1, minion_secret_name, test_namespace):
                delete_secret(kube_apis.v1, minion_secret_name, test_namespace)

            print("Clean up the JWT Auth Mergeable Minions Application:")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(
                kube_apis, f"{TEST_DATA}/jwt-auth-mergeable/mergeable/jwt-auth-ingress.yaml", test_namespace
            )

    request.addfinalizer(fin)

    return JWTAuthMergeableSetup(
        ingress_controller_endpoint, ingress_host, master_secret_name, minion_secret_name, tokens
    )


def get_token_from_file(token_type) -> str:
    """
    Get token from the file.

    :param token_type: 'master' or 'minion'
    :return: str
    """
    with open(f"{TEST_DATA}/jwt-auth-mergeable/tokens/jwt-auth-{token_type}-token.jwt") as token_file:
        return token_file.read().replace("\n", "")


step_1_expected_results = [
    {"token_type": "master", "path": "", "response_code": 404},
    {
        "token_type": "master",
        "path": "backend1",
        "response_code": 302,
        "location": "https://login-backend1.jwt-auth-mergeable.example.com",
    },
    {"token_type": "master", "path": "backend2", "response_code": 200},
    {
        "token_type": "minion",
        "path": "",
        "response_code": 302,
        "location": "https://login.jwt-auth-mergeable.example.com",
    },
    {"token_type": "minion", "path": "backend1", "response_code": 200},
    {
        "token_type": "minion",
        "path": "backend2",
        "response_code": 302,
        "location": "https://login.jwt-auth-mergeable.example.com",
    },
]

step_2_expected_results = [
    {
        "token_type": "master",
        "path": "",
        "response_code": 302,
        "location": "https://login.jwt-auth-mergeable.example.com",
    },
    {
        "token_type": "master",
        "path": "backend1",
        "response_code": 302,
        "location": "https://login-backend1.jwt-auth-mergeable.example.com",
    },
    {
        "token_type": "master",
        "path": "backend2",
        "response_code": 302,
        "location": "https://login.jwt-auth-mergeable.example.com",
    },
    {"token_type": "minion", "path": "", "response_code": 404},
    {"token_type": "minion", "path": "backend1", "response_code": 200},
    {"token_type": "minion", "path": "backend2", "response_code": 200},
]

step_3_expected_results = [
    {
        "token_type": "master",
        "path": "",
        "response_code": 302,
        "location": "https://login.jwt-auth-mergeable.example.com",
    },
    {"token_type": "master", "path": "backend1", "response_code": 200},
    {
        "token_type": "master",
        "path": "backend2",
        "response_code": 302,
        "location": "https://login.jwt-auth-mergeable.example.com",
    },
    {"token_type": "minion", "path": "", "response_code": 404},
    {
        "token_type": "minion",
        "path": "backend1",
        "response_code": 302,
        "location": "https://login-backend1.jwt-auth-mergeable.example.com",
    },
    {"token_type": "minion", "path": "backend2", "response_code": 200},
]

step_4_expected_results = [
    {
        "token_type": "master",
        "path": "",
        "response_code": 302,
        "location": "https://login.jwt-auth-mergeable.example.com",
    },
    {"token_type": "master", "path": "backend1", "response_code": 500},
    {
        "token_type": "master",
        "path": "backend2",
        "response_code": 302,
        "location": "https://login.jwt-auth-mergeable.example.com",
    },
    {"token_type": "minion", "path": "", "response_code": 404},
    {"token_type": "minion", "path": "backend1", "response_code": 500},
    {"token_type": "minion", "path": "backend2", "response_code": 200},
]

step_5_expected_results = [
    {"token_type": "master", "path": "", "response_code": 500},
    {"token_type": "master", "path": "backend1", "response_code": 500},
    {"token_type": "master", "path": "backend2", "response_code": 500},
    {"token_type": "minion", "path": "", "response_code": 500},
    {"token_type": "minion", "path": "backend1", "response_code": 500},
    {"token_type": "minion", "path": "backend2", "response_code": 500},
]


@pytest.mark.ingresses
@pytest.mark.ingresses_jwt
@pytest.mark.skip_for_nginx_oss
class TestJWTAuthMergeableMinions:
    def test_jwt_auth_response_codes_and_location(self, kube_apis, jwt_auth_setup, test_namespace):
        print("Step 1: execute check after secrets creation")
        execute_checks(jwt_auth_setup, step_1_expected_results)

        print("Step 2: replace master secret")
        replace_secret(
            kube_apis.v1,
            jwt_auth_setup.master_secret_name,
            test_namespace,
            f"{TEST_DATA}/jwt-auth-mergeable/jwt-master-secret-updated.yaml",
        )
        wait_before_test(1)
        execute_checks(jwt_auth_setup, step_2_expected_results)

        print("Step 3: now replace minion secret as well")
        replace_secret(
            kube_apis.v1,
            jwt_auth_setup.minion_secret_name,
            test_namespace,
            f"{TEST_DATA}/jwt-auth-mergeable/jwt-minion-secret-updated.yaml",
        )
        wait_before_test(1)
        execute_checks(jwt_auth_setup, step_3_expected_results)

        print("Step 4: now remove minion secret")
        delete_secret(kube_apis.v1, jwt_auth_setup.minion_secret_name, test_namespace)
        wait_before_test(1)
        execute_checks(jwt_auth_setup, step_4_expected_results)

        print("Step 5: finally remove master secret as well")
        delete_secret(kube_apis.v1, jwt_auth_setup.master_secret_name, test_namespace)
        wait_before_test(1)
        execute_checks(jwt_auth_setup, step_5_expected_results)


def execute_checks(jwt_auth_setup, expected_results) -> None:
    """
    Assert response code and location.

    :param jwt_auth_setup: JWTAuthMergeableSetup
    :param expected_results: an array of expected results
    :return:
    """
    for expected in expected_results:
        req_url = f"http://{jwt_auth_setup.public_endpoint.public_ip}:{jwt_auth_setup.public_endpoint.port}/{expected['path']}"
        resp = requests.get(
            req_url,
            headers={"host": jwt_auth_setup.ingress_host},
            cookies={"auth_token": jwt_auth_setup.tokens[expected["token_type"]]},
            allow_redirects=False,
        )
        assert resp.status_code == expected["response_code"]
        if expected.get("location", None):
            assert resp.headers["Location"] == expected["location"]

from base64 import b64encode

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
    generate_e2e_run_id,
    get_e2e_run_selector,
    is_secret_present,
    replace_secret,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml


def to_base64(b64_string):
    return b64encode(b64_string.encode("ascii")).decode("ascii")


class AuthBasicAuthMergeableSetup:
    """
    Encapsulate Auth Basic Auth Mergeable Minions Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        ingress_host (str): a hostname from Ingress resource
        master_secret_name (str):
        minion_secret_name (str):
        credentials_dict ([]): a dictionary of credentials for testing
    """

    def __init__(
        self, public_endpoint: PublicEndpoint, ingress_host, master_secret_name, minion_secret_name, credentials_dict
    ):
        self.public_endpoint = public_endpoint
        self.ingress_host = ingress_host
        self.master_secret_name = master_secret_name
        self.minion_secret_name = minion_secret_name
        self.credentials_dict = credentials_dict


@pytest.fixture(scope="class")
def auth_basic_auth_setup(
    request, kube_apis, ingress_controller_endpoint, ingress_controller, test_namespace
) -> AuthBasicAuthMergeableSetup:
    credentials_dict = {"master": get_credentials_from_file("master"), "minion": get_credentials_from_file("minion")}
    master_secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/auth-basic-auth-mergeable/auth-basic-master-secret.yaml"
    )
    minion_secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/auth-basic-auth-mergeable/auth-basic-minion-secret.yaml"
    )
    print(
        "------------------------- Deploy Auth Basic Auth Mergeable Minions Example -----------------------------------"
    )
    e2e_run_id = generate_e2e_run_id()
    create_items_from_yaml(
        kube_apis, f"{TEST_DATA}/auth-basic-auth-mergeable/mergeable/auth-basic-auth-ingress.yaml", test_namespace
    )
    ingress_host = get_first_ingress_host_from_yaml(
        f"{TEST_DATA}/auth-basic-auth-mergeable/mergeable/auth-basic-auth-ingress.yaml"
    )
    create_example_app(kube_apis, "simple", test_namespace, e2e_run_id=e2e_run_id)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace, get_e2e_run_selector(e2e_run_id))
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

            print("Clean up the Auth Basic Auth Mergeable Minions Application:")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(
                kube_apis,
                f"{TEST_DATA}/auth-basic-auth-mergeable/mergeable/auth-basic-auth-ingress.yaml",
                test_namespace,
            )

    request.addfinalizer(fin)

    return AuthBasicAuthMergeableSetup(
        ingress_controller_endpoint, ingress_host, master_secret_name, minion_secret_name, credentials_dict
    )


def get_credentials_from_file(creds_type) -> str:
    """
    Get credentials from the file.

    :param creds_type: 'master' or 'minion'
    :return: str
    """
    with open(
        f"{TEST_DATA}/auth-basic-auth-mergeable/credentials/auth-basic-auth-{creds_type}-credentials.txt"
    ) as credentials_file:
        return credentials_file.read().replace("\n", "")


step_1_expected_results = [
    {"creds_type": "master", "path": "", "response_code": 404},
    {"creds_type": "master", "path": "backend1", "response_code": 401},
    {"creds_type": "master", "path": "backend2", "response_code": 200},
    {"creds_type": "minion", "path": "", "response_code": 401},
    {"creds_type": "minion", "path": "backend1", "response_code": 200},
    {"creds_type": "minion", "path": "backend2", "response_code": 401},
]

step_2_expected_results = [
    {"creds_type": "master", "path": "", "response_code": 401},
    {"creds_type": "master", "path": "backend1", "response_code": 401},
    {"creds_type": "master", "path": "backend2", "response_code": 401},
    {"creds_type": "minion", "path": "", "response_code": 404},
    {"creds_type": "minion", "path": "backend1", "response_code": 200},
    {"creds_type": "minion", "path": "backend2", "response_code": 200},
]

step_3_expected_results = [
    {"creds_type": "master", "path": "", "response_code": 401},
    {"creds_type": "master", "path": "backend1", "response_code": 200},
    {"creds_type": "master", "path": "backend2", "response_code": 401},
    {"creds_type": "minion", "path": "", "response_code": 404},
    {"creds_type": "minion", "path": "backend1", "response_code": 401},
    {"creds_type": "minion", "path": "backend2", "response_code": 200},
]

step_4_expected_results = [
    {"creds_type": "master", "path": "", "response_code": 401},
    {"creds_type": "master", "path": "backend1", "response_code": 403},
    {"creds_type": "master", "path": "backend2", "response_code": 401},
    {"creds_type": "minion", "path": "", "response_code": 404},
    {"creds_type": "minion", "path": "backend1", "response_code": 403},
    {"creds_type": "minion", "path": "backend2", "response_code": 200},
]

step_5_expected_results = [
    {"creds_type": "master", "path": "", "response_code": 403},
    {"creds_type": "master", "path": "backend1", "response_code": 403},
    {"creds_type": "master", "path": "backend2", "response_code": 403},
    {"creds_type": "minion", "path": "", "response_code": 403},
    {"creds_type": "minion", "path": "backend1", "response_code": 403},
    {"creds_type": "minion", "path": "backend2", "response_code": 403},
]


@pytest.mark.ingresses
@pytest.mark.basic_auth
class TestAuthBasicAuthMergeableMinions:
    def test_auth_basic_auth_response_codes(self, kube_apis, auth_basic_auth_setup, test_namespace):
        print("Step 1: execute check after secrets creation")
        execute_checks(auth_basic_auth_setup, step_1_expected_results)

        print("Step 2: replace master secret")
        replace_secret(
            kube_apis.v1,
            auth_basic_auth_setup.master_secret_name,
            test_namespace,
            f"{TEST_DATA}/auth-basic-auth-mergeable/auth-basic-master-secret-updated.yaml",
        )
        wait_before_test(1)
        execute_checks(auth_basic_auth_setup, step_2_expected_results)

        print("Step 3: now replace minion secret as well")
        replace_secret(
            kube_apis.v1,
            auth_basic_auth_setup.minion_secret_name,
            test_namespace,
            f"{TEST_DATA}/auth-basic-auth-mergeable/auth-basic-minion-secret-updated.yaml",
        )
        wait_before_test(1)
        execute_checks(auth_basic_auth_setup, step_3_expected_results)

        print("Step 4: now remove minion secret")
        delete_secret(kube_apis.v1, auth_basic_auth_setup.minion_secret_name, test_namespace)
        wait_before_test(1)
        execute_checks(auth_basic_auth_setup, step_4_expected_results)

        print("Step 5: finally remove master secret as well")
        delete_secret(kube_apis.v1, auth_basic_auth_setup.master_secret_name, test_namespace)
        wait_before_test(1)
        execute_checks(auth_basic_auth_setup, step_5_expected_results)


def execute_checks(auth_basic_auth_setup, expected_results) -> None:
    """
    Assert response code.

    :param auth_basic_auth_setup: AuthBasicAuthMergeableSetup
    :param expected_results: an array of expected results
    :return:
    """
    for expected in expected_results:
        req_url = f"http://{auth_basic_auth_setup.public_endpoint.public_ip}:{auth_basic_auth_setup.public_endpoint.port}/{expected['path']}"
        resp = requests.get(
            req_url,
            headers={
                "host": auth_basic_auth_setup.ingress_host,
                "authorization": f"Basic {to_base64(auth_basic_auth_setup.credentials_dict[expected['creds_type']])}",
            },
            allow_redirects=False,
        )
        assert resp.status_code == expected["response_code"]

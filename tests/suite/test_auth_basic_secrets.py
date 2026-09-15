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


class AuthBasicSecretsSetup:
    """
    Encapsulate Auth Basic Secrets Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        ingress_host (str):
        credentials (str):
    """

    def __init__(self, public_endpoint: PublicEndpoint, ingress_host, credentials):
        self.public_endpoint = public_endpoint
        self.ingress_host = ingress_host
        self.credentials = credentials


class AuthBasicSecret:
    """
    Encapsulate secret name for Auth Basic Secrets Example.

    Attributes:
        secret_name (str):
    """

    def __init__(self, secret_name):
        self.secret_name = secret_name


@pytest.fixture(scope="class", params=["standard", "mergeable"])
def auth_basic_secrets_setup(
    request, kube_apis, ingress_controller_endpoint, ingress_controller, test_namespace
) -> AuthBasicSecretsSetup:
    with open(f"{TEST_DATA}/auth-basic-secrets/credentials/credentials.txt") as credentials_file:
        credentials = credentials_file.read().replace("\n", "")
    print("------------------------- Deploy Auth Basic Secrets Example -----------------------------------")
    e2e_run_id = generate_e2e_run_id()
    create_items_from_yaml(
        kube_apis, f"{TEST_DATA}/auth-basic-secrets/{request.param}/auth-basic-secrets-ingress.yaml", test_namespace
    )
    ingress_host = get_first_ingress_host_from_yaml(
        f"{TEST_DATA}/auth-basic-secrets/{request.param}/auth-basic-secrets-ingress.yaml"
    )
    create_example_app(kube_apis, "simple", test_namespace, e2e_run_id=e2e_run_id)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace, get_e2e_run_selector(e2e_run_id))
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port, ingress_controller_endpoint.port_ssl
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up the Auth Basic Secrets Application:")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(
                kube_apis,
                f"{TEST_DATA}/auth-basic-secrets/{request.param}/auth-basic-secrets-ingress.yaml",
                test_namespace,
            )

    request.addfinalizer(fin)

    return AuthBasicSecretsSetup(ingress_controller_endpoint, ingress_host, credentials)


@pytest.fixture
def auth_basic_secret(
    request, kube_apis, ingress_controller_endpoint, auth_basic_secrets_setup, test_namespace
) -> AuthBasicSecret:
    secret_name = create_secret_from_yaml(
        kube_apis.v1, test_namespace, f"{TEST_DATA}/auth-basic-secrets/auth-basic-secret.yaml"
    )
    wait_before_test(1)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete Secret:")
            if is_secret_present(kube_apis.v1, secret_name, test_namespace):
                delete_secret(kube_apis.v1, secret_name, test_namespace)

    request.addfinalizer(fin)

    return AuthBasicSecret(secret_name)


@pytest.mark.ingresses
@pytest.mark.basic_auth
class TestAuthBasicSecrets:
    def test_response_code_200_and_server_name(self, auth_basic_secrets_setup, auth_basic_secret):
        req_url = f"http://{auth_basic_secrets_setup.public_endpoint.public_ip}:{auth_basic_secrets_setup.public_endpoint.port}/backend2"
        resp = requests.get(
            req_url,
            headers={
                "host": auth_basic_secrets_setup.ingress_host,
                "authorization": f"Basic {to_base64(auth_basic_secrets_setup.credentials)}",
            },
        )
        assert resp.status_code == 200
        assert f"Server name: backend2" in resp.text

    def test_response_codes_after_secret_remove_and_restore(
        self, kube_apis, auth_basic_secrets_setup, test_namespace, auth_basic_secret
    ):
        req_url = f"http://{auth_basic_secrets_setup.public_endpoint.public_ip}:{auth_basic_secrets_setup.public_endpoint.port}/backend2"
        delete_secret(kube_apis.v1, auth_basic_secret.secret_name, test_namespace)
        wait_before_test(1)
        resp = requests.get(
            req_url,
            headers={
                "host": auth_basic_secrets_setup.ingress_host,
                "authorization": f"Basic {to_base64(auth_basic_secrets_setup.credentials)}",
            },
        )
        assert resp.status_code == 403

        auth_basic_secret.secret_name = create_secret_from_yaml(
            kube_apis.v1, test_namespace, f"{TEST_DATA}/auth-basic-secrets/auth-basic-secret.yaml"
        )
        wait_before_test(1)
        resp = requests.get(
            req_url,
            headers={
                "host": auth_basic_secrets_setup.ingress_host,
                "authorization": f"Basic {to_base64(auth_basic_secrets_setup.credentials)}",
            },
        )
        assert resp.status_code == 200

    def test_response_code_403_with_invalid_secret(
        self, kube_apis, auth_basic_secrets_setup, test_namespace, auth_basic_secret
    ):
        req_url = f"http://{auth_basic_secrets_setup.public_endpoint.public_ip}:{auth_basic_secrets_setup.public_endpoint.port}/backend2"
        replace_secret(
            kube_apis.v1,
            auth_basic_secret.secret_name,
            test_namespace,
            f"{TEST_DATA}/auth-basic-secrets/auth-basic-secret-invalid.yaml",
        )
        wait_before_test(1)
        resp = requests.get(
            req_url,
            headers={
                "host": auth_basic_secrets_setup.ingress_host,
                "authorization": f"Basic {to_base64(auth_basic_secrets_setup.credentials)}",
            },
        )
        assert resp.status_code == 403

    def test_response_code_401_with_updated_secret(
        self, kube_apis, auth_basic_secrets_setup, test_namespace, auth_basic_secret
    ):
        req_url = f"http://{auth_basic_secrets_setup.public_endpoint.public_ip}:{auth_basic_secrets_setup.public_endpoint.port}/backend2"
        replace_secret(
            kube_apis.v1,
            auth_basic_secret.secret_name,
            test_namespace,
            f"{TEST_DATA}/auth-basic-secrets/auth-basic-secret-updated.yaml",
        )
        wait_before_test(1)
        resp = requests.get(
            req_url,
            headers={
                "host": auth_basic_secrets_setup.ingress_host,
                "authorization": f"Basic {to_base64(auth_basic_secrets_setup.credentials)}",
            },
            allow_redirects=False,
        )
        assert resp.status_code == 401

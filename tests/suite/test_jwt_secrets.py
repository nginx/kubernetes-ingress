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


class JWTSecretsSetup:
    """
    Encapsulate JWT Secrets Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        ingress_host (str):
        jwt_token (str):
    """

    def __init__(self, public_endpoint: PublicEndpoint, ingress_host, jwt_token):
        self.public_endpoint = public_endpoint
        self.ingress_host = ingress_host
        self.jwt_token = jwt_token


class JWTSecret:
    """
    Encapsulate secret name for JWT Secrets Example.

    Attributes:
        secret_name (str):
    """

    def __init__(self, secret_name):
        self.secret_name = secret_name


@pytest.fixture(scope="class", params=["standard", "mergeable"])
def jwt_secrets_setup(
    request, kube_apis, ingress_controller_endpoint, ingress_controller, test_namespace
) -> JWTSecretsSetup:
    with open(f"{TEST_DATA}/jwt-secrets/tokens/jwt-secrets-token.jwt") as token_file:
        token = token_file.read().replace("\n", "")
    print("------------------------- Deploy JWT Secrets Example -----------------------------------")
    create_items_from_yaml(
        kube_apis, f"{TEST_DATA}/jwt-secrets/{request.param}/jwt-secrets-ingress.yaml", test_namespace
    )
    ingress_host = get_first_ingress_host_from_yaml(f"{TEST_DATA}/jwt-secrets/{request.param}/jwt-secrets-ingress.yaml")
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port, ingress_controller_endpoint.port_ssl
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up the JWT Secrets Application:")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(
                kube_apis, f"{TEST_DATA}/jwt-secrets/{request.param}/jwt-secrets-ingress.yaml", test_namespace
            )

    request.addfinalizer(fin)

    return JWTSecretsSetup(ingress_controller_endpoint, ingress_host, token)


@pytest.fixture
def jwt_secret(request, kube_apis, ingress_controller_endpoint, jwt_secrets_setup, test_namespace) -> JWTSecret:
    secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, f"{TEST_DATA}/jwt-secrets/jwt-secret.yaml")
    wait_before_test(1)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Delete Secret:")
            if is_secret_present(kube_apis.v1, secret_name, test_namespace):
                delete_secret(kube_apis.v1, secret_name, test_namespace)

    request.addfinalizer(fin)

    return JWTSecret(secret_name)


@pytest.mark.ingresses
@pytest.mark.ingresses_jwt
@pytest.mark.skip_for_nginx_oss
class TestJWTSecrets:
    def test_response_code_200_and_server_name(self, jwt_secrets_setup, jwt_secret):
        req_url = (
            f"http://{jwt_secrets_setup.public_endpoint.public_ip}:{jwt_secrets_setup.public_endpoint.port}/backend2"
        )
        resp = requests.get(
            req_url,
            headers={"host": jwt_secrets_setup.ingress_host},
            cookies={"auth_token": jwt_secrets_setup.jwt_token},
        )
        assert resp.status_code == 200
        assert f"Server name: backend2" in resp.text

    def test_response_codes_after_secret_remove_and_restore(
        self, kube_apis, jwt_secrets_setup, test_namespace, jwt_secret
    ):
        req_url = (
            f"http://{jwt_secrets_setup.public_endpoint.public_ip}:{jwt_secrets_setup.public_endpoint.port}/backend2"
        )
        delete_secret(kube_apis.v1, jwt_secret.secret_name, test_namespace)
        wait_before_test(1)
        resp = requests.get(
            req_url,
            headers={"host": jwt_secrets_setup.ingress_host},
            cookies={"auth_token": jwt_secrets_setup.jwt_token},
        )
        assert resp.status_code == 500

        jwt_secret.secret_name = create_secret_from_yaml(
            kube_apis.v1, test_namespace, f"{TEST_DATA}/jwt-secrets/jwt-secret.yaml"
        )
        wait_before_test(1)
        resp = requests.get(
            req_url,
            headers={"host": jwt_secrets_setup.ingress_host},
            cookies={"auth_token": jwt_secrets_setup.jwt_token},
        )
        assert resp.status_code == 200

    def test_response_code_500_with_invalid_secret(self, kube_apis, jwt_secrets_setup, test_namespace, jwt_secret):
        req_url = (
            f"http://{jwt_secrets_setup.public_endpoint.public_ip}:{jwt_secrets_setup.public_endpoint.port}/backend2"
        )
        replace_secret(
            kube_apis.v1, jwt_secret.secret_name, test_namespace, f"{TEST_DATA}/jwt-secrets/jwt-secret-invalid.yaml"
        )
        wait_before_test(1)
        resp = requests.get(
            req_url,
            headers={"host": jwt_secrets_setup.ingress_host},
            cookies={"auth_token": jwt_secrets_setup.jwt_token},
        )
        assert resp.status_code == 500

    def test_response_code_302_with_updated_secret(self, kube_apis, jwt_secrets_setup, test_namespace, jwt_secret):
        req_url = (
            f"http://{jwt_secrets_setup.public_endpoint.public_ip}:{jwt_secrets_setup.public_endpoint.port}/backend2"
        )
        replace_secret(
            kube_apis.v1, jwt_secret.secret_name, test_namespace, f"{TEST_DATA}/jwt-secrets/jwt-secret-updated.yaml"
        )
        wait_before_test(1)
        resp = requests.get(
            req_url,
            headers={"host": jwt_secrets_setup.ingress_host},
            cookies={"auth_token": jwt_secrets_setup.jwt_token},
            allow_redirects=False,
        )
        assert resp.status_code == 302

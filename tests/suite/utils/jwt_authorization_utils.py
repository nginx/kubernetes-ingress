"""Shared data and helpers for the JWT claim authorization E2E tests."""

import requests
import yaml
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import create_secret_from_yaml, delete_secret, wait_before_test

AUTHZ_DIR = f"{TEST_DATA}/jwt-policy/authorization"
TOKENS_DIR = f"{TEST_DATA}/jwt-policy/tokens"

jwk_secret_valid_src = f"{TEST_DATA}/jwt-policy/secret/jwk-secret-valid.yaml"
headers_app_type = "jwt-headers"


def policy_src(name: str) -> str:
    return f"{AUTHZ_DIR}/{name}.yaml"


def token_src(name: str) -> str:
    return f"{TOKENS_DIR}/authz-{name}.jwt"


def read_token(path: str) -> str:
    with open(path) as f:
        return f.readline().strip()


def vs_manifest(vs_src: str, spec_policy=None, route_policy=None) -> dict:
    """
    Load the standard VirtualServer and attach a policy at spec level and/or to the first route.
    """
    with open(vs_src) as f:
        vs = yaml.safe_load(f)
    if spec_policy:
        vs["spec"]["policies"] = [{"name": spec_policy}]
    if route_policy:
        vs["spec"]["routes"][0]["policies"] = [{"name": route_policy}]
    return vs


def create_authz_policy(custom_objects, name: str, namespace: str) -> str:
    """Create one of the policies in tests/data/jwt-policy/authorization and wait for it to be applied."""
    pol_name = create_policy_from_yaml(custom_objects, policy_src(name), namespace)
    wait_before_test()
    return pol_name


def get_with_token(url: str, host: str, token_name=None, extra_headers=None) -> requests.Response:
    """GET url with the Host header and, when given, the token from tests/data/jwt-policy/tokens."""
    headers = {"host": host}
    if token_name:
        headers["token"] = read_token(token_src(token_name))
    if extra_headers:
        headers.update(extra_headers)
    return requests.get(url, headers=headers, timeout=5)


def echoed_header(resp: requests.Response, name: str) -> str:
    """
    Return the value the upstream saw for a header, from the jwt-headers app, which prints
    `Name: [value]` for each header it echoes. Returns None if the line is missing.
    """
    prefix = f"{name}: ["
    for line in resp.text.splitlines():
        if line.startswith(prefix) and line.endswith("]"):
            return line[len(prefix) : -1]
    return None


class AuthzScenario:
    """
    Create the JWK secret and the given policies, run the body, and always clean up.

    Usage:
        with AuthzScenario(kube_apis, namespace, ["policy-claims"]) as scenario:
            ...
    """

    def __init__(self, kube_apis, namespace: str, policies: list):
        self.kube_apis = kube_apis
        self.namespace = namespace
        self.policies = policies
        self.secret_name = None
        self.policy_names = []

    def __enter__(self):
        self.secret_name = create_secret_from_yaml(self.kube_apis.v1, self.namespace, jwk_secret_valid_src)
        for pol in self.policies:
            self.policy_names.append(create_authz_policy(self.kube_apis.custom_objects, pol, self.namespace))
        return self

    def __exit__(self, *exc):
        for name in self.policy_names:
            delete_policy(self.kube_apis.custom_objects, name, self.namespace)
        if self.secret_name:
            delete_secret(self.kube_apis.v1, self.secret_name, self.namespace)
        return False

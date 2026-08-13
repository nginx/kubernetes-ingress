import base64
from copy import deepcopy
from pathlib import Path

import pytest
import requests
import yaml
from kubernetes.client.rest import ApiException
from settings import DEPLOYMENTS, TEST_DATA
from suite.test_oidc_native_ingress import keycloak_ingress_setup  # noqa: F401
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_items_from_yaml,
    create_secret,
    delete_ingress,
    delete_items_from_yaml,
    delete_namespace,
    delete_secret,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)

cm_src = f"{TEST_DATA}/oidc/nginx-config.yaml"
orig_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"

oidc_ingress_scenarios = Path(TEST_DATA) / "oidc-native/scenarios/ingress"

oidc_native_discovery_url = (
    "https://keycloak.{namespace}.svc.cluster.local:8443/realms/master/.well-known/openid-configuration"
)


def load_ingress_scenario(number):
    paths = list(oidc_ingress_scenarios.glob(f"test-{number}-*.yaml"))
    assert len(paths) == 1, f"Expected one scenario file for {number}, found {paths}"
    with paths[0].open() as f:
        return [doc for doc in yaml.safe_load_all(f) if doc is not None]


def configure_ingress_scenario_document(document, namespace, suffix, keycloak_host, mergeable_host=None):
    document = deepcopy(document)
    metadata = document.setdefault("metadata", {})
    metadata.pop("namespace", None)
    kind = document["kind"]

    if kind == "Ingress":
        original_name = metadata["name"]
        metadata["name"] = f"oidc-native-{suffix}-{original_name}"
        ann = metadata.get("annotations", {})
        merge_type = ann.get("nginx.org/mergeable-ingress-type")

        if merge_type == "minion":
            host = mergeable_host
        elif merge_type == "master":
            host_base = original_name.removesuffix("-master")
            host = f"oidc-native-{suffix}-{host_base}.example.com"
        else:
            host = f"oidc-native-{suffix}-{original_name}.example.com"

        for rule in document["spec"].get("rules", []):
            rule["host"] = host
        for tls in document["spec"].get("tls", []):
            tls["hosts"] = [host]
        for rule in document["spec"].get("rules", []):
            for path_entry in rule.get("http", {}).get("paths", []):
                path_entry["backend"]["service"]["name"] = "backend1-svc"

    elif kind == "Policy":
        native = document["spec"].get("oidcNative")
        if native:
            native["issuer"] = f"https://{keycloak_host}/realms/master"
            native["configURL"] = oidc_native_discovery_url.format(namespace=namespace)
            native["sslName"] = keycloak_host
        oidc = document["spec"].get("oidc")
        if oidc:
            base = f"https://{keycloak_host}:8443/realms/master/protocol/openid-connect"
            oidc.update(
                {
                    "authEndpoint": f"{base}/auth",
                    "tokenEndpoint": f"{base}/token",
                    "jwksURI": f"{base}/certs",
                    "endSessionEndpoint": f"{base}/logout",
                }
            )

    return document


def native_policy(secret_name, config_url, host, name="oidcnative-policy"):
    return {
        "apiVersion": "k8s.nginx.org/v1",
        "kind": "Policy",
        "metadata": {"name": name},
        "spec": {
            "oidcNative": {
                "issuer": f"https://{host}/realms/master",
                "configURL": config_url,
                "sslName": host,
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


def create_ingress_scenario_resources(kube_apis, namespace, keycloak_setup, number):
    suffix = str(number)
    resources = {"policies": [], "secrets": [], "ingresses": []}

    # Create default secret + policy
    secret_name = create_native_secret(kube_apis, namespace, keycloak_setup.secret)
    resources["secrets"].append(secret_name)
    base_policy = native_policy(secret_name, oidc_native_discovery_url.format(namespace=namespace), keycloak_setup.host)
    kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", namespace, "policies", base_policy)
    resources["policies"].append(base_policy["metadata"]["name"])

    documents = load_ingress_scenario(number)

    # Pre-compute mergeable host from master
    mergeable_host = None
    for doc in documents:
        if doc["kind"] == "Ingress":
            ann = doc.get("metadata", {}).get("annotations", {})
            if ann.get("nginx.org/mergeable-ingress-type") == "master":
                host_base = doc["metadata"]["name"].removesuffix("-master")
                mergeable_host = f"oidc-native-{suffix}-{host_base}.example.com"
                break

    # Configure and create all documents
    for doc in documents:
        if doc["kind"] == "Namespace":
            continue
        doc = configure_ingress_scenario_document(doc, namespace, suffix, keycloak_setup.host, mergeable_host)
        kind = doc["kind"]
        if kind == "Secret":
            if doc["metadata"]["name"] == "test18-wrong-type":
                doc["data"] = {"tls.crt": "YQ==", "tls.key": "YQ=="}
            name = create_secret(kube_apis.v1, namespace, doc)
            resources["secrets"].append(name)
        elif kind == "Policy":
            if doc["spec"].get("oidc"):
                njs_secret = create_native_secret(kube_apis, namespace, keycloak_setup.secret, "oidc-njs-secret")
                resources["secrets"].append(njs_secret)
            kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", namespace, "policies", doc)
            resources["policies"].append(doc["metadata"]["name"])
        elif kind == "Ingress":
            name = kube_apis.networking_v1.create_namespaced_ingress(namespace, doc).metadata.name
            resources["ingresses"].append(name)

    return resources


def cleanup_ingress_scenario_resources(kube_apis, namespace, resources):
    for name in reversed(resources["ingresses"]):
        try:
            delete_ingress(kube_apis.networking_v1, name, namespace)
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
        f"{scheme}://{endpoint.public_ip}:{port}{path}",
        headers={"Host": host},
        verify=False,
        allow_redirects=False,
    )


def ingress_conf(kube_apis, ingress_controller_prerequisites, namespace, ingress_name):
    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
    return get_ingress_nginx_template_conf(
        kube_apis.v1,
        namespace,
        ingress_name,
        ic_pod_name,
        ingress_controller_prerequisites.namespace,
    )


@pytest.fixture(scope="class")
def backend_setup(request, kube_apis, test_namespace):
    """Deploy backend1 once for all scenario tests."""
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/common/backend1.yaml", test_namespace)
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/common/backend1-svc.yaml", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    def fin():
        delete_items_from_yaml(kube_apis, f"{TEST_DATA}/common/backend1.yaml", test_namespace)
        delete_items_from_yaml(kube_apis, f"{TEST_DATA}/common/backend1-svc.yaml", test_namespace)

    request.addfinalizer(fin)


@pytest.mark.policies
@pytest.mark.native_oidc
@pytest.mark.skip_for_nginx_oss
@pytest.mark.usefixtures("crd_ingress_controller")
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [{"type": "complete", "extra_args": ["-enable-custom-resources", "-enable-oidc", "-enable-prometheus-metrics"]}],
    indirect=True,
)
class TestOIDCNativeIngressScenarios:
    @pytest.fixture(autouse=True)
    def configure_oidc_resolver(self, kube_apis, ingress_controller_prerequisites):
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            cm_src,
        )
        wait_before_test()
        yield
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            orig_cm_src,
        )

    # Scenario 1: standard -- annotation-level policy protects all paths;
    # both / and /public redirect to Keycloak (302).
    def test_scenario_1_standard_protects_all_paths(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 1)
        try:
            wait_before_test()
            ing = kube_apis.networking_v1.read_namespaced_ingress(resources["ingresses"][0], test_namespace)
            host = ing.spec.rules[0].host
            assert scenario_response(ingress_controller_endpoint, host, "/").status_code == 302
            assert scenario_response(ingress_controller_endpoint, host, "/public").status_code == 302
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 2: mergeable-route -- minion-level policy; / redirects (minion
    # carries the policy), /public is open (minion has no policy).
    def test_scenario_2_mergeable_route_level_policy(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 2)
        try:
            wait_before_test()
            ing = kube_apis.networking_v1.read_namespaced_ingress(resources["ingresses"][0], test_namespace)
            host = ing.spec.rules[0].host
            assert scenario_response(ingress_controller_endpoint, host, "/").status_code == 302
            assert scenario_response(ingress_controller_endpoint, host, "/public").status_code == 200
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 3: two-policies -- master policy with minion override; two
    # distinct oidc_provider blocks generated (config-only: verifying two
    # separate logged-in browser sessions isn't automatable here).
    def test_scenario_3_two_policies_generate_two_providers(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 3)
        try:
            wait_before_test()
            # For mergeable, config is named after the master (first Ingress)
            master_name = resources["ingresses"][0]
            conf = ingress_conf(kube_apis, ingress_controller_prerequisites, test_namespace, master_name)
            assert conf.count("oidc_provider ") == 2, "expected two oidc_provider blocks"
            assert "client_id nginx-plus;" in conf
            assert "client_id nginx-plus-2;" in conf
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 4: multi-ingress-different-policies -- two standard Ingresses
    # on different hosts, each with a different policy; each generates a
    # distinct provider (config-only).
    def test_scenario_4_multi_ingress_different_policies(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 4)
        try:
            wait_before_test()
            # Each standard Ingress generates its own config file
            confs = [
                ingress_conf(kube_apis, ingress_controller_prerequisites, test_namespace, name)
                for name in resources["ingresses"]
            ]
            assert any("client_id nginx-plus;" in c for c in confs)
            assert any("client_id nginx-plus-2;" in c for c in confs)
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 5: same-policy-multi-ingress -- two standard Ingresses sharing
    # the same policy; provider names are still globally unique (embed the
    # Ingress name) even though the source policy is shared (config-only).
    def test_scenario_5_same_policy_multi_ingress_unique_providers(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 5)
        try:
            wait_before_test()
            confs = [
                ingress_conf(kube_apis, ingress_controller_prerequisites, test_namespace, name)
                for name in resources["ingresses"]
            ]
            provider_names = []
            for c in confs:
                for line in c.splitlines():
                    line = line.strip()
                    if line.startswith("oidc_provider "):
                        provider_names.append(line.split()[1])
            assert len(provider_names) == len(set(provider_names)), "provider names must be globally unique"
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 6: njs-ingress-native-ingress -- NJS OIDC policy on one
    # Ingress (unsupported, returns 500), native OIDC on another (returns
    # 302). Verifies one broken Ingress does not affect another.
    def test_scenario_6_njs_rejected_native_works(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 6)
        try:
            wait_before_test()
            hosts = {}
            for name in resources["ingresses"]:
                ing = kube_apis.networking_v1.read_namespaced_ingress(name, test_namespace)
                hosts[name] = ing.spec.rules[0].host
            responses = {name: scenario_response(ingress_controller_endpoint, host) for name, host in hosts.items()}
            njs_responses = [r for n, r in responses.items() if "app1" in n]
            native_responses = [r for n, r in responses.items() if "app2" in n]
            assert njs_responses[0].status_code == 500, "NJS OIDC unsupported on Ingress"
            assert native_responses[0].status_code == 302, "native OIDC should redirect"
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 7: lifecycle-delete -- 302 -> delete policy -> 500 ->
    # recreate policy -> 302 again.
    def test_scenario_7_policy_delete_and_recreate(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 7)
        try:
            wait_before_test()
            ing = kube_apis.networking_v1.read_namespaced_ingress(resources["ingresses"][0], test_namespace)
            host = ing.spec.rules[0].host
            assert scenario_response(ingress_controller_endpoint, host).status_code == 302

            delete_policy(kube_apis.custom_objects, "oidcnative-policy", test_namespace)
            resources["policies"].remove("oidcnative-policy")
            wait_before_test()
            assert scenario_response(ingress_controller_endpoint, host).status_code == 500

            policy = native_policy(
                resources["secrets"][0],
                oidc_native_discovery_url.format(namespace=test_namespace),
                keycloak_ingress_setup.host,
            )
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", test_namespace, "policies", policy
            )
            resources["policies"].append(policy["metadata"]["name"])
            wait_before_test()
            assert scenario_response(ingress_controller_endpoint, host).status_code == 302
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Secret rotation on a running scenario; Ingress continues to return
    # 302 after the client secret is patched.
    def test_scenario_secret_rotation(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 1)
        try:
            wait_before_test()
            secret_name = resources["secrets"][0]
            rotated_secret = base64.b64encode(b"rotated-client-secret").decode()
            kube_apis.v1.patch_namespaced_secret(
                secret_name, test_namespace, {"data": {"client-secret": rotated_secret}}
            )
            wait_before_test()
            ing = kube_apis.networking_v1.read_namespaced_ingress(resources["ingresses"][0], test_namespace)
            host = ing.spec.rules[0].host
            assert scenario_response(ingress_controller_endpoint, host).status_code == 302
            assert (
                kube_apis.v1.read_namespaced_secret(secret_name, test_namespace).data["client-secret"] == rotated_secret
            )
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Policy update (scope) on a running scenario; Ingress continues to
    # return 302 after the policy scope is patched.
    def test_scenario_policy_update(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 1)
        try:
            wait_before_test()
            kube_apis.custom_objects.patch_namespaced_custom_object(
                "k8s.nginx.org",
                "v1",
                test_namespace,
                "policies",
                "oidcnative-policy",
                {"spec": {"oidcNative": {"scope": "openid email"}}},
            )
            wait_before_test()
            policy = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", "oidcnative-policy")
            assert policy["spec"]["oidcNative"]["scope"] == "openid email"
            ing = kube_apis.networking_v1.read_namespaced_ingress(resources["ingresses"][0], test_namespace)
            host = ing.spec.rules[0].host
            assert scenario_response(ingress_controller_endpoint, host).status_code == 302
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 8: no-tls -- config-generation smoke only; HTTP request
    # returns 302 to Keycloak. The full browser flow needs a Secure cookie
    # over HTTPS.
    def test_scenario_8_without_tls_redirects(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 8)
        try:
            wait_before_test()
            ing = kube_apis.networking_v1.read_namespaced_ingress(resources["ingresses"][0], test_namespace)
            host = ing.spec.rules[0].host
            assert scenario_response(ingress_controller_endpoint, host, https=False).status_code == 302
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 9: mixed-routes -- /api and /admin redirect (minions carry
    # the policy), /health and /public are open (minions have no policy).
    def test_scenario_9_mixed_routes(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, 9)
        try:
            wait_before_test()
            ing = kube_apis.networking_v1.read_namespaced_ingress(resources["ingresses"][0], test_namespace)
            host = ing.spec.rules[0].host
            assert scenario_response(ingress_controller_endpoint, host, "/api").status_code == 302
            assert scenario_response(ingress_controller_endpoint, host, "/admin").status_code == 302
            assert scenario_response(ingress_controller_endpoint, host, "/health").status_code == 200
            assert scenario_response(ingress_controller_endpoint, host, "/public").status_code == 200
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 10: cross-namespace -- Ingress references a policy in a
    # different namespace via the annotation; the oidc_provider block is
    # generated from the cross-namespace policy.
    def test_scenario_10_cross_namespace_policy(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
    ):
        policy_namespace = f"{test_namespace}-oidc-policies"
        kube_apis.v1.create_namespace({"metadata": {"name": policy_namespace}})
        resources = {"policies": [], "secrets": [], "ingresses": []}
        try:
            secret = create_native_secret(kube_apis, policy_namespace, keycloak_ingress_setup.secret)
            resources["secrets"].append(secret)
            policy = native_policy(
                secret,
                oidc_native_discovery_url.format(namespace=test_namespace),
                keycloak_ingress_setup.host,
                "cross-ns-policy",
            )
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", policy_namespace, "policies", policy
            )
            resources["policies"].append(policy["metadata"]["name"])

            scenario_ing = next(doc for doc in load_ingress_scenario(10) if doc["kind"] == "Ingress")
            ing_doc = configure_ingress_scenario_document(
                scenario_ing, test_namespace, "10", keycloak_ingress_setup.host
            )
            # Update the annotation to reference the actual policy namespace
            ing_doc["metadata"]["annotations"]["nginx.com/policies"] = f"{policy_namespace}/cross-ns-policy"
            name = kube_apis.networking_v1.create_namespaced_ingress(test_namespace, ing_doc).metadata.name
            resources["ingresses"].append(name)
            wait_before_test()

            conf = ingress_conf(kube_apis, ingress_controller_prerequisites, test_namespace, name)
            assert "oidc_provider " in conf, "expected oidc_provider block from the cross-namespace policy"
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)
            delete_namespace(kube_apis.v1, policy_namespace)

    # Scenarios 11-15: missing/wrong secret, missing/wrong CA, secret
    # storing the value under the wrong key -- all rejected by secret
    # validation, so unauthenticated requests return 500 (no valid OIDC
    # config).
    @pytest.mark.parametrize("number", [11, 12, 13, 14, 15])
    def test_invalid_secret_references_warn(
        self,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_ingress_setup,
        backend_setup,
        crd_ingress_controller,
        number,
    ):
        resources = create_ingress_scenario_resources(kube_apis, test_namespace, keycloak_ingress_setup, number)
        try:
            wait_before_test()
            ing = kube_apis.networking_v1.read_namespaced_ingress(resources["ingresses"][0], test_namespace)
            host = ing.spec.rules[0].host
            assert scenario_response(ingress_controller_endpoint, host).status_code == 500
        finally:
            cleanup_ingress_scenario_resources(kube_apis, test_namespace, resources)

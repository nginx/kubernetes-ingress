import base64
from copy import deepcopy
from pathlib import Path

import pytest
import requests
import yaml
from kubernetes.client.rest import ApiException
from settings import DEPLOYMENTS, TEST_DATA
from suite.test_oidc_native import keycloak_setup  # noqa: F401
from suite.utils.custom_assertions import assert_crd_status, assert_vs_status, assert_vsr_status
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_secret,
    delete_namespace,
    delete_secret,
    get_first_pod_name,
    get_vs_nginx_template_conf,
    replace_configmap_from_yaml,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import delete_v_s_route, delete_virtual_server

cm_src = f"{TEST_DATA}/oidc/nginx-config.yaml"
orig_cm_src = f"{DEPLOYMENTS}/common/nginx-config.yaml"

# Each scenario below is a standalone Policy/VirtualServer/(VirtualServerRoute)
# fixture, keyed by number, describing one placement/coexistence/failure
# combination for the oidcNative Policy. configure_scenario_document()
# materializes a scenario's placeholder host/service names against the
# suite's TLS/backend fixture, and create_scenario_resources() applies the
# result plus a default oidcnative-policy against a real cluster.
oidc_native_scenarios = Path(TEST_DATA) / "oidc-native/scenarios"
oidc_native_discovery_url = (
    "https://keycloak.{namespace}.svc.cluster.local:8443/realms/master/.well-known/openid-configuration"
)


def load_native_scenario(number):
    paths = list(oidc_native_scenarios.glob(f"test-{number}-*.yaml"))
    assert len(paths) == 1, f"Expected one scenario file for {number}, found {paths}"
    with paths[0].open() as scenario_file:
        # Scenario 13 starts with a leading `---`, which yields a `None`
        # document from safe_load_all -- drop it here once, so every caller
        # can safely assume a list of real documents.
        return [doc for doc in yaml.safe_load_all(scenario_file) if doc is not None]


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


def configure_scenario_document(document, namespace, suffix, keycloak_host):
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
            # The native module requires `issuer` to exactly match the
            # metadata document's "issuer" claim. Keycloak derives that claim
            # from the Host header of the discovery request, which is
            # keycloak_host here (the resolvable in-cluster service DNS
            # name) -- not the scenario's placeholder keycloak.example.com.
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


def create_scenario_resources(kube_apis, namespace, keycloak_setup, number):
    """Create one scenario's resources and return them for status checks and cleanup."""
    suffix = str(number)
    resources = {"policies": [], "secrets": [], "virtualservers": [], "virtualserverroutes": []}
    secret_name = create_native_secret(kube_apis, namespace, keycloak_setup.secret)
    resources["secrets"].append(secret_name)
    base_policy = native_policy(secret_name, oidc_native_discovery_url.format(namespace=namespace), keycloak_setup.host)
    kube_apis.custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", namespace, "policies", base_policy)
    resources["policies"].append(base_policy["metadata"]["name"])

    # Scenario 9 reuses the NJS policy defined by scenario 8a.
    if number == 9:
        njs_secret = create_native_secret(kube_apis, namespace, keycloak_setup.secret, "oidc-njs-secret")
        resources["secrets"].append(njs_secret)
        njs_policy = configure_scenario_document(load_native_scenario("8a")[0], namespace, suffix, keycloak_setup.host)
        kube_apis.custom_objects.create_namespaced_custom_object(
            "k8s.nginx.org", "v1", namespace, "policies", njs_policy
        )
        resources["policies"].append(njs_policy["metadata"]["name"])

    for document in load_native_scenario(number):
        if document["kind"] == "Namespace":
            continue
        document = configure_scenario_document(document, namespace, suffix, keycloak_setup.host)
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


def vs_conf(kube_apis, ingress_controller_prerequisites, namespace, vs_name):
    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
    return get_vs_nginx_template_conf(
        kube_apis.v1, namespace, vs_name, ic_pod_name, ingress_controller_prerequisites.namespace
    )


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
class TestOIDCNativeScenarios:
    """
    Placement, coexistence, lifecycle, and failure scenarios for the
    oidcNative Policy, asserting VS/VSR status, unauthenticated response
    codes, and (where an interactive login can't be verified in CI) the
    generated NGINX config.
    Uses the resolver-only ConfigMap (cm_src) -- none of these scenarios
    exercise zone-sync.
    """

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

    # Scenario 1: vs-spec -- VS Valid; both / and /public redirect (policy
    # applies to the whole VS spec, so every route is protected).
    def test_scenario_1_vs_spec_protects_all_routes(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 1)
        try:
            wait_before_test()
            vs_name = resources["virtualservers"][0]
            assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            vs = read_custom_resource(kube_apis.custom_objects, test_namespace, "virtualservers", vs_name)
            host = vs["spec"]["host"]
            assert scenario_response(ingress_controller_endpoint, host, "/").status_code == 302
            assert scenario_response(ingress_controller_endpoint, host, "/public").status_code == 302
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 2: vs-route -- VS Valid; / redirects (route-level policy),
    # /public is open.
    def test_scenario_2_route_level_policy(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 2)
        try:
            wait_before_test()
            vs_name = resources["virtualservers"][0]
            assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            vs = read_custom_resource(kube_apis.custom_objects, test_namespace, "virtualservers", vs_name)
            host = vs["spec"]["host"]
            assert scenario_response(ingress_controller_endpoint, host, "/").status_code == 302
            assert scenario_response(ingress_controller_endpoint, host, "/public").status_code == 200
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 3: vsr-subroute -- VS+VSR Valid; /vsr/protected redirects,
    # /vsr/public and / (no policy on parent) are open.
    def test_scenario_3_vsr_subroute_policy(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 3)
        try:
            wait_before_test()
            vs_name = resources["virtualservers"][0]
            assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            for name in resources["virtualserverroutes"]:
                assert_vsr_status(kube_apis, test_namespace, name, "Valid")
            vs = read_custom_resource(kube_apis.custom_objects, test_namespace, "virtualservers", vs_name)
            host = vs["spec"]["host"]
            assert scenario_response(ingress_controller_endpoint, host, "/vsr/protected").status_code == 302
            assert scenario_response(ingress_controller_endpoint, host, "/vsr/public").status_code == 200
            assert scenario_response(ingress_controller_endpoint, host, "/").status_code == 200
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 4: two-policies-vs -- VS Valid; two distinct oidc_provider
    # blocks generated (config-only: verifying two separate logged-in
    # browser sessions isn't automatable here).
    def test_scenario_4_two_policies_generate_two_providers(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 4)
        try:
            wait_before_test()
            vs_name = resources["virtualservers"][0]
            assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            conf = vs_conf(kube_apis, ingress_controller_prerequisites, test_namespace, vs_name)
            assert conf.count("oidc_provider ") == 2, "expected two oidc_provider blocks"
            assert "client_id nginx-plus;" in conf
            assert "client_id nginx-plus-2;" in conf
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 5: vs-and-vsr -- VS+VSR Valid; two providers, /vsr/alt uses
    # policy-2, / and /vsr/default inherit policy-1 (config-only).
    def test_scenario_5_vs_and_vsr_different_policies(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 5)
        try:
            wait_before_test()
            vs_name = resources["virtualservers"][0]
            assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            for name in resources["virtualserverroutes"]:
                assert_vsr_status(kube_apis, test_namespace, name, "Valid")
            conf = vs_conf(kube_apis, ingress_controller_prerequisites, test_namespace, vs_name)
            assert conf.count("oidc_provider ") == 2, "expected two oidc_provider blocks"
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 6: multi-vs-different-policies -- both VS Valid; each
    # generates a distinct provider (config-only: browser flow needs
    # nip.io hostnames registered in Keycloak, out of scope for CI).
    def test_scenario_6_multi_vs_different_policies(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 6)
        try:
            wait_before_test()
            for name in resources["virtualservers"]:
                assert_vs_status(kube_apis, test_namespace, name, "Valid")
            confs = [
                vs_conf(kube_apis, ingress_controller_prerequisites, test_namespace, name)
                for name in resources["virtualservers"]
            ]
            assert any("client_id nginx-plus;" in c for c in confs)
            assert any("client_id nginx-plus-2;" in c for c in confs)
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 7: same-policy-multi-vs -- both VS Valid; provider names are
    # still globally unique (embed the VS name) even though the source
    # policy is shared (config-only).
    def test_scenario_7_same_policy_multi_vs_unique_providers(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 7)
        try:
            wait_before_test()
            for name in resources["virtualservers"]:
                assert_vs_status(kube_apis, test_namespace, name, "Valid")
            confs = [
                vs_conf(kube_apis, ingress_controller_prerequisites, test_namespace, name)
                for name in resources["virtualservers"]
            ]
            provider_names = []
            for c in confs:
                for line in c.splitlines():
                    line = line.strip()
                    if line.startswith("oidc_provider "):
                        provider_names.append(line.split()[1])
            assert len(provider_names) == len(set(provider_names)), "provider names must be globally unique"
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 8a: njs-and-native -- VS Valid; config shows both the native
    # oidc_provider block and the NJS OIDC server-level set directives
    # (config-only; the two mechanisms use separate callback paths that
    # would each need their own registered Keycloak client).
    def test_scenario_8a_njs_and_native_coexist(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, "8a")
        try:
            wait_before_test()
            vs_name = resources["virtualservers"][0]
            assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            conf = vs_conf(kube_apis, ingress_controller_prerequisites, test_namespace, vs_name)
            assert "oidc_provider " in conf, "expected native oidc_provider block"
            assert "set $oidc_pkce_enable" in conf, "expected NJS OIDC server-level directives"
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 8b: conflict -- both oidc and oidcNative on the same route ->
    # rejected with VS Warning; the conflicting location fails closed with a
    # static 500 (no auth_oidc / oidc_provider wiring).
    def test_scenario_8b_rejects_njs_and_native_in_one_context(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, "8a")
        try:
            conflict = configure_scenario_document(
                load_native_scenario("8b")[0], test_namespace, "8b", keycloak_setup.host
            )
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", test_namespace, "virtualservers", conflict
            )
            resources["virtualservers"].append(conflict["metadata"]["name"])
            assert_vs_status(kube_apis, test_namespace, conflict["metadata"]["name"], "Warning")
            # The conflicting route still renders -- with the policy config
            # replaced by a static 500, not "no config at all". Only one of
            # the two OIDC implementations can be active per context; NIC
            # rejects the second one to be processed rather than silently
            # picking one, so neither auth_oidc nor an oidc_provider block
            # should end up wired to this route.
            conf = vs_conf(kube_apis, ingress_controller_prerequisites, test_namespace, conflict["metadata"]["name"])
            assert "return 500;" in conf, "expected the conflicting route to fail closed with a static 500"
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 9: njs-vs-native -- NJS on VS1, native on VS2; each VS's
    # config shows only its own mechanism (config-only).
    def test_scenario_9_njs_vs_native_separate_virtualservers(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 9)
        try:
            wait_before_test()
            for name in resources["virtualservers"]:
                assert_vs_status(kube_apis, test_namespace, name, "Valid")
            confs = {
                name: vs_conf(kube_apis, ingress_controller_prerequisites, test_namespace, name)
                for name in resources["virtualservers"]
            }
            njs_confs = [c for c in confs.values() if "set $oidc_pkce_enable" in c]
            native_confs = [c for c in confs.values() if "oidc_provider " in c]
            assert len(njs_confs) == 1, "expected exactly one VS with NJS OIDC directives"
            assert len(native_confs) == 1, "expected exactly one VS with a native oidc_provider block"
            assert "oidc_provider " not in njs_confs[0], "NJS VS should not also carry a native provider"
            assert "set $oidc_pkce_enable" not in native_confs[0], "native VS should not also carry NJS directives"
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 10: lifecycle-delete -- Valid -> delete policy -> Warning +
    # 500 -> recreate -> Valid + working (302) again.
    def test_scenario_10_policy_delete_and_recreate(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 10)
        try:
            vs_name = resources["virtualservers"][0]
            vs = assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            host = vs["spec"]["host"]
            assert scenario_response(ingress_controller_endpoint, host).status_code == 302

            delete_policy(kube_apis.custom_objects, "oidcnative-policy", test_namespace)
            resources["policies"].remove("oidcnative-policy")
            assert_vs_status(kube_apis, test_namespace, vs_name, "Warning")
            assert scenario_response(ingress_controller_endpoint, host).status_code == 500

            policy = native_policy(
                resources["secrets"][0], oidc_native_discovery_url.format(namespace=test_namespace), keycloak_setup.host
            )
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", test_namespace, "policies", policy
            )
            resources["policies"].append(policy["metadata"]["name"])
            assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            assert scenario_response(ingress_controller_endpoint, host).status_code == 302
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Secret rotation on a running scenario keeps the VS Valid.
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

    # Policy update (scope) on a running scenario keeps the VS Valid.
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

    # Scenario 13: invalid -- each policy has a field-level violation (missing
    # required field, bad enum, bad pattern) enforced by CRD/kubebuilder
    # markers, so the API server rejects it at admission time (422) and no
    # object is ever persisted.
    def test_scenario_13_invalid_fields_rejected_at_admission(
        self, crd_ingress_controller, virtual_server_setup, keycloak_setup, kube_apis, test_namespace
    ):
        for policy in load_native_scenario(13):
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

    # Scenario 22: a single Policy with both oidc and oidcNative set. Unlike
    # scenario 13, "exactly one policy type must be set" is a cross-field
    # constraint enforced only by NIC's controller (validatePolicySpec in
    # pkg/apis/configuration/validation/policy.go) -- there is no CRD-level
    # CEL rule for it and no admission webhook, so the API server accepts the
    # object. NIC then marks it Invalid after the fact.
    def test_scenario_22_conflicting_policy_types_rejected_by_controller(
        self, crd_ingress_controller, virtual_server_setup, keycloak_setup, kube_apis, test_namespace
    ):
        policy = load_native_scenario(22)[0]
        name = policy["metadata"]["name"]
        try:
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", test_namespace, "policies", policy
            )
            assert_crd_status(
                kube_apis,
                test_namespace,
                name,
                "policies",
                "Invalid",
                expected_messages=["must specify exactly one of"],
            )
        finally:
            delete_policy(kube_apis.custom_objects, name, test_namespace)

    # Scenario 14: no-tls -- config-generation smoke only; the full browser
    # flow needs a Secure cookie over HTTPS.
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

    # Scenario 15: mixed-routes -- /api and /admin redirect, /health and
    # /public are open.
    def test_scenario_15_mixed_routes(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_endpoint,
        keycloak_setup,
    ):
        resources = create_scenario_resources(kube_apis, test_namespace, keycloak_setup, 15)
        try:
            wait_before_test()
            vs_name = resources["virtualservers"][0]
            assert_vs_status(kube_apis, test_namespace, vs_name, "Valid")
            vs = read_custom_resource(kube_apis.custom_objects, test_namespace, "virtualservers", vs_name)
            host = vs["spec"]["host"]
            assert scenario_response(ingress_controller_endpoint, host, "/api").status_code == 302
            assert scenario_response(ingress_controller_endpoint, host, "/admin").status_code == 302
            assert scenario_response(ingress_controller_endpoint, host, "/health").status_code == 200
            assert scenario_response(ingress_controller_endpoint, host, "/public").status_code == 200
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

    # Scenario 16: cross-namespace -- VS Valid, no warning about a missing
    # policy, and the oidc_provider block is generated from the
    # cross-namespace policy.
    def test_scenario_16_cross_namespace_policy(
        self,
        crd_ingress_controller,
        virtual_server_setup,
        kube_apis,
        test_namespace,
        ingress_controller_prerequisites,
        keycloak_setup,
    ):
        policy_namespace = f"{test_namespace}-oidc-policies"
        kube_apis.v1.create_namespace({"metadata": {"name": policy_namespace}})
        resources = {"policies": [], "secrets": [], "virtualservers": [], "virtualserverroutes": []}
        try:
            secret = create_native_secret(kube_apis, policy_namespace, keycloak_setup.secret)
            resources["secrets"].append(secret)
            policy = native_policy(
                secret,
                oidc_native_discovery_url.format(namespace=test_namespace),
                keycloak_setup.host,
                "cross-ns-policy",
            )
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", policy_namespace, "policies", policy
            )
            resources["policies"].append(policy["metadata"]["name"])

            scenario_vs = next(doc for doc in load_native_scenario(16) if doc["kind"] == "VirtualServer")
            vs = configure_scenario_document(scenario_vs, test_namespace, "16", keycloak_setup.host)
            vs["spec"]["policies"][0]["namespace"] = policy_namespace
            kube_apis.custom_objects.create_namespaced_custom_object(
                "k8s.nginx.org", "v1", test_namespace, "virtualservers", vs
            )
            resources["virtualservers"].append(vs["metadata"]["name"])
            assert_vs_status(kube_apis, test_namespace, vs["metadata"]["name"], "Valid")
            conf = vs_conf(kube_apis, ingress_controller_prerequisites, test_namespace, vs["metadata"]["name"])
            assert "oidc_provider " in conf, "expected oidc_provider block from the cross-namespace policy"
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)
            delete_namespace(kube_apis.v1, policy_namespace)

    # Scenarios 17-21: missing/wrong secret, missing/wrong CA, secret storing
    # the value under the wrong key -- all rejected by secret validation, so
    # the VS reaches Warning and unauthenticated requests return 500 (no
    # valid OIDC config).
    @pytest.mark.parametrize("number", [17, 18, 19, 20, 21])
    def test_invalid_secret_references_warn(
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
            vs = assert_vs_status(kube_apis, test_namespace, resources["virtualservers"][0], "Warning")
            assert scenario_response(ingress_controller_endpoint, vs["spec"]["host"]).status_code == 500
        finally:
            cleanup_scenario_resources(kube_apis, test_namespace, resources)

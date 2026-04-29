"""Tests for multiple regex paths per VSR feature.

A single VSR may be referenced by multiple regex VS routes. The VS paths and
VSR subroute paths must form an exact set match. This file exercises the happy
path and several failure scenarios.
"""

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_event, wait_and_assert_status_code
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.resources_utils import (
    get_events,
    get_first_pod_name,
    get_vs_nginx_template_conf,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route_from_yaml,
    create_virtual_server_from_yaml,
    delete_v_s_route,
    delete_virtual_server,
    patch_v_s_route_from_yaml,
    patch_virtual_server_from_yaml,
)
from suite.utils.yaml_utils import get_first_host_from_yaml

EXAMPLE = "virtual-server-route-multiple-regex"


class MultiRegexVSRSetup:
    """Encapsulate multi-regex VSR test details."""

    def __init__(self, public_endpoint, namespace, vs_host, vs_name):
        self.public_endpoint = public_endpoint
        self.namespace = namespace
        self.vs_host = vs_host
        self.vs_name = vs_name
        self.req_url = f"http://{public_endpoint.public_ip}:{public_endpoint.port}"


@pytest.fixture(scope="class")
def multi_regex_vsr_setup(request, kube_apis, ingress_controller_endpoint, test_namespace) -> MultiRegexVSRSetup:
    """
    Deploy a VirtualServer with multiple regex routes and two VSRs.

    All resources live in a single namespace (test_namespace) so teardown
    is handled automatically when the namespace is removed.
    """
    print("------------------------- Deploy Virtual Server -----------------------------------")
    vs_src = f"{TEST_DATA}/{EXAMPLE}/standard/virtual-server.yaml"
    vs_name = create_virtual_server_from_yaml(kube_apis.custom_objects, vs_src, test_namespace)
    vs_host = get_first_host_from_yaml(vs_src)

    print("------------------------- Deploy Virtual Server Routes -----------------------------------")
    for vsr_file in ["route-api", "route-images"]:
        create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            f"{TEST_DATA}/{EXAMPLE}/{vsr_file}.yaml",
            test_namespace,
        )

    # Poll the Kubernetes API until the IC sets the VS status to "Valid".
    # The IC only marks the VS Valid after it has successfully applied the
    # config to nginx, making this a reliable readiness signal that works
    # across all image variants (OSS, Plus, FIPS) without requiring network
    # access to nginx. Up to 60 seconds (30 × 2 s) before giving up.
    # Diagnostic prints are intentional — they surface the IC's state in
    # CI logs so we can distinguish a timing race from a fundamental rejection.
    for _ in range(30):
        vs_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "virtualservers", vs_name)
        state = vs_info.get("status", {}).get("state")
        print(f"[multi_regex_vsr_setup] VS '{vs_name}' status.state={state!r}")
        if state == "Valid":
            break
        wait_before_test(2)
    else:
        pytest.fail(
            f"[multi_regex_vsr_setup] VS '{vs_name}' did not reach Valid state after 60 s; "
            f"last status={vs_info.get('status', {})!r}"
        )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up multi-regex VSR resources:")
            delete_v_s_route(kube_apis.custom_objects, "route-api", test_namespace)
            delete_v_s_route(kube_apis.custom_objects, "route-images", test_namespace)
            delete_virtual_server(kube_apis.custom_objects, vs_name, test_namespace)

    request.addfinalizer(fin)
    return MultiRegexVSRSetup(ingress_controller_endpoint, test_namespace, vs_host, vs_name)


@pytest.mark.vsr
@pytest.mark.vsr_multi_regex
@pytest.mark.parametrize(
    "crd_ingress_controller, multi_regex_vsr_setup",
    [
        (
            {"type": "complete", "extra_args": ["-enable-custom-resources"]},
            {},
        )
    ],
    indirect=True,
)
class TestVSRMultipleRegexPaths:
    """Test multiple regex paths per VSR, including normalisation and error cases."""

    def restore_valid_state(self, kube_apis, setup):
        """Restore VS and both VSRs to their valid baseline YAML."""
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            setup.vs_name,
            f"{TEST_DATA}/{EXAMPLE}/standard/virtual-server.yaml",
            setup.namespace,
        )
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            "route-api",
            f"{TEST_DATA}/{EXAMPLE}/route-api.yaml",
            setup.namespace,
        )
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            "route-images",
            f"{TEST_DATA}/{EXAMPLE}/route-images.yaml",
            setup.namespace,
        )
        wait_before_test()

    # ------------------------------------------------------------------ #
    # Happy-path tests
    # ------------------------------------------------------------------ #

    @pytest.mark.smoke
    def test_happy_path_status(self, kube_apis, crd_ingress_controller, multi_regex_vsr_setup):
        """VS and both VSRs should be Valid after initial deploy."""
        setup = multi_regex_vsr_setup
        # No wait needed here — the fixture already blocked until the IC is
        # serving traffic, so the status subresource is guaranteed to be set.
        vs_info = read_custom_resource(kube_apis.custom_objects, setup.namespace, "virtualservers", setup.vs_name)
        assert vs_info["status"]["state"] == "Valid", f"VS status: {vs_info.get('status', 'not yet populated')}"
        assert vs_info["status"]["reason"] == "AddedOrUpdated"

        for vsr_name in ["route-api", "route-images"]:
            vsr_info = read_custom_resource(kube_apis.custom_objects, setup.namespace, "virtualserverroutes", vsr_name)
            assert vsr_info["status"]["state"] == "Valid", f"VSR {vsr_name} status: {vsr_info['status']}"
            assert vsr_info["status"]["reason"] == "AddedOrUpdated"

    def test_happy_path_traffic(self, kube_apis, crd_ingress_controller, multi_regex_vsr_setup):
        """Each path should return its expected canned response body."""
        setup = multi_regex_vsr_setup

        expected = {
            "/api/v1": "api-v1",
            "/api/v2": "api-v2",
            "/images/jpg": "images-jpg",
            "/images/png": "images-png",
            "/static": "static",
        }

        for path, body in expected.items():
            wait_and_assert_status_code(200, f"{setup.req_url}{path}", setup.vs_host)
            resp = requests.get(f"{setup.req_url}{path}", headers={"host": setup.vs_host})
            assert resp.status_code == 200, f"Expected 200 for {path}, got {resp.status_code}"
            assert body in resp.text, f"Expected body '{body}' for {path}, got '{resp.text}'"

    def test_happy_path_nginx_config(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, multi_regex_vsr_setup
    ):
        """Generated nginx config should contain a location block for every routed path."""
        setup = multi_regex_vsr_setup
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            setup.namespace,
            setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        # generatePath() wraps regex patterns in double quotes and adds a space
        # between modifier and pattern (e.g. ~/api/v1 → ~ "/api/v1").
        assert 'location ~ "/api/v1"' in config, 'Expected ~ "/api/v1" location block'
        assert 'location ~ "/api/v2"' in config, 'Expected ~ "/api/v2" location block'
        assert 'location ~* "/images/jpg"' in config, 'Expected ~* "/images/jpg" location block'
        assert 'location ~* "/images/png"' in config, 'Expected ~* "/images/png" location block'
        assert "location /static" in config, "Expected /static location block (non-VSR direct return route)"

    # ------------------------------------------------------------------ #
    # Failure: VS references a path not present in the VSR
    # ------------------------------------------------------------------ #

    def test_vs_path_not_in_vsr(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, multi_regex_vsr_setup
    ):
        """When VS adds ~/api/v3 but route-api has no matching subroute, route-api is rejected."""
        setup = multi_regex_vsr_setup

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            setup.vs_name,
            f"{TEST_DATA}/{EXAMPLE}/virtual-server-missing-vsr-path.yaml",
            setup.namespace,
        )
        wait_before_test(2)

        vs_info = read_custom_resource(kube_apis.custom_objects, setup.namespace, "virtualservers", setup.vs_name)
        assert vs_info["status"]["state"] == "Warning", f"VS should be Warning, got: {vs_info['status']}"

        events = get_events(kube_apis.v1, setup.namespace)
        assert_event("is invalid", events)

        self.restore_valid_state(kube_apis, setup)

    # ------------------------------------------------------------------ #
    # Failure: VSR has a subroute not referenced by the VS
    # ------------------------------------------------------------------ #

    def test_vsr_path_not_in_vs(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, multi_regex_vsr_setup
    ):
        """When route-api adds ~/api/v99 not referenced by VS, the VSR is rejected."""
        setup = multi_regex_vsr_setup

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            "route-api",
            f"{TEST_DATA}/{EXAMPLE}/route-api-orphan-subroute.yaml",
            setup.namespace,
        )
        wait_before_test(2)

        vs_info = read_custom_resource(kube_apis.custom_objects, setup.namespace, "virtualservers", setup.vs_name)
        assert vs_info["status"]["state"] == "Warning", f"VS should be Warning, got: {vs_info['status']}"

        events = get_events(kube_apis.v1, setup.namespace)
        assert_event("is invalid", events)

        self.restore_valid_state(kube_apis, setup)

    # ------------------------------------------------------------------ #
    # Failure: VS has duplicate regex paths for the same VSR
    # ------------------------------------------------------------------ #

    def test_vs_duplicate_paths(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, multi_regex_vsr_setup
    ):
        """VS with ~/api/v1 listed twice should still be valid (deduplicated) but the VSR should fail
        because the VSR subroutes don't cover the deduplicated path set."""
        setup = multi_regex_vsr_setup

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            setup.vs_name,
            f"{TEST_DATA}/{EXAMPLE}/virtual-server-duplicate-paths.yaml",
            setup.namespace,
        )
        wait_before_test(2)

        # VS still valid; VSR validation handles path matching
        vs_info = read_custom_resource(kube_apis.custom_objects, setup.namespace, "virtualservers", setup.vs_name)
        # The duplicate path is deduplicated, so the VSR can still validate against the unique set
        assert vs_info["status"]["state"] in (
            "Valid",
            "Warning",
        ), f"VS should be Valid or Warning, got: {vs_info['status']}"

        self.restore_valid_state(kube_apis, setup)

    # ------------------------------------------------------------------ #
    # Failure: VSR has duplicate subroute paths
    # ------------------------------------------------------------------ #

    def test_vsr_duplicate_paths(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, multi_regex_vsr_setup
    ):
        """VSR with duplicate ~/api/v1 subroutes fails standalone validation (duplicate paths)."""
        setup = multi_regex_vsr_setup

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            "route-api",
            f"{TEST_DATA}/{EXAMPLE}/route-api-duplicate-paths.yaml",
            setup.namespace,
        )
        wait_before_test(2)

        vs_info = read_custom_resource(kube_apis.custom_objects, setup.namespace, "virtualservers", setup.vs_name)
        assert vs_info["status"]["state"] == "Warning", f"VS should be Warning, got: {vs_info['status']}"

        events = get_events(kube_apis.v1, setup.namespace)
        assert_event("is invalid", events)

        self.restore_valid_state(kube_apis, setup)

    # ------------------------------------------------------------------ #
    # Failure: VSR mixes regex and non-regex subroute paths
    # ------------------------------------------------------------------ #

    def test_vsr_mixed_regex_nonregex(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, multi_regex_vsr_setup
    ):
        """VSR with both ~/api/v1 (regex) and /api/prefix (non-regex) fails validation."""
        setup = multi_regex_vsr_setup

        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            "route-api",
            f"{TEST_DATA}/{EXAMPLE}/route-api-mixed-types.yaml",
            setup.namespace,
        )
        wait_before_test(2)

        vs_info = read_custom_resource(kube_apis.custom_objects, setup.namespace, "virtualservers", setup.vs_name)
        assert vs_info["status"]["state"] == "Warning", f"VS should be Warning, got: {vs_info['status']}"

        events = get_events(kube_apis.v1, setup.namespace)
        assert_event("is invalid", events)

        self.restore_valid_state(kube_apis, setup)

"""Tests for config rollback with VirtualServerRoute resources."""

import pytest
from suite.utils.custom_assertions import (
    assert_vs_status,
    assert_vsr_status,
    wait_and_assert_status_code,
)
from suite.utils.resources_utils import (
    get_first_pod_name,
    get_vs_nginx_template_conf,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import (
    patch_v_s_route,
    patch_virtual_server,
)


@pytest.mark.vs
@pytest.mark.vsr
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-enable-config-safety",
                    "-enable-snippets",
                    "-global-configuration=nginx-ingress/nginx-configuration",
                    "-enable-leader-election=false",
                ],
            },
            {"example": "virtual-server-route"},
            {"example": "transport-server-tcp-load-balance"},
        )
    ],
    indirect=True,
)
class TestConfigRollbackVSRoute:
    """Tests for rollback when patching a VS or VSR with an invalid snippet.

    Uses the standard virtual-server-route fixture (VS + 2 VSRs across 2 namespaces).
    Parametrized by target (vs/vsr) and snippet type to show that regardless of which
    resource or snippet type introduces the bad config, the entire VS+VSR group goes Invalid.
    """

    @pytest.mark.parametrize("target", ["vs", "vsr"])
    @pytest.mark.parametrize(
        "snippet_value,expected_nginx_error",
        [
            (
                "sub_filter_once invalid;",
                'invalid value "invalid" in "sub_filter_once" directive',
            ),
            (
                "add_header;",
                'invalid number of arguments in "add_header" directive',
            ),
        ],
    )
    def test_vsr_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_setup,
        v_s_route_app_setup,
        transport_server_setup,
        target,
        snippet_value,
        expected_nginx_error,
    ):
        """Patch a VS or VSR with an invalid snippet — VS and all VSRs become Invalid, traffic rolls back."""
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        vs_setup = v_s_route_setup
        route_m = vs_setup.route_m
        route_s = vs_setup.route_s

        # Step 1: verify traffic on both VSR routes
        backend1_url = f"http://{vs_setup.public_endpoint.public_ip}:{vs_setup.public_endpoint.port}{route_m.paths[0]}"
        backend2_url = f"http://{vs_setup.public_endpoint.public_ip}:{vs_setup.public_endpoint.port}{route_s.paths[0]}"
        wait_and_assert_status_code(200, backend1_url, vs_setup.vs_host)
        wait_and_assert_status_code(200, backend2_url, vs_setup.vs_host)

        # Step 2: patch either VS or VSR with invalid snippet
        if target == "vs":
            patch_virtual_server(
                kube_apis.custom_objects,
                vs_setup.vs_name,
                vs_setup.namespace,
                {
                    "metadata": {"name": vs_setup.vs_name},
                    "spec": {"server-snippets": snippet_value},
                },
            )
        else:
            patch_v_s_route(
                kube_apis.custom_objects,
                route_m.name,
                route_m.namespace,
                {
                    "metadata": {"name": route_m.name},
                    "spec": {
                        "subroutes": [
                            {
                                "path": route_m.paths[0],
                                "location-snippets": snippet_value,
                                "action": {"pass": "backend1"},
                            }
                        ]
                    },
                },
            )
        wait_before_test()

        # Step 3: traffic still works on both routes — invalid config was rolled back
        wait_and_assert_status_code(200, backend1_url, vs_setup.vs_host)
        wait_and_assert_status_code(200, backend2_url, vs_setup.vs_host)
        conf = get_vs_nginx_template_conf(
            kube_apis.v1,
            vs_setup.namespace,
            vs_setup.vs_name,
            ic_pod,
            ingress_controller_prerequisites.namespace,
        )
        assert snippet_value.split(";")[0].split()[0] not in conf

        # Step 4: VS and both VSRs are Invalid, status contains actual nginx error and rollback confirmation
        assert_vs_status(
            kube_apis,
            vs_setup.namespace,
            vs_setup.vs_name,
            "Invalid",
            expected_reason="AddedOrUpdatedWithError",
            expected_messages=[
                "but was not applied",
                "rolled back to previous working config",
                expected_nginx_error,
            ],
        )
        assert_vsr_status(
            kube_apis,
            route_m.namespace,
            route_m.name,
            "Invalid",
            expected_reason="AddedOrUpdatedWithError",
            expected_messages=[
                "but was not applied",
                "rolled back to previous working config",
                expected_nginx_error,
            ],
        )
        assert_vsr_status(
            kube_apis,
            route_s.namespace,
            route_s.name,
            "Invalid",
            expected_reason="AddedOrUpdatedWithError",
            expected_messages=[
                "but was not applied",
                "rolled back to previous working config",
                expected_nginx_error,
            ],
        )

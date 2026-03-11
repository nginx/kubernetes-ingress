"""Tests for config rollback with VirtualServerRoute resources."""

import pytest
from suite.utils.custom_assertions import (
    wait_and_assert_status_code,
)
from suite.utils.resources_utils import (
    get_events_for_object,
    get_first_pod_name,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import (
    get_vs_nginx_template_conf,
    patch_v_s_route,
    patch_virtual_server,
    read_vs,
    read_vsr,
)

IC_EXTRA_ARGS = [
    "-enable-custom-resources",
    "-enable-config-rollback",
    "-enable-snippets",
    "-global-configuration=nginx-ingress/nginx-configuration",
    "-enable-leader-election=false",
]

@pytest.mark.rollback
@pytest.mark.vs
@pytest.mark.vsr
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": IC_EXTRA_ARGS,
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
    Parametrized to patch either the VS or a VSR to show that regardless of which
    resource introduces the bad config, the entire VS+VSR group goes Invalid together.
    """

    @pytest.mark.parametrize("target", ["vs", "vsr"])
    def test_vsr_rollback(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_setup,
        v_s_route_app_setup,
        transport_server_setup,
        target,
    ):
        """Patch a VS or VSR with an invalid snippet — VS and all VSRs become Invalid, traffic rolls back."""
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        vs_setup = v_s_route_setup
        route_m = vs_setup.route_m
        route_s = vs_setup.route_s

        # Step 1: verify traffic on both VSR routes
        backend1_url = (
            f"http://{vs_setup.public_endpoint.public_ip}" f":{vs_setup.public_endpoint.port}{route_m.paths[0]}"
        )
        backend2_url = (
            f"http://{vs_setup.public_endpoint.public_ip}" f":{vs_setup.public_endpoint.port}{route_s.paths[0]}"
        )
        wait_and_assert_status_code(200, backend1_url, vs_setup.vs_host)
        wait_and_assert_status_code(200, backend2_url, vs_setup.vs_host)

        # Step 2: patch either VS or VSR with invalid snippet (snippet-only directives)
        if target == "vs":
            patch_virtual_server(
                kube_apis.custom_objects,
                vs_setup.vs_name,
                vs_setup.namespace,
                {
                    "metadata": {"name": vs_setup.vs_name},
                    "spec": {"server-snippets": "sub_filter_once invalid;"},
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
                                "location-snippets": "sub_filter_once invalid;",
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
        assert "sub_filter_once" not in conf

        # Step 4: VS and both VSRs are Invalid, events contain rollback confirmation
        vs_info = read_vs(kube_apis.custom_objects, vs_setup.namespace, vs_setup.vs_name)
        assert vs_info["status"]["state"] == "Invalid"
        vsr_m_info = read_vsr(kube_apis.custom_objects, route_m.namespace, route_m.name)
        assert vsr_m_info["status"]["state"] == "Invalid"
        vsr_s_info = read_vsr(kube_apis.custom_objects, route_s.namespace, route_s.name)
        assert vsr_s_info["status"]["state"] == "Invalid"

        vs_events = get_events_for_object(kube_apis.v1, vs_setup.namespace, vs_setup.vs_name)
        latest = vs_events[-1]
        assert latest.reason == "AddedOrUpdatedWithError"
        assert "but was not applied" in latest.message
        assert "rolled back to previous working config" in latest.message
        print(latest.reason)

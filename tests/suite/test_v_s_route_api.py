import json

import pytest
import requests
from settings import NGINX_API_VERSION
from suite.utils.nginx_api_utils import get_nginx_generation_value, wait_for_empty_array, wait_for_non_empty_array
from suite.utils.resources_utils import scale_deployment


@pytest.mark.vsr
@pytest.mark.vsr_api
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": ["-enable-custom-resources", "-nginx-status-allow-cidrs=0.0.0.0/0,::/0"],
            },
            {"example": "virtual-server-route-dynamic-configuration"},
        )
    ],
    indirect=True,
)
class TestVSRNginxPlusApi:
    def test_dynamic_configuration(
        self, kube_apis, ingress_controller_endpoint, crd_ingress_controller, v_s_route_setup, v_s_route_app_setup
    ):
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.api_port}"
        vsr_s_upstream = (
            f"vs_{v_s_route_setup.namespace}_{v_s_route_setup.vs_name}_"
            f"vsr_{v_s_route_setup.route_s.namespace}_{v_s_route_setup.route_s.name}_backend2"
        )
        vsr_m_upstream = (
            f"vs_{v_s_route_setup.namespace}_{v_s_route_setup.vs_name}_"
            f"vsr_{v_s_route_setup.route_m.namespace}_{v_s_route_setup.route_m.name}_backend1"
        )
        initial_reloads_count = get_nginx_generation_value(req_url)
        upstream_servers_s_url = f"{req_url}/api/{NGINX_API_VERSION}/http/upstreams/{vsr_s_upstream}/servers"
        upstream_servers_m_url = f"{req_url}/api/{NGINX_API_VERSION}/http/upstreams/{vsr_m_upstream}/servers"
        print("Scale BE deployment")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend2", v_s_route_setup.route_s.namespace, 0)
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", v_s_route_setup.route_m.namespace, 0)
        wait_for_empty_array(upstream_servers_s_url)
        wait_for_empty_array(upstream_servers_m_url)
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend2", v_s_route_setup.route_s.namespace, 1)
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend1", v_s_route_setup.route_m.namespace, 1)
        wait_for_non_empty_array(upstream_servers_s_url)
        wait_for_non_empty_array(upstream_servers_m_url)

        print("Run checks")
        resp_s = json.loads(requests.get(upstream_servers_s_url).text)
        resp_m = json.loads(requests.get(upstream_servers_m_url).text)
        new_reloads_count = get_nginx_generation_value(req_url)
        assert new_reloads_count == initial_reloads_count, "Expected: no new reloads"
        for resp in [resp_s, resp_m]:
            assert resp[0]["max_conns"] == 32
            assert resp[0]["max_fails"] == 25
            assert resp[0]["fail_timeout"] == "15s"
            assert resp[0]["slow_start"] == "10s"

    def test_status_zone_support(
        self, kube_apis, ingress_controller_endpoint, crd_ingress_controller, v_s_route_setup, v_s_route_app_setup
    ):
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.api_port}"
        status_zone_url = f"{req_url}/api/{NGINX_API_VERSION}/http/server_zones"
        resp = json.loads(requests.get(status_zone_url).text)
        assert resp[f"{v_s_route_setup.vs_host}"]

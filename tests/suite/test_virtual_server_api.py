import json

import pytest
import requests
from settings import NGINX_API_VERSION
from suite.utils.nginx_api_utils import get_nginx_generation_value, wait_for_empty_array, wait_for_non_empty_array
from suite.utils.resources_utils import scale_deployment


@pytest.mark.vs
@pytest.mark.vs_api
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": ["-enable-custom-resources", "-nginx-status-allow-cidrs=0.0.0.0/0,::/0"],
            },
            {"example": "virtual-server-dynamic-configuration", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVSNginxPlusApi:
    def test_dynamic_configuration(
        self, kube_apis, ingress_controller_endpoint, crd_ingress_controller, virtual_server_setup
    ):
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.api_port}"
        vs_upstream = f"vs_{virtual_server_setup.namespace}_{virtual_server_setup.vs_name}_backend2"
        initial_reloads_count = get_nginx_generation_value(req_url)
        upstream_servers_url = f"{req_url}/api/{NGINX_API_VERSION}/http/upstreams/{vs_upstream}/servers"
        print("Scale BE deployment")
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend2", virtual_server_setup.namespace, 0)
        wait_for_empty_array(upstream_servers_url)
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "backend2", virtual_server_setup.namespace, 1)
        wait_for_non_empty_array(upstream_servers_url)

        print("Run checks:")
        resp = json.loads(requests.get(upstream_servers_url).text)
        new_reloads_count = get_nginx_generation_value(req_url)
        assert new_reloads_count == initial_reloads_count, "Expected: no new reloads"
        assert resp[0]["max_conns"] == 32
        assert resp[0]["max_fails"] == 25
        assert resp[0]["fail_timeout"] == "15s"
        assert resp[0]["slow_start"] == "10s"

    def test_status_zone_support(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        req_url = (
            f"http://"
            f"{virtual_server_setup.public_endpoint.public_ip}:{virtual_server_setup.public_endpoint.api_port}"
        )
        status_zone_url = f"{req_url}/api/{NGINX_API_VERSION}/http/server_zones"
        resp = json.loads(requests.get(status_zone_url).text)
        assert resp[f"{virtual_server_setup.vs_host}"]

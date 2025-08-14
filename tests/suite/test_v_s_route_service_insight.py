from unittest import mock

import pytest
import requests
from suite.utils.resources_utils import (
    ensure_response_from_backend,
    wait_before_test,
)


@pytest.mark.vsr
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-service-insight",
                ],
            },
            {"example": "virtual-server-route"},
        )
    ],
    indirect=True,
)
class TestServiceInsightVsr:
    def test_service_insight_vsr(
        self,
        kube_apis,
        ingress_controller_endpoint,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test if service insight is working with cross namespace virtual server route
        """

        retry = 0
        resp = mock.Mock()
        resp.json.return_value = {}
        resp.status_code == 502
        host = v_s_route_setup.vs_host
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.service_insight_port}/probe/{host}"
        ensure_response_from_backend(req_url, v_s_route_setup.vs_host)
        while (resp.json() != {"Total": 6, "Up": 6, "Unhealthy": 0}) and retry < 5:
            resp = requests.get(req_url)
            wait_before_test()
            retry = retry + 1

        assert resp.status_code == 200, f"Expected 200 code for /probe/{host} but got {resp.status_code}"
        assert resp.json() == {"Total": 6, "Up": 6, "Unhealthy": 0}

from unittest import mock

import pytest
import requests
from settings import TEST_DATA
from suite.utils.resources_utils import create_secret_from_yaml, wait_before_test
from suite.utils.ssl_utils import create_sni_session


@pytest.mark.vsr
@pytest.mark.vsr_secrets
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-watch-namespace=nginx-ingress,backends,backend2-namespace",
                    f"-watch-secret-namespace=backends",
                ],
            },
            {"example": "watch-secret-namespace"},
        )
    ],
    indirect=True,
)
class TestVSRWatchSecretNamespacesValid:
    def test_responses(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_setup,
        v_s_route_app_setup,
    ):
        """Creates 3 tests 1). watching specific ns and secret ns, 2). watching only specific secret ns, 3). watching all ns"""
        src_vs_sec_yaml = f"{TEST_DATA}/watch-secret-namespace/tls-secret.yaml"
        create_secret_from_yaml(kube_apis.v1, "backends", src_vs_sec_yaml)
        req_url = f"https://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port_ssl}"
        session = create_sni_session()
        exception = ""
        resp = mock.Mock()
        resp.status_code = "None"
        resp.text = "None"
        retry = 0
        while resp.status_code == "None" and retry < 10:
            wait_before_test()
            try:
                resp = session.get(
                    f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                    headers={"host": v_s_route_setup.vs_host},
                    allow_redirects=False,
                    verify=False,
                )
            except requests.exceptions.SSLError as e:
                exception = str(e)
                print(f"SSL certificate exception: {exception}")
            retry = retry + 1

        assert resp.status_code == 200


@pytest.mark.vsr
@pytest.mark.vsr_secrets
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-watch-namespace=nginx-ingress,backends,backend2-namespace",
                    f"-watch-secret-namespace=invalid",
                ],
            },
            {"example": "watch-secret-namespace"},
        )
    ],
    indirect=True,
)
class TestVSRWatchSecretNamespacesInvalid:
    def test_responses(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_setup,
        v_s_route_app_setup,
    ):
        """Creates 2 tests 1). watching specific ns and invalid secret ns, 2). watching only invalid secret ns"""
        src_vs_sec_yaml = f"{TEST_DATA}/watch-secret-namespace/tls-secret.yaml"
        create_secret_from_yaml(kube_apis.v1, "backends", src_vs_sec_yaml)
        req_url = f"https://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port_ssl}"
        session = create_sni_session()
        exception = ""
        wait_before_test()
        try:
            resp = session.get(
                f"{req_url}{v_s_route_setup.route_m.paths[0]}",
                headers={"host": v_s_route_setup.vs_host},
                allow_redirects=False,
                verify=False,
            )
        except requests.exceptions.SSLError as e:
            exception = str(e)
            print(f"SSL certificate exception: {exception}")
            resp = mock.Mock()
            resp.status_code = "None"
            resp.text = "None"
        assert "[SSL: TLSV1_UNRECOGNIZED_NAME]" in exception and "None" in resp.status_code

import pytest
import requests
import yaml
from settings import TEST_DATA
from suite.utils.resources_utils import ensure_response_from_backend


def get_weights_of_splitting(file) -> []:
    """
    Parse yaml file into an array of weights.

    :param file: an absolute path to file
    :return: []
    """
    weights = []
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            for item in dep["spec"]["routes"][0]["matches"][0]["splits"]:
                weights.append(item["weight"])
    return weights


def get_upstreams_of_splitting(file) -> []:
    """
    Parse yaml file into an array of upstreams.

    :param file: an absolute path to file
    :return: []
    """
    upstreams = []
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            for item in dep["spec"]["routes"][0]["matches"][0]["splits"]:
                upstreams.append(item["action"]["pass"])
    return upstreams


@pytest.mark.vs
@pytest.mark.vs_canary
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-focused-canary", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVSFocusedCanaryRelease:
    def test_several_requests(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        weights = get_weights_of_splitting(f"{TEST_DATA}/virtual-server-focused-canary/standard/virtual-server.yaml")
        upstreams = get_upstreams_of_splitting(
            f"{TEST_DATA}/virtual-server-focused-canary/standard/virtual-server.yaml"
        )
        sum_weights = sum(weights)
        ratios = [round(i / sum_weights, 1) for i in weights]

        counter_v1, counter_v2 = 0, 0
        for _ in range(100):
            ensure_response_from_backend(
                virtual_server_setup.backend_1_url, virtual_server_setup.vs_host, {"x-version": "canary"}, check404=True
            )
            status_code = 502
            while status_code == 502:
                resp = requests.get(
                    virtual_server_setup.backend_1_url,
                    headers={"host": virtual_server_setup.vs_host, "x-version": "canary"},
                )
                status_code = resp.status_code

            if upstreams[0] in resp.text in resp.text:
                counter_v1 = counter_v1 + 1
            elif upstreams[1] in resp.text in resp.text:
                counter_v2 = counter_v2 + 1
            else:
                pytest.fail(f"An unexpected backend in response: {resp.text}")

        assert abs(round(counter_v1 / (counter_v1 + counter_v2), 1) - ratios[0]) <= 0.2
        assert abs(round(counter_v2 / (counter_v1 + counter_v2), 1) - ratios[1]) <= 0.2

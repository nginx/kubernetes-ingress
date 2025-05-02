import pytest
import requests
import yaml
from settings import TEST_DATA
from suite.utils.resources_utils import ensure_response_from_backend
from suite.utils.yaml_utils import get_paths_from_vsr_yaml
from yaml.loader import Loader


def get_weights_of_splitting(file) -> []:
    """
    Parse VSR yaml file into an array of weights.

    :param file: an absolute path to file
    :return: []
    """
    weights = []
    with open(file) as f:
        docs = yaml.load_all(f, Loader=Loader)
        for dep in docs:
            for item in dep["spec"]["subroutes"][0]["splits"]:
                weights.append(item["weight"])
    return weights


def get_upstreams_of_splitting(file) -> []:
    """
    Parse VSR yaml file into an array of upstreams.

    :param file: an absolute path to file
    :return: []
    """
    upstreams = []
    with open(file) as f:
        docs = yaml.load_all(f, Loader=Loader)
        for dep in docs:
            for item in dep["spec"]["subroutes"][0]["splits"]:
                upstreams.append(item["action"]["pass"])
    return upstreams


@pytest.mark.vsr
@pytest.mark.vsr_splits
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-route-split-traffic"},
        )
    ],
    indirect=True,
)
class TestVSRTrafficSplitting:
    def test_several_requests(self, kube_apis, crd_ingress_controller, v_s_route_setup, v_s_route_app_setup):
        split_path = get_paths_from_vsr_yaml(f"{TEST_DATA}/virtual-server-route-split-traffic/route-multiple.yaml")
        req_url = (
            f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}{split_path[0]}"
        )
        weights = get_weights_of_splitting(f"{TEST_DATA}/virtual-server-route-split-traffic/route-multiple.yaml")
        upstreams = get_upstreams_of_splitting(f"{TEST_DATA}/virtual-server-route-split-traffic/route-multiple.yaml")
        sum_weights = sum(weights)
        ratios = [round(i / sum_weights, 1) for i in weights]

        counter_v1, counter_v2 = 0, 0
        for _ in range(100):
            ensure_response_from_backend(req_url, v_s_route_setup.vs_host)
            status_code = 502
            while status_code == 502:
                resp = requests.get(req_url, headers={"host": v_s_route_setup.vs_host})
                status_code = resp.status_code
                if status_code == 502:
                    print("Backend is not ready yet, skip.")
            if upstreams[0] in resp.text in resp.text:
                counter_v1 = counter_v1 + 1
            elif upstreams[1] in resp.text in resp.text:
                counter_v2 = counter_v2 + 1
            else:
                pytest.fail(f"An unexpected response: {resp.text}")

        assert abs(round(counter_v1 / (counter_v1 + counter_v2), 1) - ratios[0]) <= 0.2
        assert abs(round(counter_v2 / (counter_v1 + counter_v2), 1) - ratios[1]) <= 0.2

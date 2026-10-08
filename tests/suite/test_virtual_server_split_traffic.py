import pytest
import requests
import yaml
from settings import TEST_DATA
from suite.utils.custom_resources_utils import generate_item_with_upstream_options
from suite.utils.resources_utils import ensure_response_from_backend, replace_configmap, wait_before_test
from suite.utils.vs_vsr_resources_utils import patch_virtual_server, patch_virtual_server_from_yaml


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
            for item in dep["spec"]["routes"][0]["splits"]:
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
            for item in dep["spec"]["routes"][0]["splits"]:
                upstreams.append(item["action"]["pass"])
    return upstreams


@pytest.mark.vs
@pytest.mark.smoke
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-split-traffic", "app_type": "split"},
        )
    ],
    indirect=True,
)
class TestTrafficSplitting:
    def test_several_requests(self, kube_apis, crd_ingress_controller, virtual_server_setup):
        weights = get_weights_of_splitting(f"{TEST_DATA}/virtual-server-split-traffic/standard/virtual-server.yaml")
        upstreams = get_upstreams_of_splitting(f"{TEST_DATA}/virtual-server-split-traffic/standard/virtual-server.yaml")
        sum_weights = sum(weights)
        ratios = [round(i / sum_weights, 1) for i in weights]

        counter_v1, counter_v2 = 0, 0
        for _ in range(100):
            ensure_response_from_backend(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)
            status_code = 502
            while status_code == 502:
                resp = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
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

    @pytest.mark.parametrize(
        "limit_source, small_body, large_body",
        [
            pytest.param("unset", 500 * 1024, 2 * 1024 * 1024, id="unset-1m-default"),
            pytest.param("vs-spec", 2 * 1024 * 1024, 4 * 1024 * 1024, id="vs-spec-3m"),
            pytest.param("nic-configmap", 2 * 1024 * 1024, 4 * 1024 * 1024, id="nic-configmap-3m"),
        ],
    )
    def test_large_body(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        restore_configmap,
        limit_source,
        small_body,
        large_body,
    ):
        """
        The body limit of the route must apply to the splits' children, whatever the size of the body.

        The default 1m must not be applied before the request reaches them, so a body larger than
        1m but smaller than the configured limit is accepted, and a body larger than the limit is not.
        The backends accept any body, so a 413 can only come from NGINX Ingress Controller.
        All the splits have the same limit, so it does not matter which one a request is sent to.
        """
        if limit_source == "vs-spec":
            body = generate_item_with_upstream_options(
                f"{TEST_DATA}/virtual-server-split-traffic/standard/virtual-server.yaml", {"client-max-body-size": "3m"}
            )
            patch_virtual_server(
                kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace, body
            )
        else:
            patch_virtual_server_from_yaml(
                kube_apis.custom_objects,
                virtual_server_setup.vs_name,
                f"{TEST_DATA}/virtual-server-split-traffic/standard/virtual-server.yaml",
                virtual_server_setup.namespace,
            )
        if limit_source == "nic-configmap":
            config_map = ingress_controller_prerequisites.config_map.copy()
            config_map["data"] = {"client-max-body-size": "3m"}
            replace_configmap(
                kube_apis.v1,
                config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                config_map,
            )
        wait_before_test()
        ensure_response_from_backend(virtual_server_setup.backend_1_url, virtual_server_setup.vs_host)

        headers = {"host": virtual_server_setup.vs_host}
        for _ in range(10):
            resp = requests.post(virtual_server_setup.backend_1_url, headers=headers, data=b"x" * small_body)
            assert resp.status_code == 200, f"{small_body} bytes"
            assert "Server name: backend1-" in resp.text

            resp = requests.post(virtual_server_setup.backend_1_url, headers=headers, data=b"x" * large_body)
            assert resp.status_code == 413, f"{large_body} bytes"

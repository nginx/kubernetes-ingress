import json
import os
import re
import subprocess
from datetime import datetime

import pytest
import requests
import yaml
from kubernetes.client import V1ContainerPort
from settings import TEST_DATA
from suite.utils.ap_resources_utils import (
    create_ap_logconf_from_yaml,
    create_ap_policy_from_yaml,
    delete_ap_logconf,
    delete_ap_policy,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress,
    create_ingress_with_ap_annotations,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    get_resource_metrics,
    replace_ingress_with_ap_annotations,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

ap_policy = "dataguard-alarm"
valid_resp_addr = "Server address:"
valid_resp_name = "Server name:"
invalid_resp_title = "Request Rejected"
invalid_resp_body = "The requested URL was rejected. Please consult with your administrator."
reload_ap = []
reload_ap_path = []
reload_ap_with_ingress = []


class AppProtectSetup:
    """
    Encapsulate the example details.
    Attributes:
        req_url (str):
    """

    def __init__(self, req_url):
        self.req_url = req_url


@pytest.fixture(scope="class")
def enable_prometheus_port(
    cli_arguments, kube_apis, ingress_controller_prerequisites, crd_ingress_controller_with_ap
) -> None:
    namespace = ingress_controller_prerequisites.namespace
    port = V1ContainerPort(9113, None, None, "prometheus", "TCP")
    print("------------------------- Enable 9113 port in IC ----------------------------")
    body = kube_apis.apps_v1_api.read_namespaced_deployment("nginx-ingress", namespace)
    body.spec.template.spec.containers[0].ports.append(port)
    kube_apis.apps_v1_api.patch_namespaced_deployment("nginx-ingress", namespace, body)
    wait_until_all_pods_are_ready(kube_apis.v1, namespace)


@pytest.fixture(scope="class")
def appprotect_setup(
    request, kube_apis, ingress_controller_prerequisites, ingress_controller_endpoint, test_namespace
) -> AppProtectSetup:
    """
    Deploy simple application and all the AppProtect(dataguard-alarm) resources under test in one namespace.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :param test_namespace:
    :return: BackendSetup
    """

    print("------------------------- Deploy simple backend application -------------------------")
    create_example_app(kube_apis, "simple", test_namespace)
    req_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )

    print("------------------------- Deploy Secret -----------------------------")
    src_sec_yaml = f"{TEST_DATA}/appprotect/appprotect-secret.yaml"
    create_items_from_yaml(kube_apis, src_sec_yaml, test_namespace)

    print("------------------------- Deploy logconf -----------------------------")
    src_log_yaml = f"{TEST_DATA}/appprotect/logconf.yaml"
    log_name = create_ap_logconf_from_yaml(kube_apis.custom_objects, src_log_yaml, test_namespace)

    print(f"------------------------- Deploy dataguard-alarm appolicy ---------------------------")
    src_pol_yaml = f"{TEST_DATA}/appprotect/{ap_policy}.yaml"
    pol_name = create_ap_policy_from_yaml(kube_apis.custom_objects, src_pol_yaml, test_namespace)

    def fin():
        print("Clean up:")
        print("Collect resource usage metrics")
        pod_metrics = get_resource_metrics(kube_apis.custom_objects, "pods", ingress_controller_prerequisites.namespace)
        with open("ap_pod_metrics.json", "w+") as f:
            json.dump(pod_metrics, f, ensure_ascii=False, indent=4)
        node_metrics = get_resource_metrics(
            kube_apis.custom_objects, "nodes", ingress_controller_prerequisites.namespace
        )
        with open("ap_node_metrics.json", "w+") as f:
            json.dump(node_metrics, f, ensure_ascii=False, indent=4)

        delete_ap_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_ap_logconf(kube_apis.custom_objects, log_name, test_namespace)
        delete_common_app(kube_apis, "simple", test_namespace)
        src_sec_yaml = f"{TEST_DATA}/appprotect/appprotect-secret.yaml"
        delete_items_from_yaml(kube_apis, src_sec_yaml, test_namespace)
        with open("reload_ap.json", "w+") as f:
            json.dump(reload_ap, f, ensure_ascii=False, indent=4)
        with open("reload_ap_path.json", "w+") as f:
            json.dump(reload_ap_path, f, ensure_ascii=False, indent=4)
        with open("reload_ap_with_ingress.json", "w+") as f:
            json.dump(reload_ap_with_ingress, f, ensure_ascii=False, indent=4)

    request.addfinalizer(fin)

    return AppProtectSetup(req_url)


@pytest.fixture
def setup_users(request):
    return request.config.getoption("--users")


@pytest.fixture
def setup_rate(request):
    return request.config.getoption("--hatch-rate")


@pytest.fixture
def setup_time(request):
    return request.config.getoption("--time")


def assert_invalid_responses(response) -> None:
    """
    Assert responses when policy config is blocking requests
    :param response: Response
    """
    assert invalid_resp_title in response.text
    assert invalid_resp_body in response.text
    assert response.status_code == 200


@pytest.mark.ap_perf
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
    [
        {
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-app-protect",
                f"-enable-prometheus-metrics",
            ]
        }
    ],
    indirect=["crd_ingress_controller_with_ap"],
)
class TestAppProtectPerf:
    def collect_prom_reload_metrics(self, metric_list, scenario, ip, port) -> None:
        req_url = f"http://{ip}:{port}/metrics"
        resp = requests.get(req_url)
        resp_decoded = resp.content.decode("utf-8")
        reload_metric = ""
        for line in resp_decoded.splitlines():
            if "last_reload_milliseconds{class" in line:
                reload_metric = re.findall(r"\d+", line)[0]
                metric_list.append(
                    {
                        f"Reload time ({scenario}) ": f"{reload_metric}ms",
                        "TimeStamp": str(datetime.utcnow()),
                    }
                )

    def test_ap_perf_create_ingress(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller_with_ap,
        appprotect_setup,
        enable_prometheus_port,
        test_namespace,
    ):
        """
        Test reload times for creating AP ingress
        """

        src_ing_yaml = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"
        create_ingress_with_ap_annotations(
            kube_apis, src_ing_yaml, test_namespace, ap_policy, "True", "True", "127.0.0.1:514"
        )
        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

        print("--------- Run test while AppProtect module is enabled with correct policy ---------")
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host)
        wait_before_test(40)
        response = requests.get(appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False)
        print(response.text)
        self.collect_prom_reload_metrics(
            reload_ap,
            "creating AP ingress",
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.metrics_port,
        )
        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
        assert_invalid_responses(response)

    def test_ap_perf_ingress_path_change(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller_with_ap,
        appprotect_setup,
        enable_prometheus_port,
        test_namespace,
    ):
        """
        Test reload times for changing paths
        """

        src1_ing_yaml = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"
        print(src1_ing_yaml)
        src2_ing_yaml = os.path.join(os.path.dirname(__file__), "../data/appprotect-ingress.yaml")
        print(src2_ing_yaml)
        create_ingress_with_ap_annotations(
            kube_apis, src1_ing_yaml, test_namespace, ap_policy, "True", "True", "127.0.0.1:514"
        )
        ingress_host = get_first_ingress_host_from_yaml(src1_ing_yaml)

        print("--------- Run test while AppProtect module is enabled with correct policy ---------")
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host)
        wait_before_test(30)
        replace_ingress_with_ap_annotations(
            kube_apis,
            src2_ing_yaml,
            "appprotect-ingress",
            test_namespace,
            ap_policy,
            "True",
            "True",
            "127.0.0.1:514",
        )
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host)
        wait_before_test(30)
        response = ""
        response = requests.get(appprotect_setup.req_url + "/v1/<script>", headers={"host": ingress_host}, verify=False)
        print(response.text)
        self.collect_prom_reload_metrics(
            reload_ap_path,
            "changing paths in AP ingress",
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.metrics_port,
        )
        delete_items_from_yaml(kube_apis, src2_ing_yaml, test_namespace)
        assert_invalid_responses(response)

    def test_ap_perf_multiple_ingress(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller_with_ap,
        appprotect_setup,
        enable_prometheus_port,
        test_namespace,
    ):
        """
        Test reload times for creating AP ingress while a simple ingress exists.
        """

        src1_ing_yaml = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"
        print(src1_ing_yaml)
        src2_ing_yaml = os.path.join(os.path.dirname(__file__), "../data/non-ap-ingress.yaml")
        print(src2_ing_yaml)

        with open(src2_ing_yaml) as f:
            doc = yaml.safe_load(f)
        # create ingress without AP annotation
        create_ingress(kube_apis.networking_v1, test_namespace, doc)
        wait_before_test(10)
        #  create ingress with AP annotations
        create_ingress_with_ap_annotations(
            kube_apis, src1_ing_yaml, test_namespace, ap_policy, "True", "True", "127.0.0.1:514"
        )
        ingress_host = get_first_ingress_host_from_yaml(src1_ing_yaml)

        print("--------- Run test while AppProtect module is enabled with correct policy ---------")
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host)
        wait_before_test(30)
        response = requests.get(appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False)
        print(response.text)
        self.collect_prom_reload_metrics(
            reload_ap_with_ingress,
            "creating AP ingress alongside a simple ingress",
            ingress_controller_endpoint.public_ip,
            ingress_controller_endpoint.metrics_port,
        )
        delete_items_from_yaml(kube_apis, src1_ing_yaml, test_namespace)
        delete_items_from_yaml(kube_apis, src2_ing_yaml, test_namespace)
        assert_invalid_responses(response)

    @pytest.mark.ap_resp
    def test_ap_perf_response(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        crd_ingress_controller_with_ap,
        appprotect_setup,
        enable_prometheus_port,
        test_namespace,
        setup_users,
        setup_time,
        setup_rate,
    ):
        """
        Test response times for AP ingress by running locust as a subprocess.
        """

        src_ing_yaml = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"
        print(src_ing_yaml)

        #  create ingress with AP annotations
        create_ingress_with_ap_annotations(
            kube_apis, src_ing_yaml, test_namespace, ap_policy, "True", "True", "127.0.0.1:514"
        )
        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

        print("--------- Run test while AppProtect module is enabled with correct policy ---------")
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host)
        wait_before_test(30)
        response = ""
        response = requests.get(appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False)
        print(appprotect_setup.req_url + "/<script>")
        print(ingress_host)
        print(response.text)
        # run response time tests using locust.io
        subprocess.run(
            [
                "locust",
                "-f",
                "suite/ap_request_perf.py",
                "--headless",
                "--host",
                appprotect_setup.req_url,
                "--csv",
                "ap_response_times",
                "-u",
                setup_users,  # total no. of users
                "-r",
                setup_rate,  # no. of users hatched per second
                "-t",
                setup_time,  # locust session duration in seconds
            ]
        )
        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
        assert_invalid_responses(response)

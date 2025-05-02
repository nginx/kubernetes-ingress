import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import (
    create_gc_from_yaml,
    create_ts_from_yaml,
    delete_gc,
    delete_ts,
    patch_ts,
    patch_ts_from_yaml,
)
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_secret,
    ensure_connection,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml


class IngressSetup:
    """
    Encapsulate the Smoke Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        ingress_host (str):
    """

    def __init__(self, req_url, ingress_host):
        self.req_url = req_url
        self.ingress_host = ingress_host


@pytest.fixture(scope="class")
def prometheus_secret_setup(request, kube_apis, test_namespace):
    print("------------------------- Deploy Prometheus Secret -----------------------------------")
    prometheus_secret_name = create_secret_from_yaml(
        kube_apis.v1, "nginx-ingress", f"{TEST_DATA}/prometheus/secret.yaml"
    )

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            delete_secret(kube_apis.v1, prometheus_secret_name, "nginx-ingress")

    request.addfinalizer(fin)


@pytest.fixture(scope="class")
def ingress_setup(request, kube_apis, ingress_controller_endpoint, test_namespace) -> IngressSetup:
    print("------------------------- Deploy Ingress Example -----------------------------------")
    secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, f"{TEST_DATA}/smoke/smoke-secret.yaml")
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml", test_namespace)
    ingress_host = get_first_ingress_host_from_yaml(f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml")
    create_example_app(kube_apis, "simple", test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )
    req_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up simple app")
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(kube_apis, f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml", test_namespace)
            delete_secret(kube_apis.v1, secret_name, test_namespace)

    request.addfinalizer(fin)

    return IngressSetup(req_url, ingress_host)


@pytest.mark.ingresses
@pytest.mark.smoke
class TestPrometheusExporter:
    @pytest.mark.parametrize(
        "ingress_controller, expected_metrics",
        [
            pytest.param(
                {"extra_args": ["-enable-prometheus-metrics"]},
                [
                    'nginx_ingress_controller_nginx_reload_errors_total{class="nginx"} 0',
                    'nginx_ingress_controller_ingress_resources_total{class="nginx",type="master"} 0',
                    'nginx_ingress_controller_ingress_resources_total{class="nginx",type="minion"} 0',
                    'nginx_ingress_controller_ingress_resources_total{class="nginx",type="regular"} 1',
                    "nginx_ingress_controller_nginx_last_reload_milliseconds",
                    'nginx_ingress_controller_nginx_last_reload_status{class="nginx"} 1',
                    'nginx_ingress_controller_nginx_reload_errors_total{class="nginx"} 0',
                    'nginx_ingress_controller_nginx_reloads_total{class="nginx",reason="endpoints"}',
                    'nginx_ingress_controller_nginx_reloads_total{class="nginx",reason="other"}',
                    'nginx_ingress_controller_workqueue_depth{class="nginx",name="taskQueue"}',
                    'nginx_ingress_controller_workqueue_queue_duration_seconds_bucket{class="nginx",name="taskQueue",le=',
                    'nginx_ingress_controller_workqueue_queue_duration_seconds_sum{class="nginx",name="taskQueue"}',
                    'nginx_ingress_controller_workqueue_queue_duration_seconds_count{class="nginx",name="taskQueue"}',
                ],
            )
        ],
        indirect=["ingress_controller"],
    )
    def test_metrics(
        self,
        ingress_controller_endpoint,
        ingress_controller,
        expected_metrics,
        ingress_setup,
    ):
        ensure_connection(ingress_setup.req_url, 200, {"host": ingress_setup.ingress_host})
        resp = requests.get(ingress_setup.req_url, headers={"host": ingress_setup.ingress_host}, verify=False)
        assert resp.status_code == 200
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
        ensure_connection(req_url, 200)
        resp = requests.get(req_url)
        assert resp.status_code == 200, f"Expected 200 code for /metrics but got {resp.status_code}"
        resp_content = resp.content.decode("utf-8")
        for item in expected_metrics:
            assert item in resp_content

    @pytest.mark.parametrize(
        "ingress_controller, expected_metrics",
        [
            pytest.param(
                {"extra_args": ["-enable-prometheus-metrics", "-enable-latency-metrics"]},
                [
                    'nginx_ingress_controller_upstream_server_response_latency_ms_bucket{class="nginx",code="200",pod_name=',
                    'nginx_ingress_controller_upstream_server_response_latency_ms_sum{class="nginx",code="200",pod_name=',
                    'nginx_ingress_controller_upstream_server_response_latency_ms_count{class="nginx",code="200",pod_name=',
                    'nginx_ingress_controller_ingress_resources_total{class="nginx",type="regular"} 1',
                ],
            )
        ],
        indirect=["ingress_controller"],
    )
    def test_latency_metrics(
        self,
        ingress_controller_endpoint,
        ingress_controller,
        expected_metrics,
        ingress_setup,
    ):
        ensure_connection(ingress_setup.req_url, 200, {"host": ingress_setup.ingress_host})
        resp = requests.get(ingress_setup.req_url, headers={"host": ingress_setup.ingress_host}, verify=False)
        assert resp.status_code == 200
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
        ensure_connection(req_url, 200)
        resp = requests.get(req_url)
        assert resp.status_code == 200, f"Expected 200 code for /metrics but got {resp.status_code}"
        resp_content = resp.content.decode("utf-8")
        for item in expected_metrics:
            assert item in resp_content

    @pytest.mark.parametrize(
        "ingress_controller, expected_metrics",
        [
            pytest.param(
                {
                    "extra_args": [
                        "-enable-prometheus-metrics",
                        "-enable-latency-metrics",
                        "-prometheus-tls-secret=nginx-ingress/tls-secret",
                    ]
                },
                [
                    'nginx_ingress_controller_ingress_resources_total{class="nginx",type="master"} 0',
                    'nginx_ingress_controller_ingress_resources_total{class="nginx",type="minion"} 0',
                ],
            )
        ],
        indirect=["ingress_controller"],
    )
    def test_https_metrics(
        self,
        prometheus_secret_setup,
        ingress_controller_endpoint,
        ingress_controller,
        expected_metrics,
        ingress_setup,
    ):
        # assert http fails
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
        ensure_connection(req_url, 400)
        resp = requests.get(req_url, verify=False)
        assert (
            "Client sent an HTTP request to an HTTPS server" in resp.text and resp.status_code == 400
        ), f"Expected 400 code for http request to /metrics and got {resp.status_code}"

        # assert https succeeds
        req_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
        ensure_response_from_backend(req_url, ingress_setup.ingress_host)
        resp = requests.get(req_url, verify=False)

        assert resp.status_code == 200, f"Expected 200 code for /metrics but got {resp.status_code}"

        resp_content = resp.content.decode("utf-8")
        for item in expected_metrics:
            assert item in resp_content


@pytest.fixture(scope="class")
def ts_setup(request, kube_apis, crd_ingress_controller):
    global_config_file = f"{TEST_DATA}/prometheus/transport-server/global-configuration.yaml"

    gc_resource = create_gc_from_yaml(kube_apis.custom_objects, global_config_file, "nginx-ingress")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            delete_gc(kube_apis.custom_objects, gc_resource, "nginx-ingress")

    request.addfinalizer(fin)


def assert_ts_total_metric(ingress_controller_endpoint, ts_type, value):
    req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
    resp = requests.get(req_url)
    resp_content = resp.content.decode("utf-8")

    assert resp.status_code == 200, f"Expected 200 code for /metrics but got {resp.status_code}"
    assert (
        f'nginx_ingress_controller_transportserver_resources_total{{class="nginx",type="{ts_type}"}} {value}'
        in resp_content
    )


@pytest.mark.ts
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        pytest.param(
            {
                "type": "complete",
                "extra_args": [
                    "-global-configuration=nginx-ingress/nginx-configuration",
                    "-enable-tls-passthrough",
                    "-enable-prometheus-metrics",
                ],
            },
        )
    ],
    indirect=True,
)
class TestTransportServerMetrics:
    @pytest.mark.parametrize(
        "ts",
        [
            (f"{TEST_DATA}/prometheus/transport-server/passthrough.yaml", "passthrough"),
            (f"{TEST_DATA}/prometheus/transport-server/tcp.yaml", "tcp"),
            (f"{TEST_DATA}/prometheus/transport-server/udp.yaml", "udp"),
        ],
    )
    def test_total_metrics(
        self, crd_ingress_controller, ts_setup, ingress_controller_endpoint, kube_apis, test_namespace, ts
    ):
        """
        Tests nginx_ingress_controller_transportserver_resources_total metric for a given TransportServer type.
        """
        ts_file = ts[0]
        ts_type = ts[1]

        # initially, the number of TransportServers is 0

        assert_ts_total_metric(ingress_controller_endpoint, ts_type, 0)

        # create a TS and check the metric is 1

        ts_resource = create_ts_from_yaml(kube_apis.custom_objects, ts_file, test_namespace)
        wait_before_test()

        assert_ts_total_metric(ingress_controller_endpoint, ts_type, 1)

        # make the TS invalid and check the metric is 0

        ts_resource["spec"]["listener"]["protocol"] = "invalid"

        patch_ts(kube_apis.custom_objects, test_namespace, ts_resource)
        wait_before_test()

        assert_ts_total_metric(ingress_controller_endpoint, ts_type, 0)

        # restore the TS and check the metric is 1

        patch_ts_from_yaml(kube_apis.custom_objects, ts_resource["metadata"]["name"], ts_file, test_namespace)
        wait_before_test()

        assert_ts_total_metric(ingress_controller_endpoint, ts_type, 1)

        # delete the TS and check the metric is 0

        delete_ts(kube_apis.custom_objects, ts_resource, test_namespace)
        wait_before_test()

        assert_ts_total_metric(ingress_controller_endpoint, ts_type, 0)


@pytest.mark.ingresses
@pytest.mark.smoke
@pytest.mark.skip_for_nginx_oss
class TestPrometheusExporterPlus:
    @pytest.mark.parametrize(
        "ingress_controller, expected_metrics",
        [
            pytest.param(
                {"extra_args": ["-enable-prometheus-metrics", "-enable-oidc"]},
                [
                    'nginx_ingress_nginxplus_cache_bypass_bytes{class="nginx",zone="jwk"}',
                    'nginx_ingress_nginxplus_cache_expired_bytes{class="nginx",zone="jwk"}',
                    'nginx_ingress_nginxplus_cache_hit_responses{class="nginx",zone="jwk"}',
                    'nginx_ingress_nginxplus_cache_miss_responses{class="nginx",zone="jwk"}',
                    'nginx_ingress_nginxplus_cache_size{class="nginx",zone="jwk"}',
                    'nginxplus_worker_connection_accepted{class="nginx"',
                    'nginxplus_worker_connection_active{class="nginx"',
                    'nginxplus_worker_http_requests_total{class="nginx"',
                ],
            )
        ],
        indirect=["ingress_controller"],
    )
    def test_plus_metrics(
        self,
        ingress_controller_endpoint,
        ingress_controller,
        expected_metrics,
        ingress_setup,
    ):
        ensure_connection(ingress_setup.req_url, 200, {"host": ingress_setup.ingress_host})
        resp = requests.get(ingress_setup.req_url, headers={"host": ingress_setup.ingress_host}, verify=False)
        assert resp.status_code == 200
        req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
        ensure_connection(req_url, 200)
        resp = requests.get(req_url)
        assert resp.status_code == 200, f"Expected 200 code for /metrics but got {resp.status_code}"
        resp_content = resp.content.decode("utf-8")
        for item in expected_metrics:
            assert item in resp_content

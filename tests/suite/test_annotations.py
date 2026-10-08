import pytest
import yaml
from kubernetes.client import NetworkingV1Api
from settings import DEPLOYMENTS, TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.custom_assertions import assert_event_count_increased, assert_h2c_grpc_hello
from suite.utils.resources_utils import (
    IC_SELECTOR,
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    generate_e2e_run_id,
    generate_ingresses_with_annotation,
    get_e2e_run_selector,
    get_events,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    get_nginx_template_conf,
    read_service,
    replace_configmap_from_yaml,
    replace_ingress,
    replace_service,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml, get_name_from_yaml


def get_event_count(event_text, events_list) -> int:
    for i in range(len(events_list) - 1, -1, -1):
        if event_text in events_list[i].message:
            return events_list[i].count
    return 0


def replace_ingresses_from_yaml(networking_v1: NetworkingV1Api, namespace, yaml_manifest) -> None:
    """
    Parse file and replace all Ingresses based on its contents.

    :param networking_v1: NetworkingV1Api
    :param namespace: namespace
    :param yaml_manifest: an absolute path to a file
    :return:
    """
    print(f"Replace an Ingresses from yaml")
    with open(yaml_manifest) as f:
        docs = yaml.safe_load_all(f)
        for doc in docs:
            if doc["kind"] == "Ingress":
                replace_ingress(networking_v1, doc["metadata"]["name"], namespace, doc)


def get_minions_info_from_yaml(file) -> []:
    """
    Parse yaml file and return minions details.

    :param file: an absolute path to file
    :return: [{name, svc_name}]
    """
    res = []
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            if "minion" in dep["metadata"]["name"]:
                res.append(
                    {
                        "name": dep["metadata"]["name"],
                        "svc_name": dep["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"],
                    }
                )
    return res


class AnnotationsSetup:
    """Encapsulate Annotations example details.

    Attributes:
        public_endpoint: PublicEndpoint
        ingress_name:
        ingress_pod_name:
        ingress_host:
        namespace: example namespace
    """

    def __init__(
        self,
        public_endpoint: PublicEndpoint,
        ingress_src_file,
        ingress_name,
        ingress_host,
        ingress_pod_name,
        namespace,
        ingress_event_text,
        ingress_error_event_text,
        upstream_names=None,
    ):
        self.public_endpoint = public_endpoint
        self.ingress_name = ingress_name
        self.ingress_pod_name = ingress_pod_name
        self.namespace = namespace
        self.ingress_host = ingress_host
        self.ingress_src_file = ingress_src_file
        self.ingress_event_text = ingress_event_text
        self.ingress_error_event_text = ingress_error_event_text
        self.upstream_names = upstream_names


@pytest.fixture(scope="class")
def annotations_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    ingress_controller,
    test_namespace,
) -> AnnotationsSetup:
    print("------------------------- Deploy Annotations-Example -----------------------------------")
    e2e_run_id = generate_e2e_run_id()
    if request.param == "grpc":
        create_items_from_yaml(kube_apis, f"{TEST_DATA}/annotations/{request.param}/grpc-secret.yaml", test_namespace)
    create_items_from_yaml(
        kube_apis, f"{TEST_DATA}/annotations/{request.param}/annotations-ingress.yaml", test_namespace
    )
    ingress_name = get_name_from_yaml(f"{TEST_DATA}/annotations/{request.param}/annotations-ingress.yaml")
    ingress_host = get_first_ingress_host_from_yaml(f"{TEST_DATA}/annotations/{request.param}/annotations-ingress.yaml")
    if request.param == "mergeable":
        minions_info = get_minions_info_from_yaml(f"{TEST_DATA}/annotations/{request.param}/annotations-ingress.yaml")
    else:
        minions_info = None

    create_example_app(kube_apis, "simple", test_namespace, e2e_run_id=e2e_run_id)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace, get_e2e_run_selector(e2e_run_id))
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip, ingress_controller_endpoint.port, ingress_controller_endpoint.port_ssl
    )
    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace, IC_SELECTOR)
    upstream_names = []
    if request.param == "mergeable":
        event_text = f"Configuration for {test_namespace}/{ingress_name} was added or updated"
        error_text = f"{test_namespace}/{ingress_name} was rejected: with error"
        for minion in minions_info:
            upstream_names.append(f"{test_namespace}-{minion['name']}-{ingress_host}-{minion['svc_name']}-80")
    else:
        event_text = f"Configuration for {test_namespace}/{ingress_name} was added or updated"
        error_text = f"{test_namespace}/{ingress_name} was rejected: with error"
        upstream_names.append(f"{test_namespace}-{ingress_name}-{ingress_host}-backend1-svc-80")
        upstream_names.append(f"{test_namespace}-{ingress_name}-{ingress_host}-backend2-svc-80")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up Annotations Example:")
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )
            delete_common_app(kube_apis, "simple", test_namespace)
            delete_items_from_yaml(
                kube_apis, f"{TEST_DATA}/annotations/{request.param}/annotations-ingress.yaml", test_namespace
            )
            if request.param == "grpc":
                delete_items_from_yaml(
                    kube_apis, f"{TEST_DATA}/annotations/{request.param}/grpc-secret.yaml", test_namespace
                )

    request.addfinalizer(fin)

    return AnnotationsSetup(
        ingress_controller_endpoint,
        f"{TEST_DATA}/annotations/{request.param}/annotations-ingress.yaml",
        ingress_name,
        ingress_host,
        ic_pod_name,
        test_namespace,
        event_text,
        error_text,
        upstream_names,
    )


@pytest.fixture(scope="class")
def annotations_grpc_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    ingress_controller,
    test_namespace,
) -> AnnotationsSetup:
    print("------------------------- Deploy gRPC Annotations-Example -----------------------------------")
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/annotations/grpc/annotations-ingress.yaml", test_namespace)
    ingress_name = get_name_from_yaml(f"{TEST_DATA}/annotations/grpc/annotations-ingress.yaml")
    ingress_host = get_first_ingress_host_from_yaml(f"{TEST_DATA}/annotations/grpc/annotations-ingress.yaml")
    replace_configmap_from_yaml(
        kube_apis.v1,
        ingress_controller_prerequisites.config_map["metadata"]["name"],
        ingress_controller_prerequisites.namespace,
        f"{TEST_DATA}/common/configmap-with-grpc.yaml",
    )
    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace, IC_SELECTOR)
    event_text = f"Configuration for {test_namespace}/{ingress_name} was added or updated"
    error_text = f"{event_text} ; but was not applied: Error reloading NGINX"

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up gRPC Annotations Example:")
            delete_items_from_yaml(kube_apis, f"{TEST_DATA}/annotations/grpc/annotations-ingress.yaml", test_namespace)

    request.addfinalizer(fin)

    return AnnotationsSetup(
        ingress_controller_endpoint,
        f"{TEST_DATA}/annotations/grpc/annotations-ingress.yaml",
        ingress_name,
        ingress_host,
        ic_pod_name,
        test_namespace,
        event_text,
        error_text,
    )


@pytest.fixture(scope="class")
def grpc_h2c_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller_endpoint,
    ingress_controller,
    test_namespace,
) -> AnnotationsSetup:
    print("------------------------- Deploy gRPC Ingress without TLS -----------------------------------")
    src = f"{TEST_DATA}/annotations/grpc/h2c-ingress.yaml"

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up gRPC Ingress without TLS:")
            delete_items_from_yaml(kube_apis, src, test_namespace)
            delete_common_app(kube_apis, "grpc", test_namespace)
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )

    request.addfinalizer(fin)
    replace_configmap_from_yaml(
        kube_apis.v1,
        ingress_controller_prerequisites.config_map["metadata"]["name"],
        ingress_controller_prerequisites.namespace,
        f"{TEST_DATA}/common/configmap-with-grpc.yaml",
    )
    e2e_run_id = generate_e2e_run_id()
    create_example_app(kube_apis, "grpc", test_namespace, e2e_run_id=e2e_run_id)
    create_items_from_yaml(kube_apis, src, test_namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace, get_e2e_run_selector(e2e_run_id))
    ingress_name = get_name_from_yaml(src)
    return AnnotationsSetup(
        ingress_controller_endpoint,
        src,
        ingress_name,
        get_first_ingress_host_from_yaml(src),
        get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace),
        test_namespace,
        f"Configuration for {test_namespace}/{ingress_name} was added or updated",
        f"{test_namespace}/{ingress_name} was rejected: with error",
    )


@pytest.mark.ingresses
@pytest.mark.annotations
@pytest.mark.parametrize("annotations_setup", ["standard", "mergeable"], indirect=True)
class TestAnnotations:
    def test_nginx_config_defaults(self, kube_apis, annotations_setup, ingress_controller_prerequisites, cli_arguments):
        print("Case 1: no ConfigMap keys, no annotations in Ingress")
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            annotations_setup.namespace,
            annotations_setup.ingress_name,
            annotations_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert "proxy_send_timeout 60s;" in result_conf
        assert "max_conns=0;" in result_conf

        assert "Strict-Transport-Security" not in result_conf
        assert "http2 on;" not in result_conf

        # Without nginx.org/proxy-http-version and without a Service appProtocol, the
        # directive is omitted and NGINX applies its own default.
        assert "proxy_http_version" not in result_conf

        expected_zone_size = "256k"
        if cli_arguments["ic-type"] == "nginx-plus-ingress":
            expected_zone_size = "512k"

        for upstream in annotations_setup.upstream_names:
            assert f"zone {upstream} {expected_zone_size};" in result_conf

    @pytest.mark.parametrize(
        "annotations, expected_strings, unexpected_strings",
        [
            (
                {
                    "nginx.org/proxy-send-timeout": "10s",
                    "nginx.org/max-conns": "1024",
                    "nginx.org/hsts": "True",
                    "nginx.org/hsts-behind-proxy": "True",
                    "nginx.org/upstream-zone-size": "124k",
                    "nginx.org/proxy-set-headers": "X-Forwarded-ABC",
                    "nginx.org/proxy-http-version": "1.0",
                    "nginx.org/http2": "true",
                },
                [
                    "http2 on;",
                    "proxy_send_timeout 10s;",
                    "max_conns=1024",
                    'set $hsts_header_val "";',
                    "proxy_hide_header Strict-Transport-Security;",
                    'add_header Strict-Transport-Security "$hsts_header_val" always;',
                    "if ($http_x_forwarded_proto = 'https')",
                    'set $hsts_header_val "max-age=2592000; preload";',
                    " 124k;",
                    'proxy_set_header X-Forwarded-ABC "$http_x_forwarded_abc";',
                    "proxy_http_version 1.0;",
                    "proxy_set_header Connection close;",
                ],
                ["proxy_send_timeout 60s;", "if ($https = on)", " 256k;", "proxy_http_version 1.1;"],
            )
        ],
    )
    def test_when_annotation_in_ing_only(
        self,
        kube_apis,
        annotations_setup,
        ingress_controller_prerequisites,
        annotations,
        expected_strings,
        unexpected_strings,
    ):
        initial_events = get_events(kube_apis.v1, annotations_setup.namespace)
        initial_count = get_event_count(annotations_setup.ingress_event_text, initial_events)
        print("Case 2: no ConfigMap keys, annotations in Ingress only")
        new_ing = generate_ingresses_with_annotation(annotations_setup.ingress_src_file, annotations)
        for ing in new_ing:
            # in mergeable case this will update master ingress only
            if ing["metadata"]["name"] == annotations_setup.ingress_name:
                replace_ingress(
                    kube_apis.networking_v1, annotations_setup.ingress_name, annotations_setup.namespace, ing
                )
        wait_before_test(1)
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            annotations_setup.namespace,
            annotations_setup.ingress_name,
            annotations_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        new_events = get_events(kube_apis.v1, annotations_setup.namespace)
        assert_event_count_increased(annotations_setup.ingress_event_text, initial_count, new_events)
        for _ in expected_strings:
            assert _ in result_conf
        for _ in unexpected_strings:
            assert _ not in result_conf

    def test_proxy_http_version_from_service_app_protocol(
        self, kube_apis, annotations_setup, ingress_controller_prerequisites
    ):
        """A Service port with appProtocol: kubernetes.io/h2c infers HTTP/2 upstreams, and the
        nginx.org/proxy-http-version annotation takes precedence over it."""
        try:
            print("Case 4: appProtocol on the Service, no annotation in Ingress")
            replace_ingresses_from_yaml(
                kube_apis.networking_v1, annotations_setup.namespace, annotations_setup.ingress_src_file
            )
            wait_before_test(1)

            svc = read_service(kube_apis.v1, "backend1-svc", annotations_setup.namespace)
            svc.spec.ports[0].app_protocol = "kubernetes.io/h2c"
            replace_service(kube_apis.v1, "backend1-svc", annotations_setup.namespace, svc)
            wait_before_test(1)

            result_conf = get_ingress_nginx_template_conf(
                kube_apis.v1,
                annotations_setup.namespace,
                annotations_setup.ingress_name,
                annotations_setup.ingress_pod_name,
                ingress_controller_prerequisites.namespace,
            )
            assert "proxy_http_version 2;" in result_conf

            print("Case 5: appProtocol on the Service overridden by the annotation")
            new_ing = generate_ingresses_with_annotation(
                annotations_setup.ingress_src_file, {"nginx.org/proxy-http-version": "1.1"}
            )
            for ing in new_ing:
                if ing["metadata"]["name"] == annotations_setup.ingress_name:
                    replace_ingress(
                        kube_apis.networking_v1, annotations_setup.ingress_name, annotations_setup.namespace, ing
                    )
            wait_before_test(1)

            result_conf = get_ingress_nginx_template_conf(
                kube_apis.v1,
                annotations_setup.namespace,
                annotations_setup.ingress_name,
                annotations_setup.ingress_pod_name,
                ingress_controller_prerequisites.namespace,
            )
            assert "proxy_http_version 1.1;" in result_conf
            assert "proxy_http_version 2;" not in result_conf
        finally:
            # Restore the Service and the Ingress for the remaining tests in this class.
            svc = read_service(kube_apis.v1, "backend1-svc", annotations_setup.namespace)
            svc.spec.ports[0].app_protocol = None
            replace_service(kube_apis.v1, "backend1-svc", annotations_setup.namespace, svc)
            replace_ingresses_from_yaml(
                kube_apis.networking_v1, annotations_setup.namespace, annotations_setup.ingress_src_file
            )
            wait_before_test(1)

    @pytest.mark.parametrize(
        "configmap_file, expected_strings, unexpected_strings",
        [
            (
                f"{TEST_DATA}/annotations/configmap-with-keys.yaml",
                [
                    "proxy_send_timeout 33s;",
                    'set $hsts_header_val "";',
                    "proxy_hide_header Strict-Transport-Security;",
                    'add_header Strict-Transport-Security "$hsts_header_val" always;',
                    "if ($http_x_forwarded_proto = 'https')",
                    'set $hsts_header_val "max-age=2592000; preload";',
                    " 100k;",
                    "http2 on;",
                ],
                ["proxy_send_timeout 60s;", "if ($https = on)", " 256k;", "http2 off;"],
            ),
        ],
    )
    def test_when_annotation_in_configmap_only(
        self,
        kube_apis,
        annotations_setup,
        ingress_controller_prerequisites,
        configmap_file,
        expected_strings,
        unexpected_strings,
    ):
        initial_events = get_events(kube_apis.v1, annotations_setup.namespace)
        initial_count = get_event_count(annotations_setup.ingress_event_text, initial_events)
        print("Case 3: keys in ConfigMap, no annotations in Ingress")
        replace_ingresses_from_yaml(
            kube_apis.networking_v1, annotations_setup.namespace, annotations_setup.ingress_src_file
        )
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            configmap_file,
        )
        wait_before_test(1)
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            annotations_setup.namespace,
            annotations_setup.ingress_name,
            annotations_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        new_events = get_events(kube_apis.v1, annotations_setup.namespace)

        assert_event_count_increased(annotations_setup.ingress_event_text, initial_count, new_events)
        for _ in expected_strings:
            assert _ in result_conf
        for _ in unexpected_strings:
            assert _ not in result_conf
        main_conf = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, annotations_setup.ingress_pod_name
        )
        assert "http2 on;" in main_conf

    @pytest.mark.parametrize(
        "annotations, configmap_file, expected_strings, unexpected_strings",
        [
            (
                {
                    "nginx.org/proxy-send-timeout": "10s",
                    "nginx.org/hsts": "False",
                    "nginx.org/hsts-behind-proxy": "False",
                    "nginx.org/upstream-zone-size": "124k",
                    "nginx.org/http2": "false",
                },
                f"{TEST_DATA}/annotations/configmap-with-keys.yaml",
                ["proxy_send_timeout 10s;", " 124k;", "http2 off;"],
                ["proxy_send_timeout 33s;", "Strict-Transport-Security", " 100k;", " 256k;", "http2 on;"],
            ),
        ],
    )
    def test_ing_overrides_configmap(
        self,
        kube_apis,
        annotations_setup,
        ingress_controller_prerequisites,
        annotations,
        configmap_file,
        expected_strings,
        unexpected_strings,
    ):
        initial_events = get_events(kube_apis.v1, annotations_setup.namespace)
        initial_count = get_event_count(annotations_setup.ingress_event_text, initial_events)
        print("Case 4: keys in ConfigMap, annotations in Ingress")
        new_ing = generate_ingresses_with_annotation(annotations_setup.ingress_src_file, annotations)
        for ing in new_ing:
            # in mergeable case this will update master ingress only
            if ing["metadata"]["name"] == annotations_setup.ingress_name:
                replace_ingress(
                    kube_apis.networking_v1, annotations_setup.ingress_name, annotations_setup.namespace, ing
                )
        replace_configmap_from_yaml(
            kube_apis.v1,
            ingress_controller_prerequisites.config_map["metadata"]["name"],
            ingress_controller_prerequisites.namespace,
            configmap_file,
        )
        wait_before_test(1)
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            annotations_setup.namespace,
            annotations_setup.ingress_name,
            annotations_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        new_events = get_events(kube_apis.v1, annotations_setup.namespace)

        assert_event_count_increased(annotations_setup.ingress_event_text, initial_count, new_events)
        for _ in expected_strings:
            assert _ in result_conf
        for _ in unexpected_strings:
            assert _ not in result_conf

    @pytest.mark.parametrize(
        "annotations",
        [
            ({"nginx.org/upstream-zone-size": "0"}),
        ],
    )
    def test_upstream_zone_size_0(
        self, cli_arguments, kube_apis, annotations_setup, ingress_controller_prerequisites, annotations
    ):
        initial_events = get_events(kube_apis.v1, annotations_setup.namespace)
        initial_count = get_event_count(annotations_setup.ingress_event_text, initial_events)
        print("Edge Case: upstream-zone-size is 0")
        new_ing = generate_ingresses_with_annotation(annotations_setup.ingress_src_file, annotations)
        for ing in new_ing:
            # in mergeable case this will update master ingress only
            if ing["metadata"]["name"] == annotations_setup.ingress_name:
                replace_ingress(
                    kube_apis.networking_v1, annotations_setup.ingress_name, annotations_setup.namespace, ing
                )
        wait_before_test(1)
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            annotations_setup.namespace,
            annotations_setup.ingress_name,
            annotations_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        new_events = get_events(kube_apis.v1, annotations_setup.namespace)

        assert_event_count_increased(annotations_setup.ingress_event_text, initial_count, new_events)
        if cli_arguments["ic-type"] == "nginx-plus-ingress":
            print("Run assertions for Nginx Plus case")
            assert "zone " in result_conf
            assert " 512k;" in result_conf
        elif cli_arguments["ic-type"] == "nginx-ingress":
            print("Run assertions for Nginx OSS case")
            assert "zone " not in result_conf
            assert " 256k;" not in result_conf

    @pytest.mark.parametrize(
        "annotations",
        [
            {
                "nginx.org/proxy-send-timeout": "invalid",
                "nginx.org/max-conns": "-10",
                "nginx.org/upstream-zone-size": "-10I'm S±!@£$%^&*()invalid",
                "nginx.org/proxy-set-headers": "abc!123",
                "nginx.org/http2": "on",
            }
        ],
    )
    def test_validation(self, kube_apis, annotations_setup, ingress_controller_prerequisites, annotations):
        initial_events = get_events(kube_apis.v1, annotations_setup.namespace)
        print("Case 6: IC doesn't validate, only nginx validates")
        initial_count = get_event_count(annotations_setup.ingress_error_event_text, initial_events)
        new_ing = generate_ingresses_with_annotation(annotations_setup.ingress_src_file, annotations)
        for ing in new_ing:
            # in mergeable case this will update master ingress only
            if ing["metadata"]["name"] == annotations_setup.ingress_name:
                replace_ingress(
                    kube_apis.networking_v1, annotations_setup.ingress_name, annotations_setup.namespace, ing
                )
        wait_before_test()
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            annotations_setup.namespace,
            annotations_setup.ingress_name,
            annotations_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        new_events = get_events(kube_apis.v1, annotations_setup.namespace)
        assert "server {" not in result_conf
        assert "No such file or directory" in result_conf
        assert_event_count_increased(annotations_setup.ingress_error_event_text, initial_count, new_events)
        assert any('nginx.org/http2: Invalid value: "on"' in e.message for e in new_events)


@pytest.mark.ingresses
@pytest.mark.annotations
@pytest.mark.parametrize("annotations_setup", ["mergeable"], indirect=True)
class TestMergeableFlows:
    @pytest.mark.parametrize(
        "yaml_file, expected_strings, unexpected_strings",
        [
            (
                f"{TEST_DATA}/annotations/mergeable/minion-annotations-differ.yaml",
                [
                    "proxy_send_timeout 25s;",
                    "proxy_send_timeout 33s;",
                    "max_conns=1048;",
                    "max_conns=1024;",
                    'proxy_set_header X-Forwarded-ABC "minionA";',
                    'proxy_set_header X-Forwarded-ABC "minionB";',
                ],
                [
                    "proxy_send_timeout 10s;",
                    "max_conns=108;",
                    'proxy_set_header X-Forwarded-ABC "$http_x_forwarded_abc";',
                ],
            ),
            # nginx.org/http2 is server-level: the master's value wins, the minion's is ignored
            (f"{TEST_DATA}/annotations/mergeable/master-http2.yaml", ["http2 on;"], ["http2 off;"]),
        ],
    )
    def test_minion_overrides_master(
        self,
        kube_apis,
        annotations_setup,
        ingress_controller_prerequisites,
        yaml_file,
        expected_strings,
        unexpected_strings,
    ):
        initial_events = get_events(kube_apis.v1, annotations_setup.namespace)
        initial_count = get_event_count(annotations_setup.ingress_event_text, initial_events)
        print("Case 7: minion annotation overrides master")
        replace_ingresses_from_yaml(kube_apis.networking_v1, annotations_setup.namespace, yaml_file)
        wait_before_test(1)
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            annotations_setup.namespace,
            annotations_setup.ingress_name,
            annotations_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        new_events = get_events(kube_apis.v1, annotations_setup.namespace)
        assert_event_count_increased(annotations_setup.ingress_event_text, initial_count, new_events)
        for _ in expected_strings:
            assert _ in result_conf
        for _ in unexpected_strings:
            assert _ not in result_conf


@pytest.mark.ingresses
@pytest.mark.annotations
@pytest.mark.parametrize("annotations_setup", ["standard"], indirect=True)
class TestStandardFlows:
    @pytest.mark.parametrize(
        "yaml_file, expected_strings, unexpected_strings",
        [
            (
                f"{TEST_DATA}/annotations/standard/annotations-ingress.yaml",
                ['proxy_set_header X-Forwarded-ABC "$http_x_forwarded_abc";', 'proxy_set_header ABC "$http_abc";'],
                [
                    'proxy_set_header X-Forwarded-ABC "ABC";',
                ],
            ),
        ],
    )
    def test_standard_ingress(
        self,
        kube_apis,
        annotations_setup,
        ingress_controller_prerequisites,
        yaml_file,
        expected_strings,
        unexpected_strings,
    ):
        print("Case 8: standard ingress")
        replace_ingresses_from_yaml(kube_apis.networking_v1, annotations_setup.namespace, yaml_file)
        wait_before_test(1)
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            annotations_setup.namespace,
            annotations_setup.ingress_name,
            annotations_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        for _ in expected_strings:
            assert _ in result_conf
        for _ in unexpected_strings:
            assert _ not in result_conf


@pytest.mark.ingresses
@pytest.mark.annotations
class TestGrpcFlows:
    @pytest.mark.parametrize(
        "annotations, expected_strings, unexpected_strings",
        [
            ({"nginx.org/proxy-send-timeout": "10s"}, ["grpc_send_timeout 10s;"], ["proxy_send_timeout 60s;"]),
        ],
    )
    def test_grpc_flow(
        self,
        kube_apis,
        annotations_grpc_setup,
        ingress_controller_prerequisites,
        annotations,
        expected_strings,
        unexpected_strings,
    ):
        initial_events = get_events(kube_apis.v1, annotations_grpc_setup.namespace)
        initial_count = get_event_count(annotations_grpc_setup.ingress_event_text, initial_events)
        print("Case 5: grpc annotations override http ones")
        new_ing = generate_ingresses_with_annotation(annotations_grpc_setup.ingress_src_file, annotations)
        for ing in new_ing:
            if ing["metadata"]["name"] == annotations_grpc_setup.ingress_name:
                replace_ingress(
                    kube_apis.networking_v1, annotations_grpc_setup.ingress_name, annotations_grpc_setup.namespace, ing
                )
        wait_before_test(1)
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            annotations_grpc_setup.namespace,
            annotations_grpc_setup.ingress_name,
            annotations_grpc_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        new_events = get_events(kube_apis.v1, annotations_grpc_setup.namespace)
        assert_event_count_increased(annotations_grpc_setup.ingress_event_text, initial_count, new_events)
        for _ in expected_strings:
            assert _ in result_conf
        for _ in unexpected_strings:
            assert _ not in result_conf


@pytest.mark.ingresses
@pytest.mark.annotations
class TestGrpcWithoutTLS:
    @pytest.mark.flaky(max_runs=3)
    def test_h2c_grpc(self, kube_apis, grpc_h2c_setup, ingress_controller_prerequisites):
        """With the http2 ConfigMap key on, a gRPC Ingress without TLS serves gRPC over h2c on the HTTP port."""
        wait_before_test()
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            grpc_h2c_setup.namespace,
            grpc_h2c_setup.ingress_name,
            grpc_h2c_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        # a gRPC-only server without TLS must keep its plaintext listener
        assert "listen 80;" in result_conf
        assert "grpc_pass" in result_conf
        # HTTP/2 comes from the http context, set by the http2 ConfigMap key
        main_conf = get_nginx_template_conf(
            kube_apis.v1, ingress_controller_prerequisites.namespace, grpc_h2c_setup.ingress_pod_name
        )
        assert "http2 on;" in main_conf
        assert_h2c_grpc_hello(grpc_h2c_setup.public_endpoint, grpc_h2c_setup.ingress_host)

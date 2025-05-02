import pytest
import requests
from kubernetes.client.rest import ApiException
from settings import TEST_DATA
from suite.utils.custom_assertions import (
    assert_event,
    assert_event_and_get_count,
    assert_event_count_increased,
    assert_event_starts_with_text_and_contains_errors,
    assert_response_codes,
    assert_vs_conf_not_exists,
)
from suite.utils.custom_resources_utils import generate_item_with_upstream_options
from suite.utils.resources_utils import get_events, get_first_pod_name, replace_configmap_from_yaml, wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    get_vs_nginx_template_conf,
    patch_virtual_server,
    patch_virtual_server_from_yaml,
)


@pytest.mark.vs
@pytest.mark.vs_upstream
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-upstream-options", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVirtualServerUpstreamOptions:
    def test_nginx_config_defaults(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        print("Case 1: no ConfigMap key, no options in VS")
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        assert "random two least_conn;" in config
        assert "ip_hash;" not in config
        assert "hash " not in config
        assert "least_time " not in config

        assert "proxy_connect_timeout 60s;" in config
        assert "proxy_read_timeout 60s;" in config
        assert "proxy_send_timeout 60s;" in config

        assert "max_fails=1 fail_timeout=10s max_conns=0;" in config
        assert "slow_start" not in config

        assert "keepalive" not in config
        assert 'set $default_connection_header "";' not in config
        assert "set $default_connection_header close;" in config
        assert "proxy_set_header Upgrade $http_upgrade;" in config
        assert "proxy_set_header Connection $vs_connection_header;" in config
        assert "proxy_http_version 1.1;" in config

        assert "proxy_next_upstream error timeout;" in config
        assert "proxy_next_upstream_timeout 0s;" in config
        assert "proxy_next_upstream_tries 0;" in config

        assert "client_max_body_size 1m;" in config

        assert "proxy_buffer_size" not in config
        assert "proxy_buffering on;" in config
        assert "proxy_buffers" not in config

        assert "sticky cookie" not in config

    @pytest.mark.parametrize(
        "options, expected_strings",
        [
            (
                {
                    "lb-method": "least_conn",
                    "max-fails": 8,
                    "fail-timeout": "13s",
                    "connect-timeout": "55s",
                    "read-timeout": "1s",
                    "send-timeout": "1h",
                    "keepalive": 54,
                    "max-conns": 1048,
                    "client-max-body-size": "1048K",
                    "buffering": True,
                    "buffer-size": "2k",
                    "buffers": {"number": 4, "size": "2k"},
                },
                [
                    "least_conn;",
                    "max_fails=8 ",
                    "fail_timeout=13s ",
                    "proxy_connect_timeout 55s;",
                    "proxy_read_timeout 1s;",
                    "proxy_send_timeout 1h;",
                    "keepalive 54;",
                    'set $default_connection_header "";',
                    "max_conns=1048;",
                    "client_max_body_size 1048K;",
                    "proxy_buffering on;",
                    "proxy_buffer_size 2k;",
                    "proxy_buffers 4 2k;",
                ],
            ),
            (
                {"lb-method": "ip_hash", "connect-timeout": "75", "read-timeout": "15", "send-timeout": "1h"},
                ["ip_hash;", "proxy_connect_timeout 75s;", "proxy_read_timeout 15s;", "proxy_send_timeout 1h;"],
            ),
            (
                {"connect-timeout": "1m", "read-timeout": "1m", "send-timeout": "1s"},
                ["proxy_connect_timeout 1m;", "proxy_read_timeout 1m;", "proxy_send_timeout 1s;"],
            ),
            (
                {
                    "next-upstream": "error timeout non_idempotent",
                    "next-upstream-timeout": "5s",
                    "next-upstream-tries": 10,
                },
                [
                    "proxy_next_upstream error timeout non_idempotent;",
                    "proxy_next_upstream_timeout 5s;",
                    "proxy_next_upstream_tries 10;",
                ],
            ),
        ],
    )
    def test_when_option_in_v_s_only(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        options,
        expected_strings,
    ):
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"Configuration for {text} was added or updated"
        events_vs = get_events(kube_apis.v1, virtual_server_setup.namespace)
        initial_count = assert_event_and_get_count(vs_event_text, events_vs)
        print(f"Case 2: no key in ConfigMap , option specified in VS")
        new_body = generate_item_with_upstream_options(
            f"{TEST_DATA}/virtual-server-upstream-options/standard/virtual-server.yaml", options
        )
        patch_virtual_server(
            kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace, new_body
        )
        wait_before_test(1)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        resp_1 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        resp_2 = requests.get(virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host})
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)

        assert_event_count_increased(vs_event_text, initial_count, vs_events)
        for _ in expected_strings:
            assert _ in config
        assert_response_codes(resp_1, resp_2)

    @pytest.mark.parametrize(
        "config_map_file, expected_strings, unexpected_strings",
        [
            (
                f"{TEST_DATA}/virtual-server-upstream-options/configmap-with-keys.yaml",
                [
                    "max_fails=3 ",
                    "fail_timeout=33s ",
                    "max_conns=0;",
                    "proxy_connect_timeout 44s;",
                    "proxy_read_timeout 22s;",
                    "proxy_send_timeout 55s;",
                    "keepalive 1024;",
                    'set $default_connection_header "";',
                    "client_max_body_size 3m;",
                    "proxy_buffering off;",
                    "proxy_buffer_size 1k;",
                    "proxy_buffers 8 1k;",
                ],
                [
                    "ip_hash;",
                    "least_conn;",
                    "random ",
                    "hash",
                    "least_time ",
                    "max_fails=1 ",
                    "fail_timeout=10s ",
                    "max_conns=1000;",
                    "proxy_connect_timeout 60s;",
                    "proxy_read_timeout 60s;",
                    "proxy_send_timeout 60s;",
                    "client_max_body_size 1m;",
                    "slow_start=0s",
                    "proxy_buffering on;",
                ],
            ),
        ],
    )
    def test_when_option_in_config_map_only(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        restore_configmap,
        config_map_file,
        expected_strings,
        unexpected_strings,
    ):
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"Configuration for {text} was added or updated"
        print(f"Case 3: key specified in ConfigMap, no option in VS")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            f"{TEST_DATA}/virtual-server-upstream-options/standard/virtual-server.yaml",
            virtual_server_setup.namespace,
        )
        config_map_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
        replace_configmap_from_yaml(
            kube_apis.v1, config_map_name, ingress_controller_prerequisites.namespace, config_map_file
        )
        wait_before_test(1)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        resp_1 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        resp_2 = requests.get(virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host})
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)

        assert_event(vs_event_text, vs_events)
        for _ in expected_strings:
            assert _ in config
        for _ in unexpected_strings:
            assert _ not in config
        assert_response_codes(resp_1, resp_2)

    @pytest.mark.parametrize(
        "options, expected_strings, unexpected_strings",
        [
            (
                {
                    "lb-method": "least_conn",
                    "max-fails": 12,
                    "fail-timeout": "1m",
                    "connect-timeout": "1m",
                    "read-timeout": "77s",
                    "send-timeout": "23s",
                    "keepalive": 48,
                    "client-max-body-size": "0",
                    "buffering": True,
                    "buffer-size": "2k",
                    "buffers": {"number": 4, "size": "2k"},
                },
                [
                    "least_conn;",
                    "max_fails=12 ",
                    "fail_timeout=1m ",
                    "max_conns=0;",
                    "proxy_connect_timeout 1m;",
                    "proxy_read_timeout 77s;",
                    "proxy_send_timeout 23s;",
                    "keepalive 48;",
                    'set $default_connection_header "";',
                    "client_max_body_size 0;",
                    "proxy_buffering on;",
                    "proxy_buffer_size 2k;",
                    "proxy_buffers 4 2k;",
                ],
                [
                    "ip_hash;",
                    "random ",
                    "hash",
                    "least_time ",
                    "max_fails=1 ",
                    "fail_timeout=10s ",
                    "proxy_connect_timeout 44s;",
                    "proxy_read_timeout 22s;",
                    "proxy_send_timeout 55s;",
                    "keepalive 1024;",
                    "client_max_body_size 3m;",
                    "client_max_body_size 1m;",
                    "proxy_buffering off;",
                    "proxy_buffer_size 1k;",
                    "proxy_buffers 8 1k;",
                ],
            )
        ],
    )
    def test_v_s_overrides_config_map(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        restore_configmap,
        options,
        expected_strings,
        unexpected_strings,
    ):
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"Configuration for {text} was added or updated"
        events_vs = get_events(kube_apis.v1, virtual_server_setup.namespace)
        initial_count = assert_event_and_get_count(vs_event_text, events_vs)
        print(f"Case 4: key in ConfigMap, option specified in VS")
        new_body = generate_item_with_upstream_options(
            f"{TEST_DATA}/virtual-server-upstream-options/standard/virtual-server.yaml", options
        )
        patch_virtual_server(
            kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace, new_body
        )
        config_map_name = ingress_controller_prerequisites.config_map["metadata"]["name"]
        replace_configmap_from_yaml(
            kube_apis.v1,
            config_map_name,
            ingress_controller_prerequisites.namespace,
            f"{TEST_DATA}/virtual-server-upstream-options/configmap-with-keys.yaml",
        )
        wait_before_test(1)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        resp_1 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        resp_2 = requests.get(virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host})
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)

        assert_event_count_increased(vs_event_text, initial_count, vs_events)
        for _ in expected_strings:
            assert _ in config
        for _ in unexpected_strings:
            assert _ not in config
        assert_response_codes(resp_1, resp_2)


@pytest.mark.vs
@pytest.mark.vs_upstream
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-upstream-options", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVirtualServerUpstreamOptionValidation:
    def test_event_message_and_config(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        invalid_fields = [
            "upstreams[0].lb-method",
            "upstreams[0].fail-timeout",
            "upstreams[0].max-fails",
            "upstreams[0].connect-timeout",
            "upstreams[0].read-timeout",
            "upstreams[0].send-timeout",
            "upstreams[0].keepalive",
            "upstreams[0].max-conns",
            "upstreams[0].next-upstream",
            "upstreams[0].next-upstream-timeout",
            "upstreams[0].next-upstream-tries",
            "upstreams[0].client-max-body-size",
            "upstreams[0].buffers.number",
            "upstreams[0].buffers.size",
            "upstreams[0].buffer-size",
            "upstreams[1].lb-method",
            "upstreams[1].fail-timeout",
            "upstreams[1].max-fails",
            "upstreams[1].connect-timeout",
            "upstreams[1].read-timeout",
            "upstreams[1].send-timeout",
            "upstreams[1].keepalive",
            "upstreams[1].max-conns",
            "upstreams[1].next-upstream",
            "upstreams[1].next-upstream-timeout",
            "upstreams[1].next-upstream-tries",
            "upstreams[1].client-max-body-size",
            "upstreams[1].buffers.number",
            "upstreams[1].buffers.size",
            "upstreams[1].buffer-size",
        ]
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"VirtualServer {text} was rejected with error:"
        vs_file = f"{TEST_DATA}/virtual-server-upstream-options/virtual-server-with-invalid-keys.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, vs_file, virtual_server_setup.namespace
        )
        wait_before_test(2)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)

        assert_event_starts_with_text_and_contains_errors(vs_event_text, vs_events, invalid_fields)
        assert_vs_conf_not_exists(
            kube_apis, ic_pod_name, ingress_controller_prerequisites.namespace, virtual_server_setup
        )

    def test_openapi_validation_flow(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        invalid_fields = [
            "lb-method",
            "fail-timeout",
            "max-fails",
            "connect-timeout",
            "read-timeout",
            "send-timeout",
            "keepalive",
            "max-conns",
            "next-upstream",
            "next-upstream-timeout",
            "next-upstream-tries",
            "client-max-body-size",
            "buffers.number",
            "buffers.size",
            "buffer-size",
            "buffering",
            "tls",
        ]
        config_old = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        vs_file = f"{TEST_DATA}/virtual-server-upstream-options/virtual-server-with-invalid-keys-openapi.yaml"
        try:
            patch_virtual_server_from_yaml(
                kube_apis.custom_objects, virtual_server_setup.vs_name, vs_file, virtual_server_setup.namespace
            )
        except ApiException as ex:
            assert ex.status == 422
            for item in invalid_fields:
                assert item in ex.body
        except Exception as ex:
            pytest.fail(f"An unexpected exception is raised: {ex}")
        else:
            pytest.fail("Expected an exception but there was none")

        wait_before_test(2)
        config_new = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert config_old == config_new, "Expected: config doesn't change"


@pytest.mark.vs
@pytest.mark.vs_upstream
@pytest.mark.skip_for_nginx_oss
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {"type": "complete", "extra_args": [f"-enable-custom-resources"]},
            {"example": "virtual-server-upstream-options", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestOptionsSpecificForPlus:
    @pytest.mark.parametrize(
        "options, expected_strings",
        [
            (
                {
                    "lb-method": "least_conn",
                    "healthCheck": {"enable": True, "mandatory": True, "persistent": True},
                    "slow-start": "3h",
                    "queue": {"size": 100},
                    "ntlm": True,
                    "sessionCookie": {
                        "enable": True,
                        "name": "TestCookie",
                        "path": "/some-valid/path",
                        "expires": "max",
                        "domain": "virtual-server-route.example.com",
                        "httpOnly": True,
                        "secure": True,
                        "samesite": "strict",
                    },
                },
                [
                    "health_check uri=/ interval=5s jitter=0s",
                    "fails=1 passes=1",
                    "mandatory  persistent",
                    "keepalive_time=60s;",
                    "slow_start=3h",
                    "queue 100 timeout=60s;",
                    "ntlm;",
                    "sticky cookie TestCookie expires=max domain=virtual-server-route.example.com httponly samesite=strict secure path=/some-valid/path;",
                ],
            ),
            (
                {
                    "lb-method": "least_conn",
                    "healthCheck": {"enable": True, "mandatory": True, "persistent": True},
                    "slow-start": "3h",
                    "queue": {"size": 100},
                    "ntlm": True,
                    "sessionCookie": {
                        "enable": True,
                        "name": "TestCookie",
                        "path": "/some-valid/path",
                        "expires": "max",
                        "domain": "virtual-server-route.example.com",
                        "httpOnly": True,
                        "secure": True,
                        "samesite": "lax",
                    },
                },
                [
                    "health_check uri=/ interval=5s jitter=0s",
                    "fails=1 passes=1",
                    "mandatory  persistent",
                    "keepalive_time=60s;",
                    "slow_start=3h",
                    "queue 100 timeout=60s;",
                    "ntlm;",
                    "sticky cookie TestCookie expires=max domain=virtual-server-route.example.com httponly samesite=lax secure path=/some-valid/path;",
                ],
            ),
            (
                {
                    "lb-method": "least_conn",
                    "healthCheck": {"enable": True, "mandatory": True, "persistent": True},
                    "slow-start": "3h",
                    "queue": {"size": 100},
                    "ntlm": True,
                    "sessionCookie": {
                        "enable": True,
                        "name": "TestCookie",
                        "path": "/some-valid/path",
                        "expires": "max",
                        "domain": "virtual-server-route.example.com",
                        "httpOnly": True,
                        "secure": True,
                        "samesite": "none",
                    },
                },
                [
                    "health_check uri=/ interval=5s jitter=0s",
                    "fails=1 passes=1",
                    "mandatory  persistent",
                    "keepalive_time=60s;",
                    "slow_start=3h",
                    "queue 100 timeout=60s;",
                    "ntlm;",
                    "sticky cookie TestCookie expires=max domain=virtual-server-route.example.com httponly samesite=none secure path=/some-valid/path;",
                ],
            ),
            (
                {
                    "lb-method": "least_conn",
                    "healthCheck": {
                        "enable": True,
                        "path": "/health",
                        "interval": "15s",
                        "jitter": "3",
                        "fails": 2,
                        "passes": 2,
                        "port": 8080,
                        "tls": {"enable": True},
                        "statusMatch": "200",
                        "connect-timeout": "35s",
                        "read-timeout": "45s",
                        "send-timeout": "55s",
                        "headers": [{"name": "Host", "value": "virtual-server.example.com"}],
                        "keepalive-time": "120s",
                    },
                    "queue": {"size": 1000, "timeout": "66s"},
                    "slow-start": "0s",
                    "ntlm": True,
                },
                [
                    "health_check uri=/health  port=8080 interval=15s jitter=3s fails=2 passes=2 match=",
                    "proxy_pass https://vs",
                    "status 200;",
                    "proxy_connect_timeout 35s;",
                    "proxy_read_timeout 45s;",
                    "proxy_send_timeout 55s;",
                    'proxy_set_header Host "virtual-server.example.com"',
                    "keepalive_time=120s;",
                    "slow_start=0s",
                    "queue 1000 timeout=66s;",
                    "ntlm;",
                ],
            ),
        ],
    )
    def test_config_and_events(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        options,
        expected_strings,
    ):
        expected_strings.append(
            f"location @hc-vs_" f"{virtual_server_setup.namespace}_{virtual_server_setup.vs_name}_backend1"
        )
        expected_strings.append(
            f"location @hc-vs_" f"{virtual_server_setup.namespace}_{virtual_server_setup.vs_name}_backend2"
        )
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"Configuration for {text} was added or updated"
        events_vs = get_events(kube_apis.v1, virtual_server_setup.namespace)
        initial_count = assert_event_and_get_count(vs_event_text, events_vs)
        print(f"Case 1: option specified in VS")
        new_body = generate_item_with_upstream_options(
            f"{TEST_DATA}/virtual-server-upstream-options/standard/virtual-server.yaml", options
        )
        patch_virtual_server(
            kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace, new_body
        )
        wait_before_test(1)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        resp_1 = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        resp_2 = requests.get(virtual_server_setup.backend_2_url, headers={"host": virtual_server_setup.vs_host})
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)

        assert_event_count_increased(vs_event_text, initial_count, vs_events)
        for _ in expected_strings:
            assert _ in config
        assert_response_codes(resp_1, resp_2)

    @pytest.mark.parametrize("options", [{"slow-start": "0s"}])
    def test_slow_start_warning(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup, options
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"Configuration for {text} was added or updated ; with warning(s): Slow start will be disabled"
        print(f"Case 0: verify a warning")
        new_body = generate_item_with_upstream_options(
            f"{TEST_DATA}/virtual-server-upstream-options/standard/virtual-server.yaml", options
        )
        patch_virtual_server(
            kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace, new_body
        )
        wait_before_test(1)

        config = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)

        assert_event(vs_event_text, vs_events)
        assert "slow_start" not in config

    @pytest.mark.flaky(max_runs=3)
    def test_validation_flow(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        invalid_fields = [
            "upstreams[0].healthCheck.path",
            "upstreams[0].healthCheck.interval",
            "upstreams[0].healthCheck.jitter",
            "upstreams[0].healthCheck.keepalive-time",
            "upstreams[0].healthCheck.fails",
            "upstreams[0].healthCheck.passes",
            "upstreams[0].healthCheck.connect-timeout",
            "upstreams[0].healthCheck.read-timeout",
            "upstreams[0].healthCheck.send-timeout",
            "upstreams[0].healthCheck.headers[0].name",
            "upstreams[0].healthCheck.headers[0].value",
            "upstreams[0].healthCheck.statusMatch",
            "upstreams[0].healthCheck.grpcStatus",
            "upstreams[0].healthCheck.grpcService",
            "upstreams[0].healthCheck.mandatory",
            "upstreams[0].slow-start",
            "upstreams[0].queue.size",
            "upstreams[0].queue.timeout",
            "upstreams[0].sessionCookie.name",
            "upstreams[0].sessionCookie.path",
            "upstreams[0].sessionCookie.expires",
            "upstreams[0].sessionCookie.domain",
            "upstreams[1].healthCheck.path",
            "upstreams[1].healthCheck.interval",
            "upstreams[1].healthCheck.jitter",
            "upstreams[1].healthCheck.keepalive-time",
            "upstreams[1].healthCheck.fails",
            "upstreams[1].healthCheck.passes",
            "upstreams[1].healthCheck.connect-timeout",
            "upstreams[1].healthCheck.read-timeout",
            "upstreams[1].healthCheck.send-timeout",
            "upstreams[1].healthCheck.headers[0].name",
            "upstreams[1].healthCheck.headers[0].value",
            "upstreams[1].healthCheck.statusMatch",
            "upstreams[1].slow-start",
            "upstreams[1].queue.size",
            "upstreams[1].queue.timeout",
            "upstreams[1].sessionCookie.name",
            "upstreams[1].sessionCookie.path",
            "upstreams[1].sessionCookie.expires",
            "upstreams[1].sessionCookie.domain",
        ]
        text = f"{virtual_server_setup.namespace}/{virtual_server_setup.vs_name}"
        vs_event_text = f"VirtualServer {text} was rejected with error:"
        vs_file = f"{TEST_DATA}/virtual-server-upstream-options/plus-virtual-server-with-invalid-keys.yaml"
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects, virtual_server_setup.vs_name, vs_file, virtual_server_setup.namespace
        )
        wait_before_test(2)
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        vs_events = get_events(kube_apis.v1, virtual_server_setup.namespace)

        assert_event_starts_with_text_and_contains_errors(vs_event_text, vs_events, invalid_fields)
        assert_vs_conf_not_exists(
            kube_apis, ic_pod_name, ingress_controller_prerequisites.namespace, virtual_server_setup
        )

    def test_openapi_validation_flow(
        self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller, virtual_server_setup
    ):
        ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        invalid_fields = [
            "healthCheck.enable",
            "healthCheck.path",
            "healthCheck.interval",
            "healthCheck.jitter",
            "healthCheck.keepalive-time",
            "healthCheck.fails",
            "healthCheck.passes",
            "healthCheck.port",
            "healthCheck.connect-timeout",
            "healthCheck.read-timeout",
            "healthCheck.send-timeout",
            "healthCheck.statusMatch",
            "slow-start",
            "queue.size",
            "queue.timeout",
            "sessionCookie.name",
            "sessionCookie.path",
            "sessionCookie.expires",
            "sessionCookie.domain",
            "sessionCookie.httpOnly",
            "sessionCookie.secure",
        ]
        config_old = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        vs_file = f"{TEST_DATA}/virtual-server-upstream-options/plus-virtual-server-with-invalid-keys-openapi.yaml"
        try:
            patch_virtual_server_from_yaml(
                kube_apis.custom_objects, virtual_server_setup.vs_name, vs_file, virtual_server_setup.namespace
            )
        except ApiException as ex:
            assert ex.status == 422
            for item in invalid_fields:
                assert item in ex.body
        except Exception as ex:
            pytest.fail(f"An unexpected exception is raised: {ex}")
        else:
            pytest.fail("Expected an exception but there was none")

        wait_before_test(2)
        config_new = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        assert config_old == config_new, "Expected: config doesn't change"

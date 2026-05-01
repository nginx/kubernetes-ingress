import pytest
import yaml
from settings import TEST_DATA
from suite.utils.custom_assertions import assert_event, assert_ingress_conf_not_exists, wait_and_assert_status_code
from suite.utils.resources_utils import (
    create_ingress_controller,
    create_ingress_from_yaml,
    create_items_from_yaml,
    delete_ingress,
    delete_ingress_controller,
    delete_items_from_yaml,
    get_default_server_conf,
    get_events_for_object,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    replace_ingress,
    wait_before_test,
    wait_until_all_pods_are_ready,
)

empty_host_test_data_path = f"{TEST_DATA}/empty-host-ingress-reload"
cafe_app_src = f"{empty_host_test_data_path}/cafe-app.yaml"
cafe_ingress_src = f"{empty_host_test_data_path}/cafe-ingress.yaml"
empty_host_app_src = f"{empty_host_test_data_path}/empty-host-app.yaml"
empty_host_ingress_src = f"{empty_host_test_data_path}/empty-host-ingress.yaml"
reload_failure_buffer_size_ingress_src = (
    f"{empty_host_test_data_path}/empty-host-ingress-reload-failure-buffer-size.yaml"
)
invalid_annotations = {"nginx.org/proxy-buffer-size": "16k"}


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller, expect_rollback",
    [
        pytest.param({"extra_args": ["-allow-empty-ingress-host", "-health-status"]}, False, id="local-manager"),
        pytest.param(
            {"extra_args": ["-allow-empty-ingress-host", "-health-status", "-enable-config-safety"]},
            True,
            id="rollback-manager",
        ),
    ],
    indirect=["ingress_controller"],
)
class TestEmptyHostIngressReload:
    @pytest.fixture(scope="class")
    def reload_setup(
        self,
        request,
        kube_apis,
        ingress_controller_endpoint,
        ingress_controller,
        test_namespace,
    ):
        create_items_from_yaml(kube_apis, cafe_app_src, test_namespace)
        create_items_from_yaml(kube_apis, empty_host_app_src, test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        wait_and_assert_status_code(
            404,
            f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/",
            verify=False,
        )

        def fin():
            if request.config.getoption("--skip-fixture-teardown") == "no":
                delete_items_from_yaml(kube_apis, cafe_app_src, test_namespace)
                delete_items_from_yaml(kube_apis, empty_host_app_src, test_namespace)

        request.addfinalizer(fin)

    def test_patch_empty_host_ingress_with_invalid_annotation(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        reload_setup,
        test_namespace,
        expect_rollback,
    ):
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        request_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}"

        print("Step 1: create a working empty-host ingress that owns _default-server.conf")
        empty_host_ingress = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, empty_host_ingress_src)
        wait_before_test()
        wait_and_assert_status_code(200, f"{request_url}/", verify=False)

        print("Step 2: patch the owner with an annotation that produces invalid NGINX config")
        with open(empty_host_ingress_src) as f:
            body = yaml.safe_load(f)
        body["metadata"]["annotations"] = invalid_annotations.copy()
        replace_ingress(kube_apis.networking_v1, empty_host_ingress, test_namespace, body)
        wait_before_test()

        print("Step 3: assert traffic still works and inspect the persisted config/result event")
        # This update is accepted far enough to regenerate config, but it fails NGINX validation
        # during apply. Traffic should keep using the last working default-server owner.
        wait_and_assert_status_code(200, f"{request_url}/", verify=False)
        conf = get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)
        messages = " ".join(
            event.message for event in get_events_for_object(kube_apis.v1, test_namespace, empty_host_ingress)
        )

        if expect_rollback:
            # Config-safety keeps the previous working empty-host config on disk and records rollback.
            assert "empty-host-svc" in conf
            assert "proxy_buffer_size 16k" not in conf
            assert "rolled back to previous working config" in messages
        else:
            # Without config-safety, the rejected config can still be left on disk even though
            # NGINX keeps serving from the previous runtime state.
            assert "proxy_buffer_size 16k" in conf

        assert "but was not applied" in messages
        assert "proxy_busy_buffers_size" in messages

        delete_ingress(kube_apis.networking_v1, empty_host_ingress, test_namespace)
        wait_before_test()

    def test_delete_winner_promote_invalid_loser(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        reload_setup,
        test_namespace,
        expect_rollback,
    ):
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        request_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}"
        health_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}"

        print("Step 1: create the current empty-host winner")
        empty_host_ingress = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, empty_host_ingress_src)
        wait_before_test()
        wait_and_assert_status_code(200, f"{request_url}/", verify=False)

        print("Step 2: create a second empty-host ingress that is blocked now but will fail on promotion")
        # This second ingress is valid at the API layer, but its generated NGINX config will fail reload.
        invalid = create_ingress_from_yaml(
            kube_apis.networking_v1, test_namespace, reload_failure_buffer_size_ingress_src
        )
        wait_before_test()
        assert_event(
            "All hosts are taken by other resources",
            get_events_for_object(kube_apis.v1, test_namespace, invalid),
        )

        print("Step 3: delete the winner and assert promotion fails back to synthetic default")
        delete_ingress(kube_apis.networking_v1, empty_host_ingress, test_namespace)
        wait_before_test()

        # After the winner is deleted, NIC tries to promote the previously blocked ingress. That
        # promotion still fails during NGINX validation, so service falls back to synthetic default.
        wait_and_assert_status_code(404, f"{request_url}/", verify=False)
        wait_and_assert_status_code(200, f"{health_url}/nginx-health")
        conf = get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)
        messages = " ".join(event.message for event in get_events_for_object(kube_apis.v1, test_namespace, invalid))

        assert "but was not applied" in messages
        assert "proxy_busy_buffers_size" in messages
        if expect_rollback:
            assert "server_name _" in conf
            assert "return 404" in conf
            assert "empty-host-svc" not in conf
            assert "proxy_buffer_size 16k" not in conf
            assert "rolled back to previous working config" in messages
        else:
            assert "empty-host-svc" in conf
            assert "proxy_buffer_size 16k" in conf

        delete_ingress(kube_apis.networking_v1, invalid, test_namespace)
        wait_before_test()

    def test_named_to_empty_host_with_invalid_annotation(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        reload_setup,
        test_namespace,
        expect_rollback,
    ):
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        http_request_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}"

        print("Step 1: create a working named-host cafe ingress")
        cafe = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, cafe_ingress_src)
        wait_before_test()
        wait_and_assert_status_code(200, f"{http_request_url}/coffee", "cafe.example.com")

        print("Step 2: patch the named ingress into an empty-host ingress with invalid generated config")
        with open(cafe_ingress_src) as f:
            body = yaml.safe_load(f)
        del body["spec"]["rules"][0]["host"]
        body["metadata"]["annotations"] = invalid_annotations.copy()
        replace_ingress(kube_apis.networking_v1, cafe, test_namespace, body)
        wait_before_test()

        print("Step 3: assert the original named-host traffic/config survives the failed transition")
        # Converting a named ingress into an empty-host owner fails during apply, so the original
        # named-host traffic should continue to work.
        wait_and_assert_status_code(200, f"{http_request_url}/coffee", "cafe.example.com")
        messages = " ".join(event.message for event in get_events_for_object(kube_apis.v1, test_namespace, cafe))

        if expect_rollback:
            # Config-safety preserves the original named-host config file.
            assert get_ingress_nginx_template_conf(
                kube_apis.v1,
                test_namespace,
                cafe,
                ic_pod,
                ingress_controller_prerequisites.namespace,
            ) is not None
            assert "coffee-svc" in get_ingress_nginx_template_conf(
                kube_apis.v1,
                test_namespace,
                cafe,
                ic_pod,
                ingress_controller_prerequisites.namespace,
            )
            assert "rolled back to previous working config" in messages
        else:
            # Without config-safety, the named-host config file can disappear even though runtime
            # traffic still serves from the last good config.
            assert_ingress_conf_not_exists(
                kube_apis, ic_pod, ingress_controller_prerequisites.namespace, test_namespace, cafe
            )

        assert "but was not applied" in messages
        assert "proxy_busy_buffers_size" in messages

        delete_ingress(kube_apis.networking_v1, cafe, test_namespace)
        wait_before_test()

    def test_empty_host_to_named_with_invalid_annotation(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        reload_setup,
        test_namespace,
        expect_rollback,
    ):
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        request_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}"

        print("Step 1: create a working empty-host ingress")
        empty_host_ingress = create_ingress_from_yaml(kube_apis.networking_v1, test_namespace, empty_host_ingress_src)
        wait_before_test()
        wait_and_assert_status_code(200, f"{request_url}/", verify=False)

        print("Step 2: patch the owner back to named-host with invalid generated config")
        with open(empty_host_ingress_src) as f:
            body = yaml.safe_load(f)
        body["spec"]["rules"][0]["host"] = "empty-host.example.com"
        body["metadata"]["annotations"] = invalid_annotations.copy()
        replace_ingress(kube_apis.networking_v1, empty_host_ingress, test_namespace, body)
        wait_before_test()

        print("Step 3: assert default-server ownership still reflects the last good state")
        # Moving from empty-host ownership back to a named host should not break the current default
        # server when the updated config fails validation.
        wait_and_assert_status_code(200, f"{request_url}/", verify=False)
        conf = get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)
        messages = " ".join(
            event.message for event in get_events_for_object(kube_apis.v1, test_namespace, empty_host_ingress)
        )

        if expect_rollback:
            # Config-safety keeps the last working empty-host owner in _default-server.conf.
            assert "empty-host-svc" in conf
            assert "rolled back to previous working config" in messages
        else:
            # Without config-safety, the file can revert to synthetic default even though the update failed.
            assert "return 404" in conf

        assert "but was not applied" in messages
        assert "proxy_busy_buffers_size" in messages

        delete_ingress(kube_apis.networking_v1, empty_host_ingress, test_namespace)
        wait_before_test()


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "invalid_empty_host_ingress_before_startup, expect_rollback",
    [
        pytest.param(["-allow-empty-ingress-host", "-health-status"], False, id="local-manager"),
        pytest.param(
            ["-allow-empty-ingress-host", "-health-status", "-enable-config-safety"],
            True,
            id="rollback-manager",
        ),
    ],
    indirect=["invalid_empty_host_ingress_before_startup"],
)
class TestEmptyHostIngressStartupProtection:
    @pytest.fixture(scope="class")
    def invalid_empty_host_ingress_before_startup(
        self, request, kube_apis, cli_arguments, ingress_controller_prerequisites, test_namespace
    ):
        print("Step 1: create the backend and an empty-host ingress that will fail during initial apply")
        create_items_from_yaml(kube_apis, empty_host_app_src, test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        # This ingress exists before NIC starts. It will be accepted from the API perspective,
        # but its generated NGINX config will fail validation during initial apply.
        ingress_name = create_ingress_from_yaml(
            kube_apis.networking_v1,
            test_namespace,
            reload_failure_buffer_size_ingress_src,
        )
        wait_before_test()

        print("Step 2: start NIC and let it try to apply the invalid startup config")
        # Start NIC after the invalid empty-host ingress already exists.
        extra_args = request.param + ["-enable-custom-resources=false"]
        ic_name = create_ingress_controller(
            kube_apis.v1,
            kube_apis.apps_v1_api,
            cli_arguments,
            ingress_controller_prerequisites.namespace,
            extra_args,
        )

        def fin():
            if request.config.getoption("--skip-fixture-teardown") == "no":
                delete_ingress(kube_apis.networking_v1, ingress_name, test_namespace)
                delete_items_from_yaml(kube_apis, empty_host_app_src, test_namespace)
                delete_ingress_controller(
                    kube_apis.apps_v1_api,
                    ic_name,
                    cli_arguments["deployment-type"],
                    ingress_controller_prerequisites.namespace,
                )

        request.addfinalizer(fin)
        return ingress_name

    def test_default_server_survives_invalid_empty_host_ingress_on_startup(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller_endpoint,
        invalid_empty_host_ingress_before_startup,
        test_namespace,
        expect_rollback,
    ):
        ic_pod = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)
        request_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}"
        health_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}"
        messages = " ".join(
            event.message
            for event in get_events_for_object(kube_apis.v1, test_namespace, invalid_empty_host_ingress_before_startup)
        )
        conf = get_default_server_conf(kube_apis.v1, ic_pod, ingress_controller_prerequisites.namespace)

        print("Step 3: assert startup keeps the synthetic default server available")
        wait_and_assert_status_code(404, f"{request_url}/", verify=False)
        wait_and_assert_status_code(200, f"{health_url}/nginx-health")
        assert "but was not applied" in messages
        assert "proxy_busy_buffers_size" in messages

        assert "server_name _" in conf
        if expect_rollback:
            # With config-safety enabled on top of PR1, NIC keeps the bootstrapped synthetic
            # default server on disk instead of leaving the failed empty-host config in place.
            assert "empty-host-svc" not in conf
            assert "proxy_buffer_size 16k" not in conf
            assert "rolled back to previous working config" in messages
        else:
            # Without config-safety, the failed empty-host config can still be left on disk even
            # though runtime traffic stays on the startup default server.
            assert "empty-host-svc" in conf
            assert "proxy_buffer_size 16k" in conf

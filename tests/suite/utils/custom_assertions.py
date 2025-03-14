"""Describe the custom assertion methods"""

import time

import pytest
import requests
from suite.utils.resources_utils import get_events
from suite.utils.vs_vsr_resources_utils import get_vs_nginx_template_conf


def assert_no_new_events(old_list, new_list):
    assert len(old_list) == len(new_list), "Expected: lists are of the same size"
    for i in range(len(new_list) - 1, -1, -1):
        if old_list[i].count != new_list[i].count:
            pytest.fail(f'Expected: no new events. There is a new event found:"{new_list[i].message}". Exiting...')


def assert_event_count_increased(event_text, count, events_list) -> None:
    """
    Search for the event in the list and verify its counter is more than the expected value.

    :param event_text: event text
    :param count: expected value
    :param events_list: list of events
    :return:
    """
    for i in range(len(events_list) - 1, -1, -1):
        if event_text in events_list[i].message:
            assert events_list[i].count > count
            return
    pytest.fail(f'Failed to find the event "{event_text}" in the list. Exiting...')


def assert_event_and_count(event_text, count, events_list) -> None:
    """
    Search for the event in the list and compare its counter with an expected value.

    :param event_text: event text
    :param count: expected value
    :param events_list: list of events
    :return:
    """
    for i in range(len(events_list) - 1, -1, -1):
        if event_text in events_list[i].message:
            assert events_list[i].count == count
            return
    pytest.fail(f'Failed to find the event "{event_text}" in the list. Exiting...')


def assert_event_with_full_equality_and_count(event_text, count, events_list) -> None:
    """
    Search for the event in the list and compare its counter with an expected value.

    :param event_text: event text
    :param count: expected value
    :param events_list: list of events
    :return:
    """

    for i in range(len(events_list) - 1, -1, -1):
        # some events have trailing whitespace
        message_stripped = events_list[i].message.rstrip()

        if event_text == message_stripped:
            assert events_list[i].count == count
            return
    pytest.fail(f'Failed to find the event "{event_text}" in the list. Exiting...')


def assert_event_and_get_count(event_text, events_list) -> int:
    """
    Search for the event in the list and return its counter.

    :param event_text: event text
    :param events_list: list of events
    :return: event.count
    """
    for i in range(len(events_list) - 1, -1, -1):
        if event_text in events_list[i].message:
            return events_list[i].count
    pytest.fail(f'Failed to find the event "{event_text}" in the list. Exiting...')


def get_event_count(event_text, events_list) -> int:
    """
    Search for the event in the list and return its counter.

    :param event_text: event text
    :param events_list: list of events
    :return: (int)
    """
    for i in range(len(events_list) - 1, -1, -1):
        if event_text in events_list[i].message:
            return events_list[i].count
    pytest.fail(f'Failed to find the event "{event_text}" in the list. Exiting...')


def wait_for_event_count_increases(kube_apis, event_text, initial_count, events_namespace) -> None:
    """
    Wait for the event counter to get bigger than the initial value.

    :param kube_apis: KubeApis
    :param event_text: event text
    :param initial_count: expected value
    :param events_namespace: namespace to fetch events
    :return:
    """
    events_list = get_events(kube_apis.v1, events_namespace)
    count = get_event_count(event_text, events_list)
    counter = 0
    while count <= initial_count and counter < 4:
        time.sleep(1)
        counter = counter + 1
        events_list = get_events(kube_apis.v1, events_namespace)
        count = get_event_count(event_text, events_list)
    assert count > initial_count, f'After several seconds the event counter has not increased "{event_text}"'


def assert_response_codes(resp_1, resp_2, code_1=200, code_2=200) -> None:
    """
    Assert responses status codes.

    :param resp_1: Response
    :param resp_2: Response
    :param code_1: expected status code
    :param code_2: expected status code
    :return:
    """
    assert resp_1.status_code == code_1
    assert resp_2.status_code == code_2


def assert_event(event_text, events_list) -> None:
    """
    Search for the event in the list.

    :param event_text: event text
    :param events_list: list of events
    :return:
    """
    for i in range(len(events_list) - 1, -1, -1):
        if event_text in events_list[i].message:
            return
    pytest.fail(f'Failed to find the event "{event_text}" in {events_list}. Exiting...')


def assert_event_not_present(event_text, events_list) -> None:
    """
    Search for the event in the list.

    :param event_text: event text
    :param events_list: list of events
    :return:
    """
    for i in range(len(events_list) - 1, -1, -1):
        if event_text in events_list[i].message:
            pytest.fail(f'Event "{event_text}" exists in the list. Exiting...')


def assert_event_starts_with_text_and_contains_errors(event_text, events_list, fields_list) -> None:
    """
    Search for the event starting with the expected text in the list and check its message.

    :param event_text: event text
    :param events_list: list of events
    :param fields_list: expected message contents
    :return:
    """
    for i in range(len(events_list) - 1, -1, -1):
        if str(events_list[i].message).startswith(event_text):
            for field_error in fields_list:
                assert field_error in events_list[i].message
            return
    pytest.fail(f'Failed to find the event starting with "{event_text}" in the list. Exiting...')


def assert_vs_conf_not_exists(kube_apis, ic_pod_name, ic_namespace, virtual_server_setup):
    new_response = get_vs_nginx_template_conf(
        kube_apis.v1, virtual_server_setup.namespace, virtual_server_setup.vs_name, ic_pod_name, ic_namespace
    )
    assert "No such file or directory" in new_response


def assert_vs_conf_exists(kube_apis, ic_pod_name, ic_namespace, virtual_server_setup):
    new_response = get_vs_nginx_template_conf(
        kube_apis.v1, virtual_server_setup.namespace, virtual_server_setup.vs_name, ic_pod_name, ic_namespace
    )
    assert "No such file or directory" not in new_response


def wait_and_assert_status_code(code, req_url, host, **kwargs) -> None:
    """
    Wait for a specific response status code.

    :param  code: status_code
    :param  req_url: request url
    :param  host: request headers if any
    :paramv **kwargs: optional arguments that ``request`` takes
    :return:
    """
    counter = 0
    resp = requests.get(req_url, headers={"host": host}, **kwargs)
    while not resp.status_code == code and counter <= 30:
        time.sleep(1)
        counter = counter + 1
        resp = requests.get(req_url, headers={"host": host}, **kwargs)
    assert resp.status_code == code, f"After 30 seconds the status_code is still not {code}"


def assert_grpc_entries_exist(config) -> None:
    """
    Assert that the gPRC config entries are present in the config file.

    :param config: the nginx config
    :return:
    """
    assert "grpc_connect_timeout 60s;" in config
    assert "grpc_read_timeout 60s;" in config
    assert "grpc_send_timeout 60s;" in config

    assert "grpc_set_header X-Real-IP $remote_addr;" in config
    assert "grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;" in config
    assert "grpc_set_header X-Forwarded-Host $host;" in config
    assert "grpc_set_header X-Forwarded-Port $server_port;" in config
    assert "grpc_set_header X-Forwarded-Proto $scheme;" in config

    assert 'grpc_set_header Host "$host";' in config

    assert "grpc_next_upstream error timeout;" in config
    assert "grpc_next_upstream_timeout 0s;" in config
    assert "grpc_next_upstream_tries 0;" in config


def assert_proxy_entries_do_not_exist(config) -> None:
    """
    Assert that the proxy config entries are not present in the config file.

    :param config: the nginx config
    :return:
    """
    assert "proxy_connect_timeout 60s;" not in config
    assert "proxy_read_timeout 60s;" not in config
    assert "proxy_send_timeout 60s;" not in config

    assert "proxy_set_header Upgrade $http_upgrade;" not in config
    assert "proxy_http_version 1.1;" not in config

    assert "proxy_next_upstream error timeout;" not in config
    assert "proxy_next_upstream_timeout 0s;" not in config
    assert "proxy_next_upstream_tries 0;" not in config


def assert_proxy_entries_exist(config) -> None:
    """
    Assert that the proxy config entries are present in the config file.

    :param config: the nginx config
    :return:
    """

    assert "proxy_connect_timeout 60s;" in config
    assert "proxy_read_timeout 60s;" in config
    assert "proxy_send_timeout 60s;" in config

    assert "proxy_set_header Upgrade $http_upgrade;" in config
    assert "proxy_http_version 1.1;" in config

    assert "proxy_next_upstream error timeout;" in config
    assert "proxy_next_upstream_timeout 0s;" in config
    assert "proxy_next_upstream_tries 0;" in config


def assert_pods_scaled_to_count(apps_v1_api, v1, deployment_name, namespace, expected_count, timeout=60, interval=1):
    """
    Check if the number of pods for a given deployment has scaled down to the expected count.

    :param apps_v1_api: AppsV1Api
    :param v1: CoreV1Api
    :param deployment_name: name of the deployment to check.
    :param namespace: namespace of the deployment.
    :param expected_count: expected number of pods after scaling.
    :param timeout: Maximum time to wait for the expected count to be met.
    :param interval: Time to wait between checks.
    """
    end_time = time.time() + timeout
    while time.time() < end_time:
        selector = ",".join(
            [
                f"{key}={value}"
                for key, value in apps_v1_api.read_namespaced_deployment(
                    deployment_name, namespace
                ).spec.selector.match_labels.items()
            ]
        )
        pods = v1.list_namespaced_pod(namespace, label_selector=selector)
        pod_count = len(pods.items)
        if pod_count == expected_count:
            print(f"Expected {expected_count} pods, found {pod_count} for '{deployment_name}' in '{namespace}'.")
            return
        time.sleep(interval)
    assert (
        False
    ), f"Expected {expected_count} pods, but found {pod_count} for '{deployment_name}' in '{namespace}' after {timeout} seconds."

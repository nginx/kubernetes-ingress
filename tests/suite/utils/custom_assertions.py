"""Describe the custom assertion methods"""

import time

import pytest
import requests
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.resources_utils import (
    get_events,
    get_ingress_nginx_template_conf,
    get_vs_nginx_template_conf,
    wait_before_test,
)


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


def assert_vs_conf_not_exists(kube_apis, ic_pod_name, ic_namespace, vs_namespace, vs_name):
    """Assert that the VS nginx config file does not exist in the pod."""
    response = get_vs_nginx_template_conf(kube_apis.v1, vs_namespace, vs_name, ic_pod_name, ic_namespace)
    assert "No such file or directory" in response


def assert_vs_conf_exists(kube_apis, ic_pod_name, ic_namespace, vs_namespace, vs_name):
    """Assert that the VS nginx config file exists in the pod."""
    response = get_vs_nginx_template_conf(kube_apis.v1, vs_namespace, vs_name, ic_pod_name, ic_namespace)
    assert "No such file or directory" not in response


def assert_ingress_conf_not_exists(kube_apis, ic_pod_name, ic_namespace, ingress_namespace, ingress_name):
    """Assert that the Ingress nginx config file does not exist in the pod."""
    response = get_ingress_nginx_template_conf(kube_apis.v1, ingress_namespace, ingress_name, ic_pod_name, ic_namespace)
    assert "No such file or directory" in response


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


def assert_crd_status(
    kube_apis,
    namespace,
    name,
    crd_plural,
    expected_state,
    expected_reason=None,
    expected_messages=None,
    retry_count=30,
    wait_time=1,
):
    """Wait until a CRD resource reaches expected_state, optionally check reason and message substrings.

    :param kube_apis: KubeApis
    :param namespace: namespace
    :param name: resource name
    :param crd_plural: CRD plural name (e.g. "virtualservers", "virtualserverroutes", "transportservers")
    :param expected_state: expected status.state (e.g. "Valid", "Invalid", "Warning")
    :param expected_reason: if set, assert status.reason matches (e.g. "AddedOrUpdatedWithError")
    :param expected_messages: if set, list of substrings that must appear in status.message
    :param retry_count: number of retries
    :param wait_time: seconds between retries
    :return: the resource dict
    """
    count = 0
    resource_info = None
    while count < retry_count:
        wait_before_test(wait_time)
        resource_info = read_custom_resource(
            kube_apis.custom_objects,
            namespace,
            crd_plural,
            name,
        )

        if "status" in resource_info and resource_info["status"].get("state") == expected_state:
            reason_ok = not expected_reason or resource_info["status"].get("reason") == expected_reason
            messages_ok = not expected_messages or all(
                msg in resource_info["status"].get("message", "") for msg in expected_messages
            )
            if reason_ok and messages_ok:
                return resource_info

        count += 1
        print(f"{crd_plural} '{name}' status not ready on retry {count}, retrying...")
        wait_before_test(wait_time)

    # Provide a detailed failure message
    if resource_info and "status" in resource_info and resource_info["status"].get("state") == expected_state:
        details = []
        if expected_reason and resource_info["status"].get("reason") != expected_reason:
            details.append(f"expected reason '{expected_reason}', got '{resource_info['status'].get('reason')}'")
        if expected_messages:
            for msg in expected_messages:
                if msg not in resource_info["status"].get("message", ""):
                    details.append(f"expected '{msg}' in status message")
        pytest.fail(
            f"{crd_plural} '{name}' reached state '{expected_state}' but {'; '.join(details)}. "
            f"Current status: {resource_info.get('status')}"
        )
    else:
        pytest.fail(
            f"{crd_plural} '{name}' did not reach state '{expected_state}'. "
            f"Current status: {resource_info.get('status') if resource_info else 'N/A'}"
        )
    return None


def assert_vs_status(kube_apis, namespace, name, expected_state, **kwargs):
    """Wait until VS reaches expected_state. Thin wrapper around assert_crd_status."""
    return assert_crd_status(kube_apis, namespace, name, "virtualservers", expected_state, **kwargs)


def assert_vsr_status(kube_apis, namespace, name, expected_state, **kwargs):
    """Wait until VSR reaches expected_state. Thin wrapper around assert_crd_status."""
    return assert_crd_status(kube_apis, namespace, name, "virtualserverroutes", expected_state, **kwargs)


def assert_ts_status(kube_apis, namespace, name, expected_state, **kwargs):
    """Wait until TS reaches expected_state. Thin wrapper around assert_crd_status."""
    return assert_crd_status(kube_apis, namespace, name, "transportservers", expected_state, **kwargs)


def assert_valid_vs(kube_apis, namespace, name, retry_count=30, wait_time=1):
    """Assert that a VirtualServer reaches Valid state with AddedOrUpdated reason."""
    return assert_vs_status(
        kube_apis,
        namespace,
        name,
        "Valid",
        expected_reason="AddedOrUpdated",
        retry_count=retry_count,
        wait_time=wait_time,
    )


def assert_valid_vsr(kube_apis, namespace, name, retry_count=30, wait_time=1):
    """Assert that a VirtualServerRoute reaches Valid state with AddedOrUpdated reason."""
    return assert_vsr_status(
        kube_apis,
        namespace,
        name,
        "Valid",
        expected_reason="AddedOrUpdated",
        retry_count=retry_count,
        wait_time=wait_time,
    )


def assert_invalid_vs(kube_apis, namespace, name, retry_count=30, wait_time=1):
    """Assert that a VirtualServer reaches Invalid state."""
    return assert_vs_status(kube_apis, namespace, name, "Invalid", retry_count=retry_count, wait_time=wait_time)


def assert_invalid_vsr(kube_apis, namespace, name, retry_count=30, wait_time=1):
    """Assert that a VirtualServerRoute reaches Invalid state."""
    return assert_vsr_status(kube_apis, namespace, name, "Invalid", retry_count=retry_count, wait_time=wait_time)

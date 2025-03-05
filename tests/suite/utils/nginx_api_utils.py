"""Describe the methods to work with nginx api"""

import ast

import pytest
import requests
from settings import NGINX_API_VERSION
from suite.utils.resources_utils import wait_before_test


def get_nginx_generation_value(host) -> int:
    """
    Send request to /api/api_version/nginx and parse the response.

    :param host:
    :return: 'generation' value
    """
    resp = ast.literal_eval(requests.get(f"{host}/api/{NGINX_API_VERSION}/nginx").text)
    return resp["generation"]


def wait_for_empty_array(request_url) -> None:
    """
    Wait while the response from the API contains non-empty array.

    :param request_url:
    :return:
    """
    response = requests.get(f"{request_url}")
    counter = 0
    while response.text != "[]":
        wait_before_test(1)
        response = requests.get(f"{request_url}")
        if counter == 10:
            pytest.fail(f"After 10 seconds array is not empty, request_url: {request_url}")
        counter = counter + 1


def wait_for_non_empty_array(request_url) -> None:
    """
    Wait while the response from the API contains empty array.

    :param request_url:
    :return:
    """
    response = requests.get(f"{request_url}")
    counter = 0
    while response.text == "[]":
        wait_before_test(1)
        response = requests.get(f"{request_url}")
        if counter == 10:
            pytest.fail(f"After 10 seconds array is empty, request_url: {request_url}")
        counter = counter + 1


def wait_for_zone_sync_enabled(request_url) -> bool:
    """
    Wait while the response from the API contains zone_sync.

    :param request_url:
    :return: bool
    """
    interval = 1
    retry = 120
    count = 1
    while count <= retry:
        print(f"{count}: Calling get on {request_url}")
        resp = requests.get(request_url)
        if resp.status_code != 200:
            return False
        if "zone_sync" in resp.json():
            return True
        count += 1
        wait_before_test(interval)
    return False


def wait_for_zone_sync_nodes_online(request_url, node_count) -> bool:
    """
    Wait while the response from the API contains the correct number of online zone sync nodes.

    :param request_url:
    :param node_count
    :return: bool
    """
    interval = 1
    retry = 120
    count = 1
    while count <= retry:
        print(f"{count}: Calling get on {request_url}")
        resp = requests.get(request_url)
        if resp.status_code != 200:
            return False
        body = resp.json()
        nodes = body["status"]["nodes_online"]
        online = node_count - 1  # NGINX only shows remote peers in the `nodes_online` field
        if nodes == online:
            return True
        count += 1
        wait_before_test(interval)
    return False


def check_synced_zone_exists(request_url, zone_name) -> bool:
    """
    Check the response from the API contains the requested zone_name.

    :param request_url:
    :param zone_name
    :return: bool
    """
    resp = requests.get(request_url)
    if resp.status_code != 200:
        return False
    body = resp.json()
    for zone in body["zones"].keys():
        if zone_name in zone:
            return True
    return False

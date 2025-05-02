import ipaddress
import re
import socket

import pytest
from settings import TEST_DATA
from suite.utils.custom_resources_utils import create_ts_from_yaml, delete_ts, patch_ts_from_yaml, read_ts
from suite.utils.resources_utils import get_ts_nginx_template_conf, scale_deployment, wait_before_test


# Helper functions
def chk_endpoint(endp):
    """
    If an endpoint is IPv6, return a formatted [ip]:port
    endpoint. Otherwise, return unmodified endpoint.
    """
    ip = endp[: endp.rfind(":")]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return endp
    if address.version == 6:
        port = endp[endp.rfind(":") :]
        return f"[{ip}]{port}"
    else:
        return endp


def ipfamily_from_host(host):
    """
    Return socket type (AF_INET or AF_INET6) based on
    IP address type from host
    """
    sock = socket.AF_INET
    try:
        address = ipaddress.ip_address(host)
        if address.version == 6:
            sock = socket.AF_INET6
    except ValueError:
        pass
    return sock


@pytest.mark.ts
@pytest.mark.skip_for_loadbalancer
@pytest.mark.parametrize(
    "crd_ingress_controller, transport_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    "-global-configuration=nginx-ingress/nginx-configuration",
                    "-enable-leader-election=false",
                ],
            },
            {"example": "transport-server-udp-load-balance"},
        )
    ],
    indirect=True,
)
class TestTransportServerUdpLoadBalance:
    def restore_ts(self, kube_apis, transport_server_setup) -> None:
        """
        Function to revert a TransportServer resource to a valid state.
        """
        patch_src = f"{TEST_DATA}/transport-server-udp-load-balance/standard/transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )

    def test_number_of_replicas(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        The load balancing of UDP should result in 4 servers to match the 4 replicas of a service.
        """
        original = scale_deployment(
            kube_apis.v1, kube_apis.apps_v1_api, "udp-service", transport_server_setup.namespace, 4
        )
        num_servers = 0
        retry = 0

        while num_servers != 4 and retry <= 50:
            result_conf = get_ts_nginx_template_conf(
                kube_apis.v1,
                transport_server_setup.namespace,
                transport_server_setup.name,
                transport_server_setup.ingress_pod_name,
                ingress_controller_prerequisites.namespace,
            )

            pattern = "server .*;"
            num_servers = len(re.findall(pattern, result_conf))
            retry += 1
            wait_before_test(1)
            print(f"Retry #{retry}")

        assert num_servers == 4

        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "udp-service", transport_server_setup.namespace, original)
        retry = 0
        while num_servers is not original and retry <= 50:
            result_conf = get_ts_nginx_template_conf(
                kube_apis.v1,
                transport_server_setup.namespace,
                transport_server_setup.name,
                transport_server_setup.ingress_pod_name,
                ingress_controller_prerequisites.namespace,
            )

            pattern = "server .*;"
            num_servers = len(re.findall(pattern, result_conf))
            retry += 1
            wait_before_test(1)
            print(f"Retry #{retry}")

        assert num_servers is original

    def test_udp_request_load_balanced(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Requests to the load balanced UDP service should result in responses from 3 different endpoints.
        """
        wait_before_test()
        port = transport_server_setup.public_endpoint.udp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        print(f"sending udp requests to: {host}:{port}")

        endpoints = {}
        retry = 0
        while len(endpoints) != 3 and retry <= 30:
            for i in range(20):
                host = host.strip("[]")
                client = socket.socket(ipfamily_from_host(host), socket.SOCK_DGRAM, 0)
                client.sendto(b"ping", (host, port))
                data, address = client.recvfrom(4096)
                endpoint = data.decode()
                print(f" req number {i}; response: {endpoint}")
                if endpoint not in endpoints:
                    endpoints[endpoint] = 1
                else:
                    endpoints[endpoint] = endpoints[endpoint] + 1
                client.close()
            retry += 1
            wait_before_test(1)
            print(f"Retry #{retry}")

        assert len(endpoints) == 3

        result_conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            transport_server_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        pattern = "server .*;"
        servers = re.findall(pattern, result_conf)
        for key in endpoints.keys():
            found = False
            for server in servers:
                if chk_endpoint(key) in server:
                    found = True
            assert found

    def test_udp_request_load_balanced_multiple(self, kube_apis, crd_ingress_controller, transport_server_setup):
        """
        Requests to the load balanced UDP service should result in responses from 3 different endpoints.
        """
        port = transport_server_setup.public_endpoint.udp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        # Step 1, confirm load balancing is working.
        print(f"sending udp requests to: {host}:{port}")
        host = host.strip("[]")
        client = socket.socket(ipfamily_from_host(host), socket.SOCK_DGRAM, 0)
        client.sendto(b"ping", (host, port))
        data, address = client.recvfrom(4096)
        endpoint = data.decode()
        print(f"response: {endpoint}")
        client.close()

        # Step 2, add a second TransportServer with the same port and confirm the collision
        transport_server_file = f"{TEST_DATA}/transport-server-udp-load-balance/second-transport-server.yaml"
        ts_resource = create_ts_from_yaml(
            kube_apis.custom_objects, transport_server_file, transport_server_setup.namespace
        )
        wait_before_test()

        second_ts_name = ts_resource["metadata"]["name"]
        response = read_ts(
            kube_apis.custom_objects,
            transport_server_setup.namespace,
            second_ts_name,
        )
        assert (
            response["status"]
            and response["status"]["reason"] == "Rejected"
            and response["status"]["state"] == "Warning"
            and response["status"]["message"] == "Listener udp-server with host empty host is taken by another resource"
        )

        # Step 3, remove the default TransportServer with the same port
        delete_ts(kube_apis.custom_objects, transport_server_setup.resource, transport_server_setup.namespace)

        wait_before_test()
        response = read_ts(
            kube_apis.custom_objects,
            transport_server_setup.namespace,
            second_ts_name,
        )
        assert (
            response["status"]
            and response["status"]["reason"] == "AddedOrUpdated"
            and response["status"]["state"] == "Valid"
        )

        # Step 4, confirm load balancing is still working.
        client = socket.socket(ipfamily_from_host(host), socket.SOCK_DGRAM, 0)
        client.sendto(b"ping", (host, port))
        data, address = client.recvfrom(4096)
        endpoint = data.decode()
        print(f"response: {endpoint}")
        client.close()
        assert endpoint != ""

        # cleanup
        delete_ts(kube_apis.custom_objects, ts_resource, transport_server_setup.namespace)
        transport_server_file = f"{TEST_DATA}/transport-server-udp-load-balance/standard/transport-server.yaml"
        create_ts_from_yaml(kube_apis.custom_objects, transport_server_file, transport_server_setup.namespace)
        wait_before_test()

    @pytest.mark.parametrize("file", ["wrong-port-transport-server.yaml", "missing-service-transport-server.yaml"])
    def test_udp_request_fails(self, kube_apis, crd_ingress_controller, transport_server_setup, file):
        patch_src = f"{TEST_DATA}/transport-server-udp-load-balance/{file}"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        # 4s includes 3s timeout for a health check to fail in case a backend pod doesn't respond or responds with
        # an unexpected response
        wait_before_test()

        port = transport_server_setup.public_endpoint.udp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        print(f"sending udp requests to: {host}:{port}")
        for i in range(3):
            host = host.strip("[]")
            client = socket.socket(ipfamily_from_host(host), socket.SOCK_DGRAM, 0)
            client.settimeout(2)
            client.sendto(b"ping", (host, port))
            try:
                client.recvfrom(4096)
                # it should timeout
                print(f"incorrect config from {file} should have resulted in an error")
                assert False
            except socket.timeout:
                print("successfully timed out")
            client.close()

        self.restore_ts(kube_apis, transport_server_setup)

    @pytest.mark.skip_for_nginx_oss
    def test_udp_passing_healthcheck_with_match(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Configure a passing health check and check that all backend pods return responses.
        """

        # Step 1 - configure a passing health check

        patch_src = f"{TEST_DATA}/transport-server-udp-load-balance/passing-hc-transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        # 4s includes 3s timeout for a health check to fail in case a backend pod doesn't respond or responds with
        # an unexpected response
        wait_before_test(4)

        result_conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            transport_server_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        match = f"match_ts_{transport_server_setup.namespace}_transport-server_udp-app"

        assert "health_check interval=5s" in result_conf
        assert f"passes=1 jitter=0s fails=1 udp match={match}" in result_conf
        assert "health_check_timeout 3s;"
        assert 'send "health"' in result_conf
        assert 'expect  "healthy"' in result_conf

        # Step 2 - confirm load balancing works

        port = transport_server_setup.public_endpoint.udp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        print(f"sending udp requests to: {host}:{port}")

        retry = 0
        endpoints = {}
        while len(endpoints) != 3 and retry <= 30:
            for i in range(20):
                host = host.strip("[]")
                client = socket.socket(ipfamily_from_host(host), socket.SOCK_DGRAM, 0)
                client.sendto(b"ping", (host, port))
                data, address = client.recvfrom(4096)
                endpoint = data.decode()
                print(f" req number {i}; response: {endpoint}")
                if endpoint not in endpoints:
                    endpoints[endpoint] = 1
                else:
                    endpoints[endpoint] = endpoints[endpoint] + 1
                client.close()
            retry += 1
            wait_before_test(1)
            print(f"Retry #{retry}")

        assert len(endpoints) == 3

        # Step 3 - restore

        self.restore_ts(kube_apis, transport_server_setup)

    @pytest.mark.skip_for_nginx_oss
    def test_udp_failing_healthcheck_with_match(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Configure a failing health check and check that NGINX Plus doesn't respond.
        """

        # Step 1 - configure a failing health check

        patch_src = f"{TEST_DATA}/transport-server-udp-load-balance/failing-hc-transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        wait_before_test(4)

        result_conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            transport_server_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        match = f"match_ts_{transport_server_setup.namespace}_transport-server_udp-app"

        assert "health_check interval=5s" in result_conf
        assert f"passes=1 jitter=0s fails=1 udp match={match}" in result_conf
        assert "health_check_timeout 3s;"
        assert 'send "health"' in result_conf
        assert 'expect  "unmatched"' in result_conf

        # Step 2 - confirm load balancing doesn't work

        port = transport_server_setup.public_endpoint.udp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        host = host.strip("[]")
        client = socket.socket(ipfamily_from_host(host), socket.SOCK_DGRAM, 0)
        client.settimeout(2)
        client.sendto(b"ping", (host, port))
        try:
            # client.recvfrom(4096)
            data, address = client.recvfrom(4096)
            endpoint = data.decode()
            print(f" req number  response: {endpoint}")
            # it should timeout
            pytest.fail("expected a timeout")
        except socket.timeout:
            print("successfully timed out")
        client.close()

        # Step 3 - restore

        self.restore_ts(kube_apis, transport_server_setup)

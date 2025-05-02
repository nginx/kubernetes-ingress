import re
import socket
import ssl
from datetime import datetime

import pytest
from settings import TEST_DATA
from suite.utils.custom_resources_utils import create_ts_from_yaml, delete_ts, patch_ts_from_yaml, read_ts
from suite.utils.resources_utils import (
    create_secret_from_yaml,
    delete_items_from_yaml,
    get_reload_count,
    get_ts_nginx_template_conf,
    replace_secret,
    scale_deployment,
    wait_before_test,
)
from suite.utils.yaml_utils import get_secret_name_from_vs_or_ts_yaml


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
                    "-enable-prometheus-metrics",
                    "-ssl-dynamic-reload=false",
                ],
            },
            {"example": "transport-server-tcp-load-balance"},
        )
    ],
    indirect=True,
)
class TestTransportServerTcpLoadBalance:
    def restore_ts(self, kube_apis, transport_server_setup) -> None:
        """
        Function to revert a TransportServer resource to a valid state.
        """
        patch_src = f"{TEST_DATA}/transport-server-tcp-load-balance/standard/transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        wait_before_test()

    def test_number_of_replicas(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        The load balancing of TCP should result in 4 servers to match the 4 replicas of a service.
        """
        original = scale_deployment(
            kube_apis.v1, kube_apis.apps_v1_api, "tcp-service", transport_server_setup.namespace, 4
        )

        num_servers = 0
        retry = 0

        while num_servers != 4 and retry <= 30:
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

        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "tcp-service", transport_server_setup.namespace, original)
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

    def test_tcp_request_load_balanced(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Requests to the load balanced TCP service should result in responses from 3 different endpoints.
        """
        wait_before_test()
        port = transport_server_setup.public_endpoint.tcp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        print(f"sending tcp requests to: {host}:{port}")

        endpoints = {}
        retry = 0
        while len(endpoints) != 3 and retry <= 30:
            for i in range(20):
                host = host.strip("[]")
                client = socket.create_connection((host, port))
                client.sendall(b"connect")
                response = client.recv(4096)
                endpoint = response.decode()
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
                if key in server:
                    found = True
            assert found

    def test_tcp_request_load_balanced_multiple(self, kube_apis, crd_ingress_controller, transport_server_setup):
        """
        Requests to the load balanced TCP service should result in responses from 3 different endpoints.
        """
        port = transport_server_setup.public_endpoint.tcp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        # Step 1, confirm load balancing is working.
        print(f"sending tcp requests to: {host}:{port}")
        host = host.strip("[]")
        client = socket.create_connection((host, port))
        client.sendall(b"connect")
        response = client.recv(4096)
        endpoint = response.decode()
        print(f"response: {endpoint}")
        client.close()
        assert endpoint != ""

        # Step 2, add a second TransportServer with the same port and confirm the collision
        transport_server_file = f"{TEST_DATA}/transport-server-tcp-load-balance/second-transport-server.yaml"
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
            and response["status"]["message"] == "Listener tcp-server with host empty host is taken by another resource"
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
        print(f"sending tcp requests to: {host}:{port}")
        host = host.strip("[]")
        client = socket.create_connection((host, port))
        client.sendall(b"connect")
        response = client.recv(4096)
        endpoint = response.decode()
        print(f"response: {endpoint}")
        client.close()
        assert endpoint != ""

        # cleanup
        delete_ts(kube_apis.custom_objects, ts_resource, transport_server_setup.namespace)
        transport_server_file = f"{TEST_DATA}/transport-server-tcp-load-balance/standard/transport-server.yaml"
        create_ts_from_yaml(kube_apis.custom_objects, transport_server_file, transport_server_setup.namespace)
        wait_before_test()

    def test_tcp_request_load_balanced_wrong_port(self, kube_apis, crd_ingress_controller, transport_server_setup):
        """
        Requests to the load balanced TCP service should result in responses from 3 different endpoints.
        """

        patch_src = f"{TEST_DATA}/transport-server-tcp-load-balance/wrong-port-transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )

        wait_before_test()

        port = transport_server_setup.public_endpoint.tcp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        print(f"sending tcp requests to: {host}:{port}")
        for i in range(3):
            try:
                host = host.strip("[]")
                client = socket.create_connection((host, port))
                client.sendall(b"connect")
            except ConnectionResetError as E:
                print("The expected exception occurred:", E)

        self.restore_ts(kube_apis, transport_server_setup)

    def test_tcp_request_load_balanced_missing_service(self, kube_apis, crd_ingress_controller, transport_server_setup):
        """
        Requests to the load balanced TCP service should result in responses from 3 different endpoints.
        """

        patch_src = f"{TEST_DATA}/transport-server-tcp-load-balance/missing-service-transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )

        wait_before_test()

        port = transport_server_setup.public_endpoint.tcp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        print(f"sending tcp requests to: {host}:{port}")
        for i in range(3):
            try:
                host = host.strip("[]")
                client = socket.create_connection((host, port))
                client.sendall(b"connect")
            except ConnectionResetError as E:
                print("The expected exception occurred:", E)

        self.restore_ts(kube_apis, transport_server_setup)

    def make_holding_connection(self, host, port):
        print(f"sending tcp requests to: {host}:{port}")
        host = host.strip("[]")
        client = socket.create_connection((host, port))
        client.sendall(b"hold")
        response = client.recv(4096)
        endpoint = response.decode()
        print(f"response: {endpoint}")
        return client

    def test_tcp_request_max_connections(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        The config, maxConns, should limit the number of open TCP connections.
        3 replicas of max 2 connections is 6, so making the 7th connection will fail.
        """

        # step 1 - set max connections to 2 with 1 replica
        patch_src = f"{TEST_DATA}/transport-server-tcp-load-balance/max-connections-transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        wait_before_test()
        configs = 0
        retry = 0
        while configs != 3 and retry <= 30:
            result_conf = get_ts_nginx_template_conf(
                kube_apis.v1,
                transport_server_setup.namespace,
                transport_server_setup.name,
                transport_server_setup.ingress_pod_name,
                ingress_controller_prerequisites.namespace,
            )

            pattern = "max_conns=2"
            configs = len(re.findall(pattern, result_conf))
            retry += 1
            wait_before_test(1)
            print(f"Retry #{retry}")

        assert configs == 3

        # step 2 - make the number of allowed connections
        port = transport_server_setup.public_endpoint.tcp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        clients = []
        for i in range(6):
            c = self.make_holding_connection(host, port)
            clients.append(c)

        # step 3 - assert the next connection fails
        try:
            c = self.make_holding_connection(host, port)
            # making a connection should fail and throw an exception
            assert c is None
        except ConnectionResetError as E:
            print("The expected exception occurred:", E)

        for c in clients:
            c.close()

        # step 4 - revert to config with no max connections
        patch_src = f"{TEST_DATA}/transport-server-tcp-load-balance/standard/transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        wait_before_test()

        # step 5 - confirm making lots of connections doesn't cause an error
        clients = []
        for i in range(24):
            c = self.make_holding_connection(host, port)
            clients.append(c)

        for c in clients:
            c.close()

    def test_tcp_request_load_balanced_method(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Update load balancing method to 'hash'. This send requests to a specific pod based on it's IP. In this case
        resulting in a single endpoint handling all the requests.
        """

        # Step 1 - set the load balancing method.

        patch_src = f"{TEST_DATA}/transport-server-tcp-load-balance/method-transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        wait_before_test()
        num_servers = 0
        retry = 0
        while num_servers != 3 and retry <= 30:
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

        assert num_servers == 3

        # Step 2 - confirm all request go to the same endpoint.

        port = transport_server_setup.public_endpoint.tcp_server_port
        host = transport_server_setup.public_endpoint.public_ip
        endpoints = {}
        retry = 0
        while len(endpoints) != 1 and retry <= 30:
            for i in range(20):
                host = host.strip("[]")
                client = socket.create_connection((host, port))
                client.sendall(b"connect")
                response = client.recv(4096)
                endpoint = response.decode()
                print(f" req number {i}; response: {endpoint}")
                if endpoint not in endpoints:
                    endpoints[endpoint] = 1
                else:
                    endpoints[endpoint] = endpoints[endpoint] + 1
                client.close()
            retry += 1
            wait_before_test(1)
            print(f"Retry #{retry}")

        assert len(endpoints) == 1

        # Step 3 - restore to default load balancing method and confirm requests are balanced.

        self.restore_ts(kube_apis, transport_server_setup)
        wait_before_test()

        endpoints = {}
        retry = 0
        while len(endpoints) != 3 and retry <= 30:
            for i in range(20):
                host = host.strip("[]")
                client = socket.create_connection((host, port))
                client.sendall(b"connect")
                response = client.recv(4096)
                endpoint = response.decode()
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

    @pytest.mark.skip_for_nginx_oss
    def test_tcp_passing_healthcheck_with_match(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Configure a passing health check and check that all backend pods return responses.
        """

        # Step 1 - configure a passing health check

        patch_src = f"{TEST_DATA}/transport-server-tcp-load-balance/passing-hc-transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        # 4s includes 3s timeout for a health check to fail in case of a connection timeout to a backend pod
        wait_before_test(4)

        result_conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            transport_server_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        match = f"match_ts_{transport_server_setup.namespace}_transport-server_tcp-app"

        assert "health_check interval=5s" in result_conf
        assert f"passes=1 jitter=0s fails=1 match={match}" in result_conf
        assert "health_check_timeout 3s;"
        assert 'send "health"' in result_conf
        assert 'expect  "healthy"' in result_conf

        # Step 2 - confirm load balancing works

        port = transport_server_setup.public_endpoint.tcp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        endpoints = {}
        retry = 0
        while len(endpoints) != 3 and retry <= 30:
            for i in range(20):
                host = host.strip("[]")
                client = socket.create_connection((host, port))
                client.sendall(b"connect")
                response = client.recv(4096)
                endpoint = response.decode()
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
    def test_tcp_failing_healthcheck_with_match(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Configure a failing health check and check that NGINX Plus resets connections.
        """

        # Step 1 - configure a failing health check

        patch_src = f"{TEST_DATA}/transport-server-tcp-load-balance/failing-hc-transport-server.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        # 4s includes 3s timeout for a health check to fail in case of a connection timeout to a backend pod
        wait_before_test(4)

        result_conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            transport_server_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        match = f"match_ts_{transport_server_setup.namespace}_transport-server_tcp-app"

        assert "health_check interval=5s" in result_conf
        assert f"passes=1 jitter=0s fails=1 match={match}" in result_conf
        assert "health_check_timeout 3s"
        assert 'send "health"' in result_conf
        assert 'expect  "unmatched"' in result_conf

        # Step 2 - confirm load balancing doesn't work

        port = transport_server_setup.public_endpoint.tcp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        host = host.strip("[]")
        client = socket.create_connection((host, port))
        client.sendall(b"connect")

        try:
            client.recv(4096)  # must return ConnectionResetError
            client.close()
            pytest.fail("We expected an error here, but didn't get it. Exiting...")
        except ConnectionResetError as ex:
            # expected error
            print(f"There was an expected exception {str(ex)}")

        # Step 3 - restore

        self.restore_ts(kube_apis, transport_server_setup)

    def test_secure_tcp_request_load_balanced(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Sends requests to a TLS enabled load balanced TCP service.
        """
        src_sec_yaml = f"{TEST_DATA}/transport-server-tcp-load-balance/tcp-tls-secret.yaml"
        src_new_sec_yaml = f"{TEST_DATA}/transport-server-tcp-load-balance/new-tls-secret.yaml"
        create_secret_from_yaml(kube_apis.v1, transport_server_setup.namespace, src_sec_yaml)
        patch_src = f"{TEST_DATA}/transport-server-tcp-load-balance/transport-server-tls.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        wait_before_test()

        result_conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            transport_server_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        port = transport_server_setup.public_endpoint.tcp_server_port
        host = transport_server_setup.public_endpoint.public_ip

        sec_name = get_secret_name_from_vs_or_ts_yaml(patch_src)
        cert_name = f"{transport_server_setup.namespace}-{sec_name}"

        assert f"listen 3333 ssl;" in result_conf
        assert f"ssl_certificate /etc/nginx/secrets/{cert_name};" in result_conf
        assert f"ssl_certificate_key /etc/nginx/secrets/{cert_name};" in result_conf

        print(f"sending tcp requests to: {host}:{port}")

        host = host.strip("[]")
        with socket.create_connection((host, port)) as sock:
            ctx = ssl.SSLContext()
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # only secure TLSv1_2+ is allowed
            ssock = ctx.wrap_socket(sock)
            print(ssock.version())
            ssock.sendall(b"connect")
            response = ssock.recv(4096)
            endpoint = response.decode()
            print(f"Connected securely to: {endpoint}")

        # with -ssl-dynamic-reload=false, we expect
        # replacing a secret to trigger a reload
        count_before_replace = get_reload_count(transport_server_setup.metrics_url)
        print(f"replacing: {sec_name} in {transport_server_setup.namespace}")
        replace_secret(kube_apis.v1, sec_name, transport_server_setup.namespace, src_new_sec_yaml)
        wait_before_test()
        print(f"waited to {datetime.now().strftime('%m/%d/%Y, %H:%M:%S')}")
        count_after = get_reload_count(transport_server_setup.metrics_url)
        reloads = count_after - count_before_replace
        expected_reloads = 1
        assert reloads == expected_reloads, f"expected {expected_reloads} reloads, got {reloads}"

        self.restore_ts(kube_apis, transport_server_setup)
        delete_items_from_yaml(kube_apis, src_sec_yaml, transport_server_setup.namespace)


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
                    "-enable-prometheus-metrics",
                    "-log-level=debug",
                ],
            },
            {"example": "transport-server-tcp-load-balance"},
        )
    ],
    indirect=True,
)
class TestTransportServerTcpLoadBalanceDynamicReload:
    def test_dynamic_reload(
        self, kube_apis, crd_ingress_controller, transport_server_setup, ingress_controller_prerequisites
    ):
        """
        Updates a secret used by the transport server and verifies that NGINX is not reloaded.
        """
        src_sec_yaml = f"{TEST_DATA}/transport-server-tcp-load-balance/tcp-tls-secret.yaml"
        src_new_sec_yaml = f"{TEST_DATA}/transport-server-tcp-load-balance/new-tls-secret.yaml"
        create_secret_from_yaml(kube_apis.v1, transport_server_setup.namespace, src_sec_yaml)
        patch_src = f"{TEST_DATA}/transport-server-tcp-load-balance/transport-server-tls.yaml"
        patch_ts_from_yaml(
            kube_apis.custom_objects,
            transport_server_setup.name,
            patch_src,
            transport_server_setup.namespace,
        )
        wait_before_test()

        result_conf = get_ts_nginx_template_conf(
            kube_apis.v1,
            transport_server_setup.namespace,
            transport_server_setup.name,
            transport_server_setup.ingress_pod_name,
            ingress_controller_prerequisites.namespace,
        )

        sec_name = get_secret_name_from_vs_or_ts_yaml(patch_src)
        cert_name = f"{transport_server_setup.namespace}-{sec_name}"

        assert f"listen 3333 ssl;" in result_conf
        assert f"ssl_certificate $secret_dir_path/{cert_name};" in result_conf
        assert f"ssl_certificate_key $secret_dir_path/{cert_name};" in result_conf

        # for Plus with -ssl-dynamic-reload=true, we expect
        # replacing a secret not to trigger a reload
        count_before_replace = get_reload_count(transport_server_setup.metrics_url)
        print(f"replacing: {sec_name} in {transport_server_setup.namespace}")
        replace_secret(kube_apis.v1, sec_name, transport_server_setup.namespace, src_new_sec_yaml)
        wait_before_test()
        print(f"waited to {datetime.now().strftime('%m/%d/%Y, %H:%M:%S')}")
        count_after = get_reload_count(transport_server_setup.metrics_url)
        reloads = count_after - count_before_replace
        expected_reloads = 0
        assert reloads == expected_reloads, f"expected {expected_reloads} reloads, got {reloads}"

        delete_items_from_yaml(kube_apis, src_sec_yaml, transport_server_setup.namespace)

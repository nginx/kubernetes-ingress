from collections import namedtuple

import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import (
    create_secret_from_yaml,
    delete_items_from_yaml,
    delete_secret,
    get_apikey_auth_secrets_from_yaml,
    get_apikey_policy_details_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import create_v_s_route_from_yaml, delete_and_create_vs_from_yaml

apikey_auth_pol_valid = f"{TEST_DATA}/apikey-auth-policy/policies/apikey-policy-valid.yaml"
apikey_auth_pol_valid_2 = f"{TEST_DATA}/apikey-auth-policy/policies/apikey-policy-valid-2.yaml"
apikey_auth_pol_server = f"{TEST_DATA}/apikey-auth-policy/policies/apikey-policy-server.yaml"
apikey_auth_pol_route = f"{TEST_DATA}/apikey-auth-policy/policies/apikey-policy-vs-route.yaml"

apikey_auth_secret_1 = f"{TEST_DATA}/apikey-auth-policy/secret/apikey-secret-1.yaml"
apikey_auth_secret_2 = f"{TEST_DATA}/apikey-auth-policy/secret/apikey-secret-2.yaml"
apikey_auth_secret_server = f"{TEST_DATA}/apikey-auth-policy/secret/apikey-secret-server.yaml"
apikey_auth_secret_route = f"{TEST_DATA}/apikey-auth-policy/secret/apikey-secret-route.yaml"

apikey_auth_vs_single_src = f"{TEST_DATA}/apikey-auth-policy/spec/virtual-server-policy-single.yaml"
apikey_auth_vs_vsr_src = f"{TEST_DATA}/apikey-auth-policy/spec/vsr/virtual-server-with-vsr.yaml"

vsr_1_src = f"{TEST_DATA}/apikey-auth-policy/spec/vsr/backend1-vsr.yaml"
vsr_2_src = f"{TEST_DATA}/apikey-auth-policy/spec/vsr/backend2-vsr.yaml"


std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"


@pytest.mark.policies
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                    f"-enable-snippets",
                ],
            },
            {
                "example": "virtual-server",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestAPIKeyAuthPolicies:
    def setup_single_policy(
        self, kube_apis, test_namespace: str, secret_src: str, policy_src: str, vs_host: str
    ) -> namedtuple:
        APIKey_policy_details = namedtuple(
            "APIKey_policy_details", ["headers", "queries", "policy_name", "secret_name", "vs_host", "apikeys"]
        )
        print(f"Create apikey auth secret")
        secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, secret_src)
        apikeys = get_apikey_auth_secrets_from_yaml(secret_src)
        details = get_apikey_policy_details_from_yaml(policy_src)

        print(f"Create apikey auth policy")
        policy_name = create_policy_from_yaml(kube_apis.custom_objects, policy_src, test_namespace)
        wait_before_test()

        headers = details["headers"]
        queries = details["queries"]
        return APIKey_policy_details(
            headers=headers,
            queries=queries,
            policy_name=policy_name,
            secret_name=secret_name,
            vs_host=vs_host,
            apikeys=apikeys,
        )

    def test_apikey_auth_policy_vs(self, kube_apis, crd_ingress_controller, virtual_server_setup, test_namespace):
        apikey_policy_details = self.setup_single_policy(
            kube_apis,
            virtual_server_setup.namespace,
            apikey_auth_secret_1,
            apikey_auth_pol_valid,
            virtual_server_setup.vs_host,
        )

        apikey_policy_2_details = self.setup_single_policy(
            kube_apis,
            virtual_server_setup.namespace,
            apikey_auth_secret_2,
            apikey_auth_pol_valid_2,
            virtual_server_setup.vs_host,
        )

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            apikey_auth_vs_single_src,
            virtual_server_setup.namespace,
        )

        host = apikey_policy_details.vs_host

        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        wait_before_test()

        # /undefined path (is not a route defined in the VirtualServer)
        undefined_without_auth_headers = {"host": host}
        undefined_with_wrong_auth_header = {"host": host, apikey_policy_details.headers[0]: "wrongpassword"}
        undefined_with_auth_headers = {"host": host, apikey_policy_details.headers[0]: apikey_policy_details.apikeys[0]}
        undefined_path = (
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/undefined"
        )
        undefined_resp_no_auth_header = requests.get(undefined_path, headers=undefined_without_auth_headers)
        undefined_resp_with_wrong_auth_header = requests.get(undefined_path, headers=undefined_with_wrong_auth_header)
        undefined_resp_with_auth_header = requests.get(undefined_path, headers=undefined_with_auth_headers)

        # /no-auth path
        no_auth_headers = {"host": host}
        no_auth_path = (
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/no-auth"
        )
        no_auth_resp = requests.get(no_auth_path, headers=no_auth_headers)

        # /backend1 path (uses policy on the server level)
        # without auth headers
        backend1_without_auth_headers = {
            "host": host,
        }
        backend1_without_auth_resp = requests.get(
            virtual_server_setup.backend_1_url, headers=backend1_without_auth_headers
        )
        # with wrong password in header
        backend1_correct_header_with_wrong_password_resps = []
        for header in apikey_policy_details.headers:
            backend1_with_auth_headers_but_wrong_password = {"host": host, header: "wrongpassword"}
            backend1_wrong_password_resp = requests.get(
                virtual_server_setup.backend_1_url, headers=backend1_with_auth_headers_but_wrong_password
            )
            backend1_correct_header_with_wrong_password_resps.append(backend1_wrong_password_resp)
        # with wrong password in query
        backend1_correct_query_with_wrong_password_resps = []
        for query in apikey_policy_details.queries:
            host_header = {"host": host}
            params = {query: "wrongpassword"}
            backend1_wrong_password_resp = requests.get(
                virtual_server_setup.backend_1_url, headers=host_header, params=params
            )
            backend1_correct_query_with_wrong_password_resps.append(backend1_wrong_password_resp)
        # try each header with each correct apikey
        backend1_correct_header_with_correct_password_resps = []
        for header in apikey_policy_details.headers:
            for key in apikey_policy_details.apikeys:
                backend1_with_auth_headers_correct_password = {"host": host, header: key}
                backend1_correct_password_resp = requests.get(
                    virtual_server_setup.backend_1_url, headers=backend1_with_auth_headers_correct_password
                )
                backend1_correct_header_with_correct_password_resps.append(backend1_correct_password_resp)
        # try each query with each correct apikey
        backend1_correct_query_with_correct_password_resps = []
        for query in apikey_policy_details.queries:
            for key in apikey_policy_details.apikeys:
                params = {query: key}
                host_header = {"host": host}
                backend1_correct_password_resp = requests.get(
                    virtual_server_setup.backend_1_url, headers=host_header, params=params
                )
                backend1_correct_query_with_correct_password_resps.append(backend1_correct_password_resp)

        # /backend2 path (uses policy on the route level)
        # without auth headers
        backend2_without_auth_headers = {"host": host}
        backend2_without_auth_resp = requests.get(
            virtual_server_setup.backend_2_url, headers=backend2_without_auth_headers
        )
        # with wrong password in header
        backend2_correct_header_with_wrong_password_resps = []
        for header in apikey_policy_2_details.headers:
            backend2_with_auth_headers_but_wrong_password = {"host": host, header: "wrongpassword"}
            backend2_wrong_password_resp = requests.get(
                virtual_server_setup.backend_2_url, headers=backend2_with_auth_headers_but_wrong_password
            )
            backend2_correct_header_with_wrong_password_resps.append(backend2_wrong_password_resp)
        # with wrong password in query
        backend2_correct_query_with_wrong_password_resps = []
        for query in apikey_policy_2_details.queries:
            host_header = {"host": host}
            params = {query: "wrongpassword"}
            backend2_wrong_password_resp = requests.get(
                virtual_server_setup.backend_2_url, headers=host_header, params=params
            )
            backend2_correct_query_with_wrong_password_resps.append(backend2_wrong_password_resp)
        # try each header with each correct apikey
        backend2_correct_header_with_correct_password_resps = []
        for header in apikey_policy_2_details.headers:
            for key in apikey_policy_2_details.apikeys:
                backend2_with_auth_headers_correct_password = {"host": host, header: key}
                backend2_correct_password_resp = requests.get(
                    virtual_server_setup.backend_2_url, headers=backend2_with_auth_headers_correct_password
                )
                backend2_correct_header_with_correct_password_resps.append(backend2_correct_password_resp)
        # try each query with each correct apikey
        backend2_correct_query_with_correct_password_resps = []
        for query in apikey_policy_2_details.queries:
            for key in apikey_policy_2_details.apikeys:
                params = {query: key}
                host_header = {"host": host}
                backend2_correct_password_resp = requests.get(
                    virtual_server_setup.backend_2_url, headers=host_header, params=params
                )
                backend2_correct_query_with_correct_password_resps.append(backend2_correct_password_resp)

        delete_policy(kube_apis.custom_objects, apikey_policy_details.policy_name, test_namespace)
        delete_secret(kube_apis.v1, apikey_policy_details.secret_name, test_namespace)

        delete_policy(kube_apis.custom_objects, apikey_policy_2_details.policy_name, test_namespace)
        delete_secret(kube_apis.v1, apikey_policy_2_details.secret_name, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        # /undefined (without an auth header)
        assert undefined_resp_no_auth_header.status_code == 401

        # /undefined (with wrong password in header)
        assert undefined_resp_with_wrong_auth_header.status_code == 403

        # /undefined (with an auth header)
        assert undefined_resp_with_auth_header.status_code == 404

        # /no-auth (snippet to turn off auth_request on this route)
        assert no_auth_resp.status_code == 200

        # /backend1 (policy on server level)
        assert backend1_without_auth_resp.status_code == 401

        # with wrong password in header
        assert len(backend1_correct_header_with_wrong_password_resps) > 0
        for response in backend1_correct_header_with_wrong_password_resps:
            assert response.status_code == 403

        # with wrong password in query
        assert len(backend1_correct_query_with_wrong_password_resps) > 0
        for response in backend1_correct_query_with_wrong_password_resps:
            assert response.status_code == 403

        # with correct password in header
        assert len(backend1_correct_header_with_correct_password_resps) > 0
        for response in backend1_correct_header_with_correct_password_resps:
            assert response.status_code == 200

        # with correct password in query
        assert len(backend1_correct_query_with_correct_password_resps) > 0
        for response in backend1_correct_query_with_correct_password_resps:
            assert response.status_code == 200

        # /backend2 (policy on route level)
        assert backend2_without_auth_resp.status_code == 401

        # with wrong password in header
        assert len(backend2_correct_header_with_wrong_password_resps) > 0
        for response in backend2_correct_header_with_wrong_password_resps:
            assert response.status_code == 403

        # with wrong password in query
        assert len(backend2_correct_query_with_wrong_password_resps) > 0
        for response in backend2_correct_query_with_wrong_password_resps:
            assert response.status_code == 403

        # with correct password in header
        assert len(backend2_correct_header_with_correct_password_resps) > 0
        for response in backend2_correct_header_with_correct_password_resps:
            assert response.status_code == 200

        # with correct password in query
        assert len(backend2_correct_query_with_correct_password_resps) > 0
        for response in backend2_correct_query_with_correct_password_resps:
            assert response.status_code == 200

    def test_apikey_auth_policy_vs_and_vsr(
        self, kube_apis, crd_ingress_controller, virtual_server_setup, test_namespace
    ):
        apikey_policy_details_server = self.setup_single_policy(
            kube_apis,
            virtual_server_setup.namespace,
            apikey_auth_secret_server,
            apikey_auth_pol_server,
            virtual_server_setup.vs_host,
        )

        apikey_policy_details_route = self.setup_single_policy(
            kube_apis,
            virtual_server_setup.namespace,
            apikey_auth_secret_route,
            apikey_auth_pol_route,
            virtual_server_setup.vs_host,
        )

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            apikey_auth_vs_vsr_src,
            virtual_server_setup.namespace,
        )
        create_v_s_route_from_yaml(kube_apis.custom_objects, vsr_1_src, virtual_server_setup.namespace)
        create_v_s_route_from_yaml(kube_apis.custom_objects, vsr_2_src, virtual_server_setup.namespace)

        host = virtual_server_setup.vs_host
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        wait_before_test(5)

        # /undefined path (is not a route defined in the VirtualServer)
        undefined_without_auth_headers = {"host": host}
        undefined_with_wrong_auth_header = {"host": host, apikey_policy_details_server.headers[0]: "wrongpassword"}
        undefined_with_auth_headers = {
            "host": host,
            apikey_policy_details_server.headers[0]: apikey_policy_details_server.apikeys[0],
        }
        undefined_path = (
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/undefined"
        )
        undefined_resp_no_auth_header = requests.get(undefined_path, headers=undefined_without_auth_headers)
        undefined_resp_with_wrong_auth_header = requests.get(undefined_path, headers=undefined_with_wrong_auth_header)
        undefined_resp_with_auth_header = requests.get(undefined_path, headers=undefined_with_auth_headers)

        # /no-auth path
        no_auth_path_server = (
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/no-auth"
        )

        no_auth_headers = {
            "host": host,
        }
        no_auth_server_resp = requests.get(no_auth_path_server, headers=no_auth_headers)

        # /backend1 (no policy on this vsr route so uses server level policy)
        backend1_path = (
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/backend1"
        )
        backend1_without_auth_headers = {"host": host}
        backend1_without_auth_resp = requests.get(backend1_path, headers=backend1_without_auth_headers)

        # with wrong password in header
        backend1_correct_header_with_wrong_password_resps = []
        for header in apikey_policy_details_server.headers:
            backend1_with_auth_headers = {"host": host, header: "wrongpassword"}
            backend1_wrong_password = requests.get(backend1_path, headers=backend1_with_auth_headers)
            backend1_correct_header_with_wrong_password_resps.append(backend1_wrong_password)
        # with wrong password in query
        backend1_correct_query_with_wrong_password_resps = []
        for query in apikey_policy_details_server.queries:
            host_header = {"host": host}
            params = {query: "wrongpassword"}
            backend1_wrong_password_resp = requests.get(backend1_path, headers=host_header, params=params)
            backend1_correct_query_with_wrong_password_resps.append(backend1_wrong_password_resp)
        # try each header with each correct apikey
        backend1_correct_header_with_correct_password_resps = []
        for header in apikey_policy_details_server.headers:
            for key in apikey_policy_details_server.apikeys:
                backend1_with_auth_headers_correct_password = {"host": host, header: key}
                backend1_correct_password_resp = requests.get(
                    backend1_path, headers=backend1_with_auth_headers_correct_password
                )
                backend1_correct_header_with_correct_password_resps.append(backend1_correct_password_resp)
        # try each query with each correct apikey
        backend1_correct_query_with_correct_password_resps = []
        for query in apikey_policy_details_server.queries:
            for key in apikey_policy_details_server.apikeys:
                params = {query: key}
                host_header = {"host": host}
                backend1_correct_password_resp = requests.get(backend1_path, headers=host_header, params=params)
                backend1_correct_query_with_correct_password_resps.append(backend1_correct_password_resp)

        # /backend2 path (uses policy on the route level)
        backend2_path = (
            f"http://{virtual_server_setup.public_endpoint.public_ip}"
            f":{virtual_server_setup.public_endpoint.port}/backend2"
        )
        # without auth headers
        backend2_without_auth_headers = {"host": host}
        backend2_without_auth_resp = requests.get(backend2_path, headers=backend2_without_auth_headers)
        # with wrong password in header
        backend2_correct_header_with_wrong_password_resps = []
        for header in apikey_policy_details_route.headers:
            backend2_with_auth_headers_but_wrong_password = {"host": host, header: "wrongpassword"}
            backend2_wrong_password_resp = requests.get(
                backend2_path, headers=backend2_with_auth_headers_but_wrong_password
            )
            backend2_correct_header_with_wrong_password_resps.append(backend2_wrong_password_resp)
        # with wrong password in query
        backend2_correct_query_with_wrong_password_resps = []
        for query in apikey_policy_details_route.queries:
            host_header = {"host": host}
            params = {query: "wrongpassword"}
            backend2_wrong_password_resp = requests.get(backend2_path, headers=host_header, params=params)
            backend2_correct_query_with_wrong_password_resps.append(backend2_wrong_password_resp)
        # try each header with each correct apikey
        backend2_correct_header_with_correct_password_resps = []
        for header in apikey_policy_details_route.headers:
            for key in apikey_policy_details_route.apikeys:
                backend2_with_auth_headers_correct_password = {"host": host, header: key}
                backend2_correct_password_resp = requests.get(
                    backend2_path, headers=backend2_with_auth_headers_correct_password
                )
                backend2_correct_header_with_correct_password_resps.append(backend2_correct_password_resp)
        # try each query with each correct apikey
        backend2_correct_query_with_correct_password_resps = []
        for query in apikey_policy_details_route.queries:
            for key in apikey_policy_details_route.apikeys:
                params = {query: key}
                host_header = {"host": host}
                backend2_correct_password_resp = requests.get(backend2_path, headers=host_header, params=params)
                backend2_correct_query_with_correct_password_resps.append(backend2_correct_password_resp)

        delete_items_from_yaml(kube_apis.custom_objects, vsr_1_src, virtual_server_setup.namespace)
        delete_items_from_yaml(kube_apis.custom_objects, vsr_2_src, virtual_server_setup.namespace)

        delete_policy(kube_apis.custom_objects, apikey_policy_details_server.policy_name, test_namespace)
        delete_secret(kube_apis.v1, apikey_policy_details_server.secret_name, test_namespace)

        delete_policy(kube_apis.custom_objects, apikey_policy_details_route.policy_name, test_namespace)
        delete_secret(kube_apis.v1, apikey_policy_details_route.secret_name, test_namespace)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        # /undefined (without an auth header)
        assert undefined_resp_no_auth_header.status_code == 401

        # /undefined (with wrong password in header)
        assert undefined_resp_with_wrong_auth_header.status_code == 403

        # /undefined (with an auth header)
        assert undefined_resp_with_auth_header.status_code == 404

        # /no-auth (snippet to turn off auth_request on this route)
        assert no_auth_server_resp.status_code == 200

        # /backend1 (policy on server level)
        assert backend1_without_auth_resp.status_code == 401

        # with wrong password in header
        assert len(backend1_correct_header_with_wrong_password_resps) > 0
        for response in backend1_correct_header_with_wrong_password_resps:
            assert response.status_code == 403

        assert len(backend1_correct_query_with_wrong_password_resps) > 0
        for response in backend1_correct_query_with_wrong_password_resps:
            assert response.status_code == 403

        # with correct password in header
        assert len(backend1_correct_header_with_correct_password_resps) > 0
        for response in backend1_correct_header_with_correct_password_resps:
            assert response.status_code == 200

        # with correct password in query
        assert len(backend1_correct_query_with_correct_password_resps) > 0
        for response in backend1_correct_query_with_correct_password_resps:
            assert response.status_code == 200

        # /backend2 (policy on route level)
        assert backend2_without_auth_resp.status_code == 401

        # with wrong password in header
        assert len(backend2_correct_header_with_wrong_password_resps) > 0
        for response in backend2_correct_header_with_wrong_password_resps:
            assert response.status_code == 403

        # with wrong password in query
        assert len(backend2_correct_query_with_wrong_password_resps) > 0
        for response in backend2_correct_query_with_wrong_password_resps:
            assert response.status_code == 403

        # with correct password in header
        assert len(backend2_correct_header_with_correct_password_resps) > 0
        for response in backend2_correct_header_with_correct_password_resps:
            assert response.status_code == 200

        # with correct password in query
        assert len(backend2_correct_query_with_correct_password_resps) > 0
        for response in backend2_correct_query_with_correct_password_resps:
            assert response.status_code == 200

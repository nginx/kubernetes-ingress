import hashlib

import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import apply_and_assert_valid_policy, delete_policy
from suite.utils.resources_utils import (
    IC_SELECTOR,
    close_sockets,
    get_first_pod_name,
    get_vs_nginx_template_conf,
    hold_requests_open,
    wait_before_test,
)
from suite.utils.vs_vsr_resources_utils import (
    apply_and_assert_valid_vs,
    apply_and_assert_valid_vsr,
    create_virtual_server_from_yaml,
    delete_and_create_v_s_route_from_yaml,
    delete_and_create_vs_from_yaml,
    delete_virtual_server,
)

std_vs_src = f"{TEST_DATA}/virtual-server-route/standard/virtual-server.yaml"
std_vsr_src = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
cl_pol_total_src = f"{TEST_DATA}/connection-limit/policies/connection-limit-total.yaml"
cl_vsr_subroute_src = f"{TEST_DATA}/connection-limit/route-subroute/virtual-server-route-subroute.yaml"
cl_vs_route_src = f"{TEST_DATA}/connection-limit/route-subroute/virtual-server-route.yaml"
cl_vsr_hostless_src = f"{TEST_DATA}/connection-limit/hostless/route-hostless.yaml"
cl_vs_2_src = f"{TEST_DATA}/connection-limit/hostless/virtual-server-2.yaml"

total_hash = hashlib.sha256(b"total").hexdigest()


@pytest.mark.policies
@pytest.mark.policies_cl
@pytest.mark.policies_cl_vsr
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                ],
            },
            {"example": "virtual-server-route"},
        )
    ],
    indirect=True,
)
class TestConnectionLimitPoliciesVsr:
    def restore_defaults(self, kube_apis, v_s_route_setup) -> None:
        """
        Restore the VirtualServer and the VirtualServerRoute without policies
        """
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            std_vs_src,
            v_s_route_setup.namespace,
        )
        delete_and_create_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()

    def hold(self, v_s_route_setup, host, path, count) -> list:
        return hold_requests_open(
            v_s_route_setup.public_endpoint.public_ip,
            v_s_route_setup.public_endpoint.port,
            host,
            path,
            count,
        )

    def get(self, v_s_route_setup, host, path) -> int:
        url = f"http://{v_s_route_setup.public_endpoint.public_ip}:{v_s_route_setup.public_endpoint.port}{path}"
        return requests.get(url, headers={"host": host}).status_code

    @pytest.mark.smoke
    def test_cl_policy_subroute(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
    ):
        """
        Test that a subroute Policy rejects requests over its limit with its status code
        """
        namespace = v_s_route_setup.route_m.namespace
        host = v_s_route_setup.vs_host
        path = v_s_route_setup.route_m.paths[0]
        pol_name = apply_and_assert_valid_policy(kube_apis, namespace, cl_pol_total_src)
        try:
            apply_and_assert_valid_vsr(kube_apis, namespace, v_s_route_setup.route_m.name, cl_vsr_subroute_src)

            ic_namespace = ingress_controller_prerequisites.namespace
            conf = get_vs_nginx_template_conf(
                kube_apis.v1,
                v_s_route_setup.namespace,
                v_s_route_setup.vs_name,
                get_first_pod_name(kube_apis.v1, ic_namespace, IC_SELECTOR),
                ic_namespace,
            )
            zone = (
                f"pol_cl_{namespace}_{pol_name}_vs_{v_s_route_setup.namespace}_{v_s_route_setup.vs_name}"
                f"_vsr_{namespace}_{v_s_route_setup.route_m.name}_{total_hash}"
            )
            assert f"limit_conn {zone} 1;" in conf

            sockets = self.hold(v_s_route_setup, host, path, 1)
            try:
                rejected = self.get(v_s_route_setup, host, path)
            finally:
                close_sockets(sockets)
            assert rejected == 429
            assert self.get(v_s_route_setup, host, path) == 200
        finally:
            delete_policy(kube_apis.custom_objects, pol_name, namespace)
            self.restore_defaults(kube_apis, v_s_route_setup)

    def test_cl_policy_vs_and_subroute_count_separately(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
    ):
        """
        Test that a VirtualServer route and a subroute that reference the same Policy count separately
        """
        namespace = v_s_route_setup.route_m.namespace
        host = v_s_route_setup.vs_host
        vs_path = "/backend3"
        vsr_path = v_s_route_setup.route_m.paths[0]
        pol_name = apply_and_assert_valid_policy(kube_apis, namespace, cl_pol_total_src)
        try:
            apply_and_assert_valid_vsr(kube_apis, namespace, v_s_route_setup.route_m.name, cl_vsr_subroute_src)
            apply_and_assert_valid_vs(kube_apis, v_s_route_setup.namespace, v_s_route_setup.vs_name, cl_vs_route_src)

            sockets = self.hold(v_s_route_setup, host, vs_path, 1)
            try:
                vsr_code = self.get(v_s_route_setup, host, vsr_path)
            finally:
                close_sockets(sockets)
            assert vsr_code == 200

            sockets = self.hold(v_s_route_setup, host, vsr_path, 1)
            try:
                vs_code = self.get(v_s_route_setup, host, vs_path)
            finally:
                close_sockets(sockets)
            assert vs_code == 200
        finally:
            delete_policy(kube_apis.custom_objects, pol_name, namespace)
            self.restore_defaults(kube_apis, v_s_route_setup)

    def test_cl_policy_hostless_vsr_counts_per_vs(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
    ):
        """
        Test that a hostless VirtualServerRoute shared by two VirtualServers counts separately for each
        """
        namespace = v_s_route_setup.route_m.namespace
        host_a = v_s_route_setup.vs_host
        path = v_s_route_setup.route_m.paths[0]
        pol_name = apply_and_assert_valid_policy(kube_apis, namespace, cl_pol_total_src)
        vs_2_name = create_virtual_server_from_yaml(kube_apis.custom_objects, cl_vs_2_src, namespace)
        host_b = "virtual-server-route-2.example.com"
        try:
            apply_and_assert_valid_vsr(kube_apis, namespace, v_s_route_setup.route_m.name, cl_vsr_hostless_src)
            wait_before_test()

            sockets = self.hold(v_s_route_setup, host_a, path, 1)
            try:
                code_b = self.get(v_s_route_setup, host_b, path)
                code_a = self.get(v_s_route_setup, host_a, path)
            finally:
                close_sockets(sockets)
            assert code_b == 200
            assert code_a == 429
        finally:
            delete_virtual_server(kube_apis.custom_objects, vs_2_name, namespace)
            delete_policy(kube_apis.custom_objects, pol_name, namespace)
            self.restore_defaults(kube_apis, v_s_route_setup)

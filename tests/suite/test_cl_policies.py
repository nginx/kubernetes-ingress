import hashlib

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import apply_and_assert_valid_policy, create_policy_from_yaml, delete_policy
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
    apply_and_assert_warning_vs,
    create_virtual_server_from_yaml,
    delete_virtual_server,
)

std_vs_src = f"{TEST_DATA}/connection-limit/standard/virtual-server.yaml"
cl_pol_total_src = f"{TEST_DATA}/connection-limit/policies/connection-limit-total.yaml"
cl_pol_total_2_src = f"{TEST_DATA}/connection-limit/policies/connection-limit-total-2.yaml"
cl_pol_dry_run_src = f"{TEST_DATA}/connection-limit/policies/connection-limit-dry-run.yaml"
cl_pol_invalid_src = f"{TEST_DATA}/connection-limit/policies/connection-limit-invalid.yaml"
cl_vs_total_src = f"{TEST_DATA}/connection-limit/spec/virtual-server-total.yaml"
cl_vs_dry_run_src = f"{TEST_DATA}/connection-limit/spec/virtual-server-dry-run.yaml"
cl_vs_invalid_src = f"{TEST_DATA}/connection-limit/spec/virtual-server-invalid.yaml"
cl_vs_override_route_src = f"{TEST_DATA}/connection-limit/spec/virtual-server-override-route.yaml"


def zone_name(pol_namespace, pol_name, vs_namespace, vs_name, key) -> str:
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return f"pol_cl_{pol_namespace}_{pol_name}_vs_{vs_namespace}_{vs_name}_{key_hash}"


@pytest.mark.policies
@pytest.mark.policies_cl
@pytest.mark.policies_cl_vs
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                ],
            },
            {
                "example": "connection-limit",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestConnectionLimitPolicies:
    def restore_default_vs(self, kube_apis, virtual_server_setup) -> None:
        """
        Restore VirtualServer without policies
        """
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace)
        create_virtual_server_from_yaml(kube_apis.custom_objects, std_vs_src, virtual_server_setup.namespace)
        wait_before_test()

    def hold(self, virtual_server_setup, path, count) -> list:
        return hold_requests_open(
            virtual_server_setup.public_endpoint.public_ip,
            virtual_server_setup.public_endpoint.port,
            virtual_server_setup.vs_host,
            path,
            count,
        )

    def get(self, virtual_server_setup, url) -> int:
        return requests.get(url, headers={"host": virtual_server_setup.vs_host}).status_code

    def get_conf(self, kube_apis, ingress_controller_prerequisites, virtual_server_setup) -> str:
        ic_namespace = ingress_controller_prerequisites.namespace
        return get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup.namespace,
            virtual_server_setup.vs_name,
            get_first_pod_name(kube_apis.v1, ic_namespace, IC_SELECTOR),
            ic_namespace,
        )

    @pytest.mark.smoke
    def test_cl_policy_limit(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that requests over the limit are rejected with the Policy status code
        """
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, cl_pol_total_src)
        try:
            apply_and_assert_valid_vs(
                kube_apis,
                virtual_server_setup.namespace,
                virtual_server_setup.vs_name,
                cl_vs_total_src,
            )
            conf = self.get_conf(kube_apis, ingress_controller_prerequisites, virtual_server_setup)
            zone = zone_name(
                test_namespace, pol_name, virtual_server_setup.namespace, virtual_server_setup.vs_name, "total"
            )
            assert f"limit_conn_zone total zone={zone}:10m;" in conf
            assert f"limit_conn {zone} 1;" in conf
            assert "limit_conn_status 429;" in conf

            sockets = self.hold(virtual_server_setup, "/backend1", 1)
            try:
                rejected = self.get(virtual_server_setup, virtual_server_setup.backend_1_url)
            finally:
                close_sockets(sockets)
            assert rejected == 429
            assert self.get(virtual_server_setup, virtual_server_setup.backend_1_url) == 200
        finally:
            delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            self.restore_default_vs(kube_apis, virtual_server_setup)

    def test_cl_policy_dry_run(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that a dry run Policy logs requests over the limit and does not reject them
        """
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, cl_pol_dry_run_src)
        try:
            apply_and_assert_valid_vs(
                kube_apis,
                virtual_server_setup.namespace,
                virtual_server_setup.vs_name,
                cl_vs_dry_run_src,
            )
            sockets = self.hold(virtual_server_setup, "/backend1", 1)
            try:
                code = self.get(virtual_server_setup, virtual_server_setup.backend_1_url)
            finally:
                close_sockets(sockets)
            assert code == 200

            ic_namespace = ingress_controller_prerequisites.namespace
            pod_name = get_first_pod_name(kube_apis.v1, ic_namespace, IC_SELECTOR)
            logs = kube_apis.v1.read_namespaced_pod_log(pod_name, ic_namespace)
            assert 'limiting connections, dry run, by zone "pol_cl_' in logs
        finally:
            delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            self.restore_default_vs(kube_apis, virtual_server_setup)

    def test_cl_policy_route_replaces_server(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that a route Policy replaces the server Policy on that route only
        """
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, cl_pol_total_src)
        pol_name_2 = apply_and_assert_valid_policy(kube_apis, test_namespace, cl_pol_total_2_src)
        try:
            apply_and_assert_valid_vs(
                kube_apis,
                virtual_server_setup.namespace,
                virtual_server_setup.vs_name,
                cl_vs_override_route_src,
            )

            sockets = self.hold(virtual_server_setup, "/backend1", 1)
            try:
                route_code = self.get(virtual_server_setup, virtual_server_setup.backend_1_url)
            finally:
                close_sockets(sockets)
            assert route_code == 200

            sockets = self.hold(virtual_server_setup, "/backend1", 2)
            try:
                route_code = self.get(virtual_server_setup, virtual_server_setup.backend_1_url)
                other_code = self.get(virtual_server_setup, virtual_server_setup.backend_2_url)
            finally:
                close_sockets(sockets)
            assert route_code == 503
            assert other_code == 200
        finally:
            delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            delete_policy(kube_apis.custom_objects, pol_name_2, test_namespace)
            self.restore_default_vs(kube_apis, virtual_server_setup)

    def test_cl_policy_invalid(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that an invalid Policy is rejected and its VirtualServer returns 500
        """
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, cl_pol_invalid_src, test_namespace)
        try:
            wait_before_test(1)
            policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
            assert (
                policy_info["status"]
                and policy_info["status"]["reason"] == "Rejected"
                and policy_info["status"]["state"] == "Invalid"
            )
            apply_and_assert_warning_vs(
                kube_apis,
                virtual_server_setup.namespace,
                virtual_server_setup.vs_name,
                cl_vs_invalid_src,
            )
            wait_before_test()
            assert self.get(virtual_server_setup, virtual_server_setup.backend_1_url) == 500
        finally:
            delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            self.restore_default_vs(kube_apis, virtual_server_setup)

    def test_cl_policy_key_change(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Test that changing the key of an attached Policy in place replaces its zone
        """
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, cl_pol_total_src)
        try:
            apply_and_assert_valid_vs(
                kube_apis,
                virtual_server_setup.namespace,
                virtual_server_setup.vs_name,
                cl_vs_total_src,
            )
            vs_namespace = virtual_server_setup.namespace
            vs_name = virtual_server_setup.vs_name
            old_zone = zone_name(test_namespace, pol_name, vs_namespace, vs_name, "total")
            new_zone = zone_name(test_namespace, pol_name, vs_namespace, vs_name, "${binary_remote_addr}")
            assert old_zone in self.get_conf(kube_apis, ingress_controller_prerequisites, virtual_server_setup)

            kube_apis.custom_objects.patch_namespaced_custom_object(
                "k8s.nginx.org",
                "v1",
                test_namespace,
                "policies",
                pol_name,
                {"spec": {"connectionLimit": {"key": "${binary_remote_addr}"}}},
            )
            wait_before_test()

            vs_info = read_custom_resource(kube_apis.custom_objects, vs_namespace, "virtualservers", vs_name)
            assert vs_info["status"]["state"] == "Valid", vs_info
            conf = self.get_conf(kube_apis, ingress_controller_prerequisites, virtual_server_setup)
            assert new_zone in conf
            assert old_zone not in conf
            assert self.get(virtual_server_setup, virtual_server_setup.backend_1_url) == 200
        finally:
            delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            self.restore_default_vs(kube_apis, virtual_server_setup)

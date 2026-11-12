import hashlib

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import apply_and_assert_valid_policy, create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import (
    IC_SELECTOR,
    close_sockets,
    create_example_app,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_response_from_backend,
    get_e2e_run_selector,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    hold_requests_open,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml, get_name_from_yaml

cl_pol_total_src = f"{TEST_DATA}/connection-limit/policies/connection-limit-total.yaml"
cl_pol_total_2_src = f"{TEST_DATA}/connection-limit/policies/connection-limit-total-2.yaml"
cl_pol_invalid_src = f"{TEST_DATA}/connection-limit/policies/connection-limit-invalid.yaml"
cl_ing_standard_src = f"{TEST_DATA}/connection-limit/ingress/standard/ingress.yaml"
cl_ing_mergeable_src = f"{TEST_DATA}/connection-limit/ingress/mergeable/ingress.yaml"
cl_ing_invalid_src = f"{TEST_DATA}/connection-limit/ingress/invalid/ingress.yaml"


def zone_name(pol_namespace, pol_name, ing_namespace, ing_name, key, minion_name="") -> str:
    name = f"pol_cl_{pol_namespace}_{pol_name}_ing_{ing_namespace}_{ing_name}"
    if minion_name:
        name = f"{name}_ing_{ing_namespace}_{minion_name}"
    return f"{name}_{hashlib.sha256(key.encode()).hexdigest()}"


@pytest.fixture(scope="function")
def backend_setup(request, kube_apis, test_namespace, e2e_run_id) -> None:
    create_example_app(kube_apis, "simple", test_namespace, e2e_run_id=e2e_run_id)
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace, get_e2e_run_selector(e2e_run_id))

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            delete_common_app(kube_apis, "simple", test_namespace)

    request.addfinalizer(fin)


@pytest.mark.policies
@pytest.mark.policies_cl
@pytest.mark.policies_cl_ingress
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        pytest.param(
            {
                "type": "complete",
                "extra_args": ["-enable-custom-resources", "-enable-leader-election=false"],
            }
        )
    ],
    indirect=["crd_ingress_controller"],
)
class TestConnectionLimitPoliciesIngress:
    def url(self, endpoint, path) -> str:
        return f"http://{endpoint.public_ip}:{endpoint.port}{path}"

    def hold(self, endpoint, host, path, count) -> list:
        return hold_requests_open(endpoint.public_ip, endpoint.port, host, path, count)

    def get(self, endpoint, host, path) -> int:
        return requests.get(self.url(endpoint, path), headers={"host": host}).status_code

    def get_conf(self, kube_apis, ingress_controller_prerequisites, namespace, ing_name) -> str:
        ic_namespace = ingress_controller_prerequisites.namespace
        return get_ingress_nginx_template_conf(
            kube_apis.v1,
            namespace,
            ing_name,
            get_first_pod_name(kube_apis.v1, ic_namespace, IC_SELECTOR),
            ic_namespace,
        )

    @pytest.mark.smoke
    def test_cl_policy_ingress(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ingress_controller_endpoint,
        backend_setup,
        test_namespace,
    ):
        """
        Test that the paths of an Ingress share its Policy limit, and requests over it get the Policy status code
        """
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, cl_pol_total_src)
        create_items_from_yaml(kube_apis, cl_ing_standard_src, test_namespace)
        try:
            host = get_first_ingress_host_from_yaml(cl_ing_standard_src)
            ing_name = get_name_from_yaml(cl_ing_standard_src)
            ensure_response_from_backend(self.url(ingress_controller_endpoint, "/backend1"), host, check404=True)

            conf = self.get_conf(kube_apis, ingress_controller_prerequisites, test_namespace, ing_name)
            zone = zone_name(test_namespace, pol_name, test_namespace, ing_name, "total")
            assert f"limit_conn_zone total zone={zone}:10m;" in conf
            assert f"limit_conn {zone} 1;" in conf
            assert "limit_conn_status 429;" in conf

            sockets = self.hold(ingress_controller_endpoint, host, "/backend1", 1)
            try:
                rejected = self.get(ingress_controller_endpoint, host, "/backend2")
            finally:
                close_sockets(sockets)
            assert rejected == 429
            assert self.get(ingress_controller_endpoint, host, "/backend2") == 200
        finally:
            delete_items_from_yaml(kube_apis, cl_ing_standard_src, test_namespace)
            delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

    def test_cl_policy_mergeable_ingress(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ingress_controller_endpoint,
        backend_setup,
        test_namespace,
    ):
        """
        Test that the master Policy applies to a minion without a Policy, and that a minion Policy replaces it
        for that minion and counts separately
        """
        pol_name = apply_and_assert_valid_policy(kube_apis, test_namespace, cl_pol_total_src)
        pol_name_2 = apply_and_assert_valid_policy(kube_apis, test_namespace, cl_pol_total_2_src)
        create_items_from_yaml(kube_apis, cl_ing_mergeable_src, test_namespace)
        try:
            host = get_first_ingress_host_from_yaml(cl_ing_mergeable_src)
            master_name = get_name_from_yaml(cl_ing_mergeable_src)
            ensure_response_from_backend(self.url(ingress_controller_endpoint, "/backend1"), host, check404=True)
            ensure_response_from_backend(self.url(ingress_controller_endpoint, "/backend2"), host, check404=True)

            conf = self.get_conf(kube_apis, ingress_controller_prerequisites, test_namespace, master_name)
            master_zone = zone_name(test_namespace, pol_name, test_namespace, master_name, "total")
            minion_zone = zone_name(
                test_namespace, pol_name_2, test_namespace, master_name, "total", "cl-ingress-minion-1"
            )
            assert f"limit_conn_zone total zone={master_zone}:10m;" in conf
            assert f"limit_conn_zone total zone={minion_zone}:10m;" in conf

            # The minion without a Policy gets the master limit; the other minion does not count against it.
            sockets = self.hold(ingress_controller_endpoint, host, "/backend2", 1)
            try:
                master_code = self.get(ingress_controller_endpoint, host, "/backend2")
                minion_code = self.get(ingress_controller_endpoint, host, "/backend1")
            finally:
                close_sockets(sockets)
            assert master_code == 429
            assert minion_code == 200

            # The minion Policy allows 2 and rejects with its own status code.
            sockets = self.hold(ingress_controller_endpoint, host, "/backend1", 2)
            try:
                minion_code = self.get(ingress_controller_endpoint, host, "/backend1")
                master_code = self.get(ingress_controller_endpoint, host, "/backend2")
            finally:
                close_sockets(sockets)
            assert minion_code == 503
            assert master_code == 200
        finally:
            delete_items_from_yaml(kube_apis, cl_ing_mergeable_src, test_namespace)
            delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            delete_policy(kube_apis.custom_objects, pol_name_2, test_namespace)

    def test_cl_policy_ingress_invalid(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        backend_setup,
        test_namespace,
    ):
        """
        Test that an Ingress that references an invalid Policy returns 500
        """
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, cl_pol_invalid_src, test_namespace)
        create_items_from_yaml(kube_apis, cl_ing_invalid_src, test_namespace)
        try:
            wait_before_test(1)
            policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
            assert (
                policy_info["status"]
                and policy_info["status"]["reason"] == "Rejected"
                and policy_info["status"]["state"] == "Invalid"
            )
            host = get_first_ingress_host_from_yaml(cl_ing_invalid_src)
            ensure_response_from_backend(self.url(ingress_controller_endpoint, "/backend1"), host, check404=True)
            assert self.get(ingress_controller_endpoint, host, "/backend1") == 500
        finally:
            delete_items_from_yaml(kube_apis, cl_ing_invalid_src, test_namespace)
            delete_policy(kube_apis.custom_objects, pol_name, test_namespace)

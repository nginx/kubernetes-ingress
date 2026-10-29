import pytest
from settings import TEST_DATA
from suite.utils.ap_resources_utils import (
    assert_waf_blocked,
    send_malicious_request_with_retry,
    wait_for_plm_bundle_ready,
)
from suite.utils.custom_resources_utils import create_resource_from_yaml, delete_resource
from suite.utils.policy_resources_utils import apply_and_wait_for_valid_policy, delete_policy
from suite.utils.vs_vsr_resources_utils import delete_and_create_vs_from_yaml, patch_virtual_server_from_yaml

AP_POLICY_SRC = f"{TEST_DATA}/ap-waf-plm/appolicy.yaml"
WAF_POLICY_SRC = f"{TEST_DATA}/ap-waf-plm/policies/waf.yaml"
WAF_SPEC_VS = f"{TEST_DATA}/ap-waf-v5/virtual-server-waf-spec.yaml"
STD_VS = f"{TEST_DATA}/ap-waf-v5/standard/virtual-server.yaml"


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect_waf_plm
@pytest.mark.parametrize(
    "crd_ingress_controller_with_plm, virtual_server_setup",
    [
        (
            {"extra_args": ["-enable-leader-election=false"]},
            {"example": "ap-waf-v5", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestWAFPLMVS:
    def test_plm_bundle_blocks_attack(
        self,
        kube_apis,
        crd_ingress_controller_with_plm,
        virtual_server_setup,
        test_namespace,
    ):
        """
        PLM compiles the APPolicy, NIC fetches the bundle from SeaweedFS, and the VirtualServer blocks an XSS request.
        """
        ap_pol = create_resource_from_yaml(kube_apis.custom_objects, AP_POLICY_SRC, test_namespace, "appolicies")
        wait_for_plm_bundle_ready(kube_apis.custom_objects, test_namespace, "appolicies", ap_pol["metadata"]["name"])
        pol_name = apply_and_wait_for_valid_policy(kube_apis, test_namespace, WAF_POLICY_SRC, retry_count=60)
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            WAF_SPEC_VS,
            virtual_server_setup.namespace,
        )

        response = send_malicious_request_with_retry(
            virtual_server_setup.backend_1_url,
            virtual_server_setup.vs_host,
        )

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            STD_VS,
            virtual_server_setup.namespace,
        )
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_resource(kube_apis.custom_objects, ap_pol, test_namespace, "appolicies")

        assert_waf_blocked(response)

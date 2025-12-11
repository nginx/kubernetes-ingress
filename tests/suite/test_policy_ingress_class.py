import pytest
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import wait_before_test
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
    patch_virtual_server_from_yaml,
)

vs_src = f"{TEST_DATA}/policy-ingress-class/virtual-server.yaml"
vs_policy_src = f"{TEST_DATA}/policy-ingress-class/virtual-server-policy.yaml"

policy_src = f"{TEST_DATA}/policy-ingress-class/policy.yaml"
policy_ingress_class_src = f"{TEST_DATA}/policy-ingress-class/policy-ingress-class.yaml"
policy_other_ingress_class_src = f"{TEST_DATA}/policy-ingress-class/policy-other-ingress-class.yaml"


@pytest.mark.policies
@pytest.mark.policies_rl
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
                "example": "rate-limit",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestRateLimitingPolicies:
    def restore_default_vs(self, kube_apis, virtual_server_setup) -> None:
        """
        Restore VirtualServer without policy spec
        """
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace)
        create_virtual_server_from_yaml(kube_apis.custom_objects, vs_src, virtual_server_setup.namespace)
        wait_before_test()

    @pytest.mark.parametrize("src", [vs_policy_src])
    def test_policy_empty_ingress_class(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if policy with no ingress class is applied to vs
        """
        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_src, test_namespace)

        wait_before_test()
        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )

        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        vs_info = read_custom_resource(
            kube_apis.custom_objects, virtual_server_setup.namespace, "virtualservers", virtual_server_setup.vs_name
        )
        assert (
            vs_info["status"]
            and vs_info["status"]["reason"] == "AddedOrUpdated"
            and vs_info["status"]["state"] == "Valid"
        )

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

    @pytest.mark.parametrize("src", [vs_policy_src])
    def test_policy_matching_ingress_class(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if policy with matching ingress class is applied to vs
        """
        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_ingress_class_src, test_namespace)

        wait_before_test()
        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
        assert (
            policy_info["status"]
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        )

        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        vs_info = read_custom_resource(
            kube_apis.custom_objects, virtual_server_setup.namespace, "virtualservers", virtual_server_setup.vs_name
        )
        assert (
            vs_info["status"]
            and vs_info["status"]["reason"] == "AddedOrUpdated"
            and vs_info["status"]["state"] == "Valid"
        )

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

    @pytest.mark.parametrize("src", [vs_policy_src])
    def test_policy_non_matching_ingress_class(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        src,
    ):
        """
        Test if non matching policy gets caught by vc validation
        """
        print(f"Create rl policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_other_ingress_class_src, test_namespace)

        wait_before_test()
        policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)

        assert "status" not in policy_info, "the policy is not managed by the IC, therefore the status is not updated"

        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()

        vs_info = read_custom_resource(
            kube_apis.custom_objects, virtual_server_setup.namespace, "virtualservers", virtual_server_setup.vs_name
        )
        assert (
            vs_info["status"]
            and "rate-limit-primary is missing or invalid" in vs_info["status"]["message"]
            and vs_info["status"]["reason"] == "AddedOrUpdatedWithWarning"
            and vs_info["status"]["state"] == "Warning"
        )

        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)

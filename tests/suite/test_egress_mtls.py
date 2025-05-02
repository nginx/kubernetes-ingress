import pytest
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import create_secret_from_yaml, delete_secret, wait_before_test
from suite.utils.ssl_utils import create_sni_session
from suite.utils.vs_vsr_resources_utils import delete_and_create_vs_from_yaml, patch_virtual_server_from_yaml, read_vs

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
std_vsr_src = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
std_vs_vsr_src = f"{TEST_DATA}/virtual-server-route/standard/virtual-server.yaml"

mtls_sec_valid_src = f"{TEST_DATA}/egress-mtls/secret/egress-mtls-secret.yaml"
mtls_sec_valid_crl_src = f"{TEST_DATA}/egress-mtls/secret/egress-mtls-secret-crl.yaml"
tls_sec_valid_src = f"{TEST_DATA}/egress-mtls/secret/tls-secret.yaml"

mtls_pol_valid_src = f"{TEST_DATA}/egress-mtls/policies/egress-mtls.yaml"
mtls_pol_invalid_src = f"{TEST_DATA}/egress-mtls/policies/egress-mtls-invalid.yaml"

mtls_vs_spec_src = f"{TEST_DATA}/egress-mtls/spec/virtual-server-mtls.yaml"
mtls_vs_route_src = f"{TEST_DATA}/egress-mtls/route-subroute/virtual-server-mtls.yaml"
mtls_vsr_subroute_src = f"{TEST_DATA}/egress-mtls/route-subroute/virtual-server-route-mtls.yaml"
mtls_vs_vsr_src = f"{TEST_DATA}/egress-mtls/route-subroute/virtual-server-vsr.yaml"


def setup_policy(kube_apis, test_namespace, mtls_secret, tls_secret, policy):
    print(f"Create egress-mtls secret")
    mtls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, mtls_secret)

    print(f"Create tls secret")
    tls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, tls_secret)

    print(f"Create egress-mtls policy")
    pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy, test_namespace)

    return mtls_secret_name, tls_secret_name, pol_name


def teardown_policy(kube_apis, test_namespace, tls_secret, pol_name, mtls_secret):
    print("Delete policy and related secrets")
    delete_secret(kube_apis.v1, tls_secret, test_namespace)
    delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
    delete_secret(kube_apis.v1, mtls_secret, test_namespace)


@pytest.mark.policies
@pytest.mark.policies_mtls
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-leader-election=false",
                ],
            },
            {
                "example": "virtual-server",
                "app_type": "secure-ca",
            },
        )
    ],
    indirect=True,
)
class TestEgressMtlsPolicyVS:
    @pytest.mark.parametrize(
        "policy_src, vs_src, mtls_ca_secret, expected_code, expected_text, vs_message, vs_state, test_description",
        [
            (
                mtls_pol_valid_src,
                mtls_vs_spec_src,
                mtls_sec_valid_src,
                200,
                "hello from pod secure-app",
                "was added or updated",
                "Valid",
                "Test valid EgressMTLS policy applied to a VirtualServer spec",
            ),
            (
                mtls_pol_valid_src,
                mtls_vs_route_src,
                mtls_sec_valid_src,
                200,
                "hello from pod secure-app",
                "was added or updated",
                "Valid",
                "Test valid EgressMTLS policy applied to a VirtualServer path",
            ),
            (
                mtls_pol_valid_src,
                mtls_vs_spec_src,
                mtls_sec_valid_crl_src,
                200,
                "hello from pod secure-app",
                "was added or updated",
                "Valid",
                "Test valid EgressMTLS policy applied to a VirtualServer with a CRL",
            ),
            (
                mtls_pol_invalid_src,
                mtls_vs_spec_src,
                mtls_sec_valid_src,
                500,
                "Internal Server Error",
                "is missing or invalid",
                "Warning",
                "Test invalid EgressMTLS policy applied to a VirtualServer",
            ),
        ],
    )
    def test_egress_mtls_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        policy_src,
        vs_src,
        mtls_ca_secret,
        expected_code,
        expected_text,
        vs_message,
        vs_state,
        test_description,
    ):
        """
        Test egress-mtls with valid and invalid policy in vs spec and route contexts.
        """
        print("------------------------- {} -----------------------------------".format(test_description))
        session = create_sni_session()
        mtls_secret, tls_secret, pol_name = setup_policy(
            kube_apis,
            test_namespace,
            mtls_ca_secret,
            tls_sec_valid_src,
            policy_src,
        )

        print(f"Patch vs with policy: {policy_src}")
        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp = session.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
            allow_redirects=False,
            verify=False,
        )

        vs_events = read_vs(kube_apis.custom_objects, test_namespace, virtual_server_setup.vs_name)
        teardown_policy(kube_apis, test_namespace, tls_secret, pol_name, mtls_secret)

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        assert (
            resp.status_code == expected_code
            and expected_text in resp.text
            and vs_message in vs_events["status"]["message"]
            and vs_events["status"]["state"] == vs_state
        )

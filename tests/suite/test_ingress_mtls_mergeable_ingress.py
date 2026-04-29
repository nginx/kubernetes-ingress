from unittest import mock

import pytest
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import apply_and_wait_for_valid_policy, delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    delete_secret,
    ensure_connection_to_public_endpoint,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.ssl_utils import create_sni_session
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml, get_name_from_yaml

mergeable_master_src = f"{TEST_DATA}/ingress-mtls/ingress/mergeable-master/ingress-mtls-ingress.yaml"
mergeable_minion_src = f"{TEST_DATA}/ingress-mtls/ingress/mergeable-minion/ingress-mtls-ingress.yaml"
mtls_pol_src = f"{TEST_DATA}/ingress-mtls/policies/ingress-mtls.yaml"
mtls_sec_src = f"{TEST_DATA}/ingress-mtls/secret/ingress-mtls-secret.yaml"
tls_sec_src = f"{TEST_DATA}/ingress-mtls/secret/tls-secret.yaml"
crt = f"{TEST_DATA}/ingress-mtls/client-auth/valid/client-cert.pem"
key = f"{TEST_DATA}/ingress-mtls/client-auth/valid/client-key.pem"


@pytest.mark.policies
@pytest.mark.policies_mtls
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
class TestIngressMTLSMergeableIngress:
    def test_ingress_mtls_policy_mergeable_master(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
    ):
        """Validates that an IngressMTLS policy on a mergeable master Ingress enforces client certificate authentication across all merged paths."""

        ingress_host = get_first_ingress_host_from_yaml(mergeable_master_src)
        request_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"
        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        mtls_secret_name = ""
        tls_secret_name = ""
        pol_name = ""
        try:
            print("Create ingress-mtls secret")
            mtls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, mtls_sec_src)
            print("Create tls secret")
            tls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, tls_sec_src)
            print("Create ingress-mtls policy")
            apply_and_wait_for_valid_policy(kube_apis, test_namespace, mtls_pol_src)
            pol_name = get_name_from_yaml(mtls_pol_src)
            create_items_from_yaml(kube_apis, mergeable_master_src, test_namespace)
            ensure_connection_to_public_endpoint(
                ingress_controller_endpoint.public_ip,
                ingress_controller_endpoint.port,
                ingress_controller_endpoint.port_ssl,
            )
            policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
            session = create_sni_session()
            # No cert gives 400 meaning the policy is enforced at the master server block level
            resp = mock.Mock()
            resp.status_code = 502
            counter = 0
            while resp.status_code != 400 and counter < 10:
                resp = session.get(
                    request_url,
                    headers={"host": ingress_host},
                    allow_redirects=False,
                    verify=False,
                )
                wait_before_test()
                counter += 1

            assert resp.status_code == 400, (
                f"Expected 400 with no client cert on mergeable master, "
                f"got {resp.status_code}. Response: {resp.text}"
            )
            assert (
                "No required SSL certificate was sent" in resp.text
            ), f"Expected SSL error message in response body, got: {resp.text}"
            # Valid cert gives 200 which confirms the merged Ingress routes correctly
            resp = session.get(
                request_url,
                cert=(crt, key),
                headers={"host": ingress_host},
                allow_redirects=False,
                verify=False,
            )
            assert (
                resp.status_code == 200
            ), f"Expected 200 with valid client cert, got {resp.status_code}. Response: {resp.text}"
            assert "Server address:" in resp.text, f"Expected backend response, got: {resp.text}"
            assert (
                policy_info["status"]["reason"] == "AddedOrUpdated" and policy_info["status"]["state"] == "Valid"
            ), f"Expected policy AddedOrUpdated/Valid, got {policy_info.get('status', {})}"
        finally:
            if pol_name:
                delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            delete_items_from_yaml(kube_apis, mergeable_master_src, test_namespace)
            if tls_secret_name:
                delete_secret(kube_apis.v1, tls_secret_name, test_namespace)
            if mtls_secret_name:
                delete_secret(kube_apis.v1, mtls_secret_name, test_namespace)
            delete_common_app(kube_apis, "simple", test_namespace)

    def test_ingress_mtls_policy_mergeable_minion(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
    ):
        """Validates that IngressMTLS policies are only enforced when placed on the master Ingress in a mergeable setup."""

        ingress_host = get_first_ingress_host_from_yaml(mergeable_minion_src)
        request_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"
        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
        mtls_secret_name = ""
        tls_secret_name = ""
        pol_name = ""
        try:
            print("Create ingress-mtls secret")
            mtls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, mtls_sec_src)
            print("Create tls secret")
            tls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, tls_sec_src)
            print("Create ingress-mtls policy")
            apply_and_wait_for_valid_policy(kube_apis, test_namespace, mtls_pol_src)
            pol_name = get_name_from_yaml(mtls_pol_src)
            create_items_from_yaml(kube_apis, mergeable_minion_src, test_namespace)
            ensure_connection_to_public_endpoint(
                ingress_controller_endpoint.public_ip,
                ingress_controller_endpoint.port,
                ingress_controller_endpoint.port_ssl,
            )
            policy_info = read_custom_resource(kube_apis.custom_objects, test_namespace, "policies", pol_name)
            session = create_sni_session()
            # No cert gives 200, the policy on the minion is ignored, no mTLS enforcement
            resp = mock.Mock()
            resp.status_code = 502
            counter = 0
            while resp.status_code != 200 and counter < 10:
                resp = session.get(
                    request_url,
                    headers={"host": ingress_host},
                    allow_redirects=False,
                    verify=False,
                )
                wait_before_test()
                counter += 1
            assert resp.status_code == 200, (
                f"Expected 200 (IngressMTLS on minion should be ignored), "
                f"got {resp.status_code}. Response: {resp.text}"
            )
            assert "Server address:" in resp.text, f"Expected backend response, got: {resp.text}"
            assert (
                policy_info["status"]["reason"] == "AddedOrUpdated" and policy_info["status"]["state"] == "Valid"
            ), f"Expected policy AddedOrUpdated/Valid, got {policy_info.get('status', {})}"
        finally:
            if pol_name:
                delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            delete_items_from_yaml(kube_apis, mergeable_minion_src, test_namespace)
            if tls_secret_name:
                delete_secret(kube_apis.v1, tls_secret_name, test_namespace)
            if mtls_secret_name:
                delete_secret(kube_apis.v1, mtls_secret_name, test_namespace)
            delete_common_app(kube_apis, "simple", test_namespace)

from unittest import mock

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.policy_resources_utils import (
    apply_and_wait_for_valid_policy,
    create_policy_from_yaml,
    delete_policy,
)
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

mtls_ingress_src = f"{TEST_DATA}/ingress-mtls/ingress/ingress-mtls-policy-ingress.yaml"
mtls_pol_src = f"{TEST_DATA}/ingress-mtls/policies/ingress-mtls.yaml"
mtls_invalid_pol_src = f"{TEST_DATA}/ingress-mtls/policies/ingress-mtls-invalid.yaml"
mtls_sec_src = f"{TEST_DATA}/ingress-mtls/secret/ingress-mtls-secret.yaml"
tls_sec_src = f"{TEST_DATA}/ingress-mtls/secret/tls-secret.yaml"

crt = f"{TEST_DATA}/ingress-mtls/client-auth/valid/client-cert.pem"
key = f"{TEST_DATA}/ingress-mtls/client-auth/valid/client-key.pem"
invalid_crt = f"{TEST_DATA}/ingress-mtls/client-auth/invalid/client-cert.pem"
invalid_key = f"{TEST_DATA}/ingress-mtls/client-auth/invalid/client-key.pem"


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
class TestIngressMTLSPoliciesIngress:
    def setup_ingress_mtls(self, kube_apis, test_namespace):
        print("Create ingress-mtls secret")
        mtls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, mtls_sec_src)

        print("Create tls secret")
        tls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, tls_sec_src)

        print("Create ingress-mtls policy")
        apply_and_wait_for_valid_policy(kube_apis, test_namespace, mtls_pol_src)
        pol_name = get_name_from_yaml(mtls_pol_src)

        return mtls_secret_name, tls_secret_name, pol_name

    def setup_invalid_ingress_mtls(self, kube_apis, test_namespace):
        print("Create ingress-mtls secret")
        mtls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, mtls_sec_src)

        print("Create tls secret")
        tls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, tls_sec_src)

        print("Create invalid ingress-mtls policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, mtls_invalid_pol_src, test_namespace)
        wait_before_test()

        return mtls_secret_name, tls_secret_name, pol_name

    @pytest.mark.parametrize(
        "certificate, expected_code, expected_text, exception",
        [
            ((crt, key), 200, "Server address:", ""),
            ("", 400, "No required SSL certificate was sent", ""),
            ((invalid_crt, invalid_key), "None", "None", "Caused by SSLError"),
        ],
    )
    def test_ingress_mtls_policy_ingress(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
        certificate,
        expected_code,
        expected_text,
        exception,
    ):
        ingress_host = get_first_ingress_host_from_yaml(mtls_ingress_src)
        request_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"

        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

        mtls_secret_name = ""
        tls_secret_name = ""
        pol_name = ""
        try:
            mtls_secret_name, tls_secret_name, pol_name = self.setup_ingress_mtls(kube_apis, test_namespace)
            create_items_from_yaml(kube_apis, mtls_ingress_src, test_namespace)

            ensure_connection_to_public_endpoint(
                ingress_controller_endpoint.public_ip,
                ingress_controller_endpoint.port,
                ingress_controller_endpoint.port_ssl,
            )

            policy_info = read_custom_resource(
                kube_apis.custom_objects,
                test_namespace,
                "policies",
                pol_name,
            )

            session = create_sni_session()
            ssl_exception = ""
            resp = mock.Mock()
            resp.status_code = 502
            counter = 0

            while resp.status_code != expected_code and counter < 10:
                try:
                    resp = session.get(
                        request_url,
                        cert=certificate,
                        headers={"host": ingress_host},
                        allow_redirects=False,
                        verify=False,
                    )
                    wait_before_test()
                    counter += 1

                except requests.exceptions.SSLError as e:
                    print(f"SSL certificate exception: {e}")
                    ssl_exception = str(e)
                    resp = mock.Mock()
                    resp.status_code = "None"
                    resp.text = "None"
                    break

            assert (
                resp.status_code == expected_code
            ), f"Expected status {expected_code}, got {resp.status_code}. Response: {resp.text}"
            assert expected_text in resp.text, f"Expected {expected_text!r} in response, got: {resp.text}"
            assert (
                exception in ssl_exception
            ), f"Expected SSL exception containing {exception!r}, got: {ssl_exception!r}"
            assert (
                policy_info["status"]["reason"] == "AddedOrUpdated" and policy_info["status"]["state"] == "Valid"
            ), f"Expected policy to be AddedOrUpdated/Valid, got {policy_info.get('status', {})}"

        finally:
            if pol_name:
                delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            delete_items_from_yaml(kube_apis, mtls_ingress_src, test_namespace)

            if tls_secret_name:
                delete_secret(kube_apis.v1, tls_secret_name, test_namespace)

            if mtls_secret_name:
                delete_secret(kube_apis.v1, mtls_secret_name, test_namespace)
            delete_common_app(kube_apis, "simple", test_namespace)

    def test_invalid_ingress_mtls_policy_ingress(
        self,
        kube_apis,
        crd_ingress_controller,
        ingress_controller_endpoint,
        test_namespace,
    ):
        ingress_host = get_first_ingress_host_from_yaml(mtls_ingress_src)
        request_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"

        create_example_app(kube_apis, "simple", test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

        mtls_secret_name = ""
        tls_secret_name = ""
        pol_name = ""
        try:
            mtls_secret_name, tls_secret_name, pol_name = self.setup_invalid_ingress_mtls(kube_apis, test_namespace)
            create_items_from_yaml(kube_apis, mtls_ingress_src, test_namespace)

            ensure_connection_to_public_endpoint(
                ingress_controller_endpoint.public_ip,
                ingress_controller_endpoint.port,
                ingress_controller_endpoint.port_ssl,
            )

            policy_info = read_custom_resource(
                kube_apis.custom_objects,
                test_namespace,
                "policies",
                pol_name,
            )
            counter = 0
            while (
                "status" not in policy_info
                or policy_info["status"].get("reason") != "Rejected"
                or policy_info["status"].get("state") != "Invalid"
            ) and counter < 30:
                wait_before_test()
                policy_info = read_custom_resource(
                    kube_apis.custom_objects,
                    test_namespace,
                    "policies",
                    pol_name,
                )
                counter += 1

            session = create_sni_session()
            resp = mock.Mock()
            resp.status_code = 404
            counter = 0
            while resp.status_code != 500 and counter < 30:
                resp = session.get(
                    request_url,
                    headers={"host": ingress_host},
                    allow_redirects=False,
                    verify=False,
                )
                wait_before_test()
                counter += 1

            assert resp.status_code == 500, f"Expected 500 for invalid policy, got {resp.status_code}"
            assert (
                policy_info["status"]["reason"] == "Rejected" and policy_info["status"]["state"] == "Invalid"
            ), f"Expected policy to be Rejected/Invalid, got {policy_info.get('status', {})}"

        finally:
            if pol_name:
                delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
            delete_items_from_yaml(kube_apis, mtls_ingress_src, test_namespace)

            if tls_secret_name:
                delete_secret(kube_apis.v1, tls_secret_name, test_namespace)

            if mtls_secret_name:
                delete_secret(kube_apis.v1, mtls_secret_name, test_namespace)
            delete_common_app(kube_apis, "simple", test_namespace)

from unittest import mock

import pytest
import requests
from settings import TEST_DATA
from suite.utils.policy_resources_utils import create_policy_from_yaml, delete_policy
from suite.utils.resources_utils import create_secret_from_yaml, delete_secret, wait_before_test
from suite.utils.ssl_utils import create_sni_session
from suite.utils.vs_vsr_resources_utils import (
    delete_and_create_vs_from_yaml,
    patch_v_s_route_from_yaml,
    patch_virtual_server_from_yaml,
    read_vs,
    read_vsr,
)

std_vs_src = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
std_vsr_src = f"{TEST_DATA}/virtual-server-route/route-multiple.yaml"
std_vs_vsr_src = f"{TEST_DATA}/virtual-server-route/standard/virtual-server.yaml"

mtls_sec_valid_src = f"{TEST_DATA}/ingress-mtls/secret/ingress-mtls-secret.yaml"
tls_sec_valid_src = f"{TEST_DATA}/ingress-mtls/secret/tls-secret.yaml"

mtls_pol_valid_src = f"{TEST_DATA}/ingress-mtls/policies/ingress-mtls.yaml"
mtls_pol_invalid_src = f"{TEST_DATA}/ingress-mtls/policies/ingress-mtls-invalid.yaml"

mtls_vs_spec_src = f"{TEST_DATA}/ingress-mtls/spec/virtual-server-mtls.yaml"
mtls_vs_route_src = f"{TEST_DATA}/ingress-mtls/route-subroute/virtual-server-mtls.yaml"
mtls_vsr_subroute_src = f"{TEST_DATA}/ingress-mtls/route-subroute/virtual-server-route-mtls.yaml"
mtls_vs_vsr_src = f"{TEST_DATA}/ingress-mtls/route-subroute/virtual-server-vsr.yaml"

crt = f"{TEST_DATA}/ingress-mtls/client-auth/valid/client-cert.pem"
key = f"{TEST_DATA}/ingress-mtls/client-auth/valid/client-key.pem"
invalid_crt = f"{TEST_DATA}/ingress-mtls/client-auth/invalid/client-cert.pem"
invalid_key = f"{TEST_DATA}/ingress-mtls/client-auth/invalid/client-cert.pem"

mtls_secret_crl = f"{TEST_DATA}/ingress-mtls/secret/ingress-mtls-secret-crl.yaml"
mtls_pol_crl = f"{TEST_DATA}/ingress-mtls/policies/ingress-mtls-crl.yaml"

crt_not_revoked = f"{TEST_DATA}/ingress-mtls/client-auth/not-revoked/client-cert.pem"
key_not_revoked = f"{TEST_DATA}/ingress-mtls/client-auth/not-revoked/client-key.pem"
crt_revoked = f"{TEST_DATA}/ingress-mtls/client-auth/revoked/client-cert.pem"
key_revoked = f"{TEST_DATA}/ingress-mtls/client-auth/revoked/client-key.pem"


def setup_policy(kube_apis, test_namespace, mtls_secret, tls_secret, policy):
    print(f"Create ingress-mtls secret")
    mtls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, mtls_secret)

    print(f"Create ingress-mtls policy")
    pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy, test_namespace)

    print(f"Create tls secret")
    tls_secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, tls_secret)
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
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestIngressMtlsPolicyVS:
    @pytest.mark.parametrize(
        "policy_src, vs_src, expected_code, expected_text, vs_message, vs_state",
        [
            (
                mtls_pol_valid_src,
                mtls_vs_spec_src,
                200,
                "Server address:",
                "was added or updated",
                "Valid",
            ),
            (
                mtls_pol_valid_src,
                mtls_vs_route_src,
                500,
                "Internal Server Error",
                "is not allowed in the route context",
                "Warning",
            ),
            (
                mtls_pol_invalid_src,
                mtls_vs_spec_src,
                500,
                "Internal Server Error",
                "is missing or invalid",
                "Warning",
            ),
        ],
    )
    @pytest.mark.smoke
    def test_ingress_mtls_policy(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        policy_src,
        vs_src,
        expected_code,
        expected_text,
        vs_message,
        vs_state,
    ):
        """
        Test ingress-mtls with valid and invalid policy in vs spec and route contexts.
        """
        session = create_sni_session()
        mtls_secret, tls_secret, pol_name = setup_policy(
            kube_apis,
            test_namespace,
            mtls_sec_valid_src,
            tls_sec_valid_src,
            policy_src,
        )

        print(f"Patch vs with policy: {policy_src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp = mock.Mock()
        resp.status_code == 502
        counter = 0

        while resp.status_code != expected_code and counter < 10:
            resp = session.get(
                virtual_server_setup.backend_1_url_ssl,
                cert=(crt, key),
                headers={"host": virtual_server_setup.vs_host},
                allow_redirects=False,
                verify=False,
            )
            wait_before_test()
            counter += 1

        vs_res = read_vs(kube_apis.custom_objects, test_namespace, virtual_server_setup.vs_name)
        teardown_policy(kube_apis, test_namespace, tls_secret, pol_name, mtls_secret)

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )

        print("printing out the response text")
        print(resp.text)

        assert (
            resp.status_code == expected_code
            and expected_text in resp.text
            and vs_message in vs_res["status"]["message"]
            and vs_res["status"]["state"] == vs_state
        )

    @pytest.mark.parametrize(
        "certificate, expected_code, expected_text, exception",
        [
            ((crt, key), 200, "Server address:", ""),
            ("", 400, "No required SSL certificate was sent", ""),
            ((invalid_crt, invalid_key), "None", "None", "Caused by SSLError"),
        ],
    )
    def test_ingress_mtls_policy_cert(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        certificate,
        expected_code,
        expected_text,
        exception,
    ):
        """
        Test ingress-mtls with valid and invalid policy
        """
        session = create_sni_session()
        mtls_secret, tls_secret, pol_name = setup_policy(
            kube_apis,
            test_namespace,
            mtls_sec_valid_src,
            tls_sec_valid_src,
            mtls_pol_valid_src,
        )

        print(f"Patch vs with policy: {mtls_pol_valid_src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            mtls_vs_spec_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        ssl_exception = ""
        resp = mock.Mock()
        resp.status_code == 502
        counter = 0

        while resp.status_code != expected_code and counter < 10:
            try:
                resp = session.get(
                    virtual_server_setup.backend_1_url_ssl,
                    cert=certificate,
                    headers={"host": virtual_server_setup.vs_host},
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

        teardown_policy(kube_apis, test_namespace, tls_secret, pol_name, mtls_secret)

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )
        assert resp.status_code == expected_code and expected_text in resp.text and exception in ssl_exception

    @pytest.mark.smoke
    @pytest.mark.parametrize(
        "policy_src, vs_src, mtls_secret_in, expected_code, expected_text, vs_message, vs_state",
        [
            (
                mtls_pol_valid_src,
                mtls_vs_spec_src,
                mtls_secret_crl,
                200,
                "Server address:",
                "added or updated",
                "Valid",
            ),
            (
                mtls_pol_crl,
                mtls_vs_spec_src,
                mtls_sec_valid_src,
                404,
                "Not Found",
                "added or updated",
                "Invalid",
            ),
            (
                mtls_pol_crl,
                mtls_vs_spec_src,
                mtls_secret_crl,
                404,
                "Not Found",
                "added or updated ; with warning(s)",
                "Invalid",
            ),
        ],
    )
    def test_ingress_mtls_policy_crl(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        policy_src,
        mtls_secret_in,
        vs_src,
        expected_code,
        expected_text,
        vs_message,
        vs_state,
    ):
        session = create_sni_session()
        mtls_secret, tls_secret, pol_name = setup_policy(
            kube_apis,
            test_namespace,
            mtls_secret_in,
            tls_sec_valid_src,
            policy_src,
        )

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            vs_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        resp = mock.Mock()
        resp.status_code == 502
        counter = 0

        while resp.status_code != expected_code and counter < 10:
            resp = session.get(
                virtual_server_setup.backend_1_url_ssl,
                cert=(crt_not_revoked, key_not_revoked),
                headers={"host": virtual_server_setup.vs_host},
                allow_redirects=False,
                verify=False,
            )
            wait_before_test()
            counter += 1

        vs_res = read_vs(kube_apis.custom_objects, test_namespace, virtual_server_setup.vs_name)
        teardown_policy(kube_apis, test_namespace, tls_secret, pol_name, mtls_secret)

        delete_and_create_vs_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )
        assert (
            resp.status_code == expected_code
            and expected_text in resp.text
            and vs_message in vs_res["status"]["message"]
            and vs_res["status"]["state"] == vs_state
        )

    @pytest.mark.parametrize(
        "certificate, expected_code, expected_text, exception",
        [
            ((crt_not_revoked, key_not_revoked), 200, "Server address:", ""),
            ("", 400, "No required SSL certificate was sent", ""),
            ((crt_revoked, key_revoked), 400, "The SSL certificate error", ""),
        ],
    )
    def test_ingress_mtls_policy_cert_crl(
        self,
        kube_apis,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
        certificate,
        expected_code,
        expected_text,
        exception,
    ):
        """
        Test ingress-mtls with valid and invalid policy
        """
        session = create_sni_session()
        mtls_secret, tls_secret, pol_name = setup_policy(
            kube_apis,
            test_namespace,
            mtls_secret_crl,
            tls_sec_valid_src,
            mtls_pol_valid_src,
        )

        print(f"Patch vs with policy: {mtls_pol_valid_src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            mtls_vs_spec_src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        ssl_exception = ""
        resp = mock.Mock()
        resp.status_code == 502
        counter = 0

        while resp.status_code != expected_code and counter < 10:
            try:
                resp = session.get(
                    virtual_server_setup.backend_1_url_ssl,
                    cert=certificate,
                    headers={"host": virtual_server_setup.vs_host},
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

        teardown_policy(kube_apis, test_namespace, tls_secret, pol_name, mtls_secret)

        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            std_vs_src,
            virtual_server_setup.namespace,
        )
        assert resp.status_code == expected_code and expected_text in resp.text and exception in ssl_exception


@pytest.mark.policies
@pytest.mark.policies_mtls
@pytest.mark.parametrize(
    "crd_ingress_controller, v_s_route_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-leader-election=false",
                ],
            },
            {"example": "virtual-server-route"},
        )
    ],
    indirect=True,
)
class TestIngressMtlsPolicyVSR:
    def test_ingress_mtls_policy_vsr(
        self,
        kube_apis,
        crd_ingress_controller,
        v_s_route_app_setup,
        v_s_route_setup,
        test_namespace,
    ):
        """
        Test ingress-mtls in vsr subroute context.
        """
        mtls_secret, tls_secret, pol_name = setup_policy(
            kube_apis,
            v_s_route_setup.route_m.namespace,
            mtls_sec_valid_src,
            tls_sec_valid_src,
            mtls_pol_valid_src,
        )
        print(f"Patch vsr with policy: {mtls_vsr_subroute_src} and vs with tls secret: {tls_secret}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            mtls_vs_vsr_src,
            v_s_route_setup.namespace,
        )
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            mtls_vsr_subroute_src,
            v_s_route_setup.route_m.namespace,
        )
        wait_before_test()
        vsr_res = read_vsr(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.namespace,
            v_s_route_setup.route_m.name,
        )
        teardown_policy(kube_apis, v_s_route_setup.route_m.namespace, tls_secret, pol_name, mtls_secret)
        patch_v_s_route_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.route_m.name,
            std_vsr_src,
            v_s_route_setup.route_m.namespace,
        )
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            v_s_route_setup.vs_name,
            std_vs_vsr_src,
            v_s_route_setup.namespace,
        )
        assert (
            vsr_res["status"]["state"] == "Warning"
            and f"{pol_name} is not allowed in the subroute context" in vsr_res["status"]["message"]
        )

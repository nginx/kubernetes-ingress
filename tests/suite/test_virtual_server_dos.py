import os
import subprocess
from datetime import datetime

import pytest
import requests
from settings import TEST_DATA
from suite.utils.custom_assertions import wait_and_assert_status_code
from suite.utils.custom_resources_utils import (
    create_dos_logconf_from_yaml,
    create_dos_policy_from_yaml,
    create_dos_protected_from_yaml,
    delete_dos_logconf,
    delete_dos_policy,
    delete_dos_protected,
)
from suite.utils.dos_utils import (
    check_learning_status_with_admd_s,
    clean_good_bad_clients,
    find_in_log,
    log_content_to_dic,
)
from suite.utils.resources_utils import (
    clear_file_contents,
    create_example_app,
    delete_common_app,
    ensure_response_from_backend,
    get_file_contents,
    nginx_reload,
    replace_configmap_from_yaml,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_virtual_server_from_yaml,
    delete_virtual_server,
    get_vs_nginx_template_conf,
)
from suite.utils.yaml_utils import get_first_host_from_yaml, get_paths_from_vs_yaml

valid_resp_addr = "Server address:"
valid_resp_name = "Server name:"
invalid_resp_title = "Request Rejected"
invalid_resp_body = "The requested URL was rejected. Please consult with your administrator."
reload_times = {}


class VirtualServerSetupDos:
    def __init__(self, public_endpoint, namespace, vs_host, vs_name, vs_paths):
        self.public_endpoint = public_endpoint
        self.namespace = namespace
        self.vs_host = vs_host
        self.vs_name = vs_name
        self.backend_1_url = f"http://{public_endpoint.public_ip}:{public_endpoint.port}{vs_paths[0]}"


@pytest.fixture(scope="class")
def virtual_server_setup_dos(request, kube_apis, ingress_controller_endpoint, test_namespace) -> VirtualServerSetupDos:
    print("------------------------- Deploy Virtual Server Example -----------------------------------")
    vs_source = f"{TEST_DATA}/virtual-server-dos/virtual-server.yaml"
    vs_name = create_virtual_server_from_yaml(kube_apis.custom_objects, vs_source, test_namespace)
    vs_host = get_first_host_from_yaml(vs_source)
    vs_paths = get_paths_from_vs_yaml(vs_source)
    vs_paths[0] += f"good_path.html"
    if request.param["app_type"]:
        create_example_app(kube_apis, request.param["app_type"], test_namespace)
        wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up Virtual Server Example:")
            delete_virtual_server(kube_apis.custom_objects, vs_name, test_namespace)
            if request.param["app_type"]:
                delete_common_app(kube_apis, request.param["app_type"], test_namespace)

    request.addfinalizer(fin)

    return VirtualServerSetupDos(ingress_controller_endpoint, test_namespace, vs_host, vs_name, vs_paths)


class DosSetup:
    """
    Encapsulate the example details.
    Attributes:
        req_url (str):
        protected_name (str)
        pol_name (str):
        log_name (str):
    """

    def __init__(self, req_url, protected_name, pol_name, log_name):
        self.req_url = req_url
        self.protected_name = protected_name
        self.pol_name = pol_name
        self.log_name = log_name


@pytest.fixture(scope="class")
def dos_setup(
    request, kube_apis, ingress_controller_endpoint, ingress_controller_prerequisites, test_namespace
) -> DosSetup:
    """
    Deploy simple application and all the DOS resources under test in one namespace.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :param ingress_controller_prerequisites: IC pre-requisites
    :param test_namespace:
    :return: DosSetup
    """

    # Clean old scripts if still running
    clean_good_bad_clients()
    print(f"------------- Replace ConfigMap --------------")
    replace_configmap_from_yaml(
        kube_apis.v1,
        ingress_controller_prerequisites.config_map["metadata"]["name"],
        ingress_controller_prerequisites.namespace,
        f"{TEST_DATA}/dos/nginx-config.yaml",
    )

    req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/"

    print("------------------------- Deploy vs-logconf -----------------------------")
    src_log_yaml = f"{TEST_DATA}/virtual-server-dos/dos-logconf.yaml"
    log_name = create_dos_logconf_from_yaml(kube_apis.custom_objects, src_log_yaml, test_namespace)

    print(f"------------------------- Deploy vs-dospolicy ---------------------------")
    src_pol_yaml = f"{TEST_DATA}/virtual-server-dos/dos-policy.yaml"
    pol_name = create_dos_policy_from_yaml(kube_apis.custom_objects, src_pol_yaml, test_namespace)

    print(f"------------------------- Deploy protected resource ---------------------------")
    src_protected_yaml = f"{TEST_DATA}/virtual-server-dos/dos-protected.yaml"
    protected_name = create_dos_protected_from_yaml(
        kube_apis.custom_objects, src_protected_yaml, test_namespace, ingress_controller_prerequisites.namespace
    )

    for item in kube_apis.v1.list_namespaced_pod(ingress_controller_prerequisites.namespace).items:
        if "nginx-ingress" in item.metadata.name:
            nginx_reload(kube_apis.v1, item.metadata.name, ingress_controller_prerequisites.namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            delete_dos_policy(kube_apis.custom_objects, pol_name, test_namespace)
            delete_dos_logconf(kube_apis.custom_objects, log_name, test_namespace)
            delete_dos_protected(kube_apis.custom_objects, protected_name, test_namespace)
            clean_good_bad_clients()

    request.addfinalizer(fin)

    return DosSetup(req_url, protected_name, pol_name, log_name)


@pytest.mark.dos
@pytest.mark.parametrize(
    "crd_ingress_controller_with_dos, virtual_server_setup_dos",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-app-protect-dos",
                    f"-log-level=debug",
                ],
            },
            {"example": "virtual-server-dos", "app_type": "dos"},
        )
    ],
    indirect=True,
)
class TestDos:
    def getPodNameThatContains(self, kube_apis, namespace, contains_string):
        for item in kube_apis.v1.list_namespaced_pod(namespace).items:
            if contains_string in item.metadata.name:
                return item.metadata.name
        return ""

    def test_responses_after_setup(
        self, kube_apis, crd_ingress_controller_with_dos, dos_setup, virtual_server_setup_dos
    ):
        print("\nStep 1: initial check")
        wait_and_assert_status_code(200, virtual_server_setup_dos.backend_1_url, virtual_server_setup_dos.vs_host)

    def test_dos_vs_logs(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_dos,
        virtual_server_setup_dos,
        dos_setup,
        test_namespace,
    ):
        """
        Test app protect logs appear in syslog after sending request to dos enabled route
        """
        print("----------------------- Get syslog pod name ----------------------")
        syslog_pod = self.getPodNameThatContains(kube_apis, ingress_controller_prerequisites.namespace, "syslog")
        assert "syslog" in syslog_pod
        log_loc = f"/var/log/messages"
        clear_file_contents(kube_apis.v1, log_loc, syslog_pod, ingress_controller_prerequisites.namespace)

        print("----------------------- Send request ----------------------")
        ensure_response_from_backend(virtual_server_setup_dos.backend_1_url, virtual_server_setup_dos.vs_host)

        response = requests.get(
            virtual_server_setup_dos.backend_1_url, headers={"host": virtual_server_setup_dos.vs_host}
        )
        print(response.text)

        wait_before_test(20)

        print("----------------------- Check Logs ----------------------")
        print(f"log_loc: {log_loc} syslog_pod: {syslog_pod} namespace: {ingress_controller_prerequisites.namespace}")
        log_contents = get_file_contents(kube_apis.v1, log_loc, syslog_pod, ingress_controller_prerequisites.namespace)

        assert 'product="app-protect-dos"' in log_contents
        assert f'vs_name="{test_namespace}/dos-protected/name"' in log_contents
        assert "bad_actor" in log_contents

    def test_vs_with_dos_config(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_dos,
        dos_setup,
        virtual_server_setup_dos,
        test_namespace,
    ):
        """
        Test to verify Dos annotations in nginx config
        """
        conf_directives = [
            f"app_protect_dos_enable on;",
            f"app_protect_dos_security_log_enable on;",
            f'app_protect_dos_monitor "dos.example.com";',
            f'app_protect_dos_name "{test_namespace}/dos-protected/name";',
            f"app_protect_dos_policy_file /etc/nginx/dos/policies/{test_namespace}_{dos_setup.pol_name}.json;",
            f"app_protect_dos_security_log_enable on;",
            f"app_protect_dos_security_log /etc/nginx/dos/logconfs/{test_namespace}_{dos_setup.log_name}.json syslog:server=syslog-svc.{ingress_controller_prerequisites.namespace}.svc.cluster.local:514;",
            f"access_log syslog:server=accesslog-svc.{ingress_controller_prerequisites.namespace}.svc.cluster.local:514 log_dos if=$loggable;",
            f'app_protect_dos_access_file "/etc/nginx/dos/allowlist/{test_namespace}_{dos_setup.protected_name}.json";',
        ]

        print("\n confirm response for standard request")
        wait_and_assert_status_code(200, virtual_server_setup_dos.backend_1_url, virtual_server_setup_dos.vs_host)

        pod_name = self.getPodNameThatContains(kube_apis, ingress_controller_prerequisites.namespace, "nginx-ingress")

        result_conf = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup_dos.namespace,
            virtual_server_setup_dos.vs_name,
            pod_name,
            "nginx-ingress",
        )

        for _ in conf_directives:
            assert _ in result_conf

        print("Remove Virtual Server in location block")
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup_dos.vs_name, test_namespace)
        print("Add Virtual Server in server block")

        vs_source_server_block = f"{TEST_DATA}/virtual-server-dos/virtual-server-block-server.yaml"
        create_virtual_server_from_yaml(kube_apis.custom_objects, vs_source_server_block, test_namespace)
        wait_before_test(5)

        print("\n confirm response for standard request")
        wait_and_assert_status_code(200, virtual_server_setup_dos.backend_1_url, virtual_server_setup_dos.vs_host)

        result_conf = get_vs_nginx_template_conf(
            kube_apis.v1,
            virtual_server_setup_dos.namespace,
            virtual_server_setup_dos.vs_name,
            pod_name,
            "nginx-ingress",
        )

        for _ in conf_directives:
            assert _ in result_conf

        print("Clean up new VS server block")
        delete_virtual_server(kube_apis.custom_objects, virtual_server_setup_dos.vs_name, test_namespace)

        print("Return VS location block")
        vs_source = f"{TEST_DATA}/virtual-server-dos/virtual-server.yaml"
        create_virtual_server_from_yaml(kube_apis.custom_objects, vs_source, test_namespace)

    def test_vs_dos_under_attack_no_learning(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_dos,
        virtual_server_setup_dos,
        dos_setup,
        test_namespace,
    ):
        """
        Test App Protect Dos: Block bad clients attack
        """
        print("----------------------- Get syslog pod name ----------------------")
        syslog_pod = self.getPodNameThatContains(kube_apis, ingress_controller_prerequisites.namespace, "syslog")
        assert "syslog" in syslog_pod
        log_loc = f"/var/log/messages"
        clear_file_contents(kube_apis.v1, log_loc, syslog_pod, ingress_controller_prerequisites.namespace)

        print("------------------------- Attack -----------------------------")
        print("start bad clients requests")
        p_attack = subprocess.Popen(
            [f"exec {TEST_DATA}/dos/bad_clients_xff.sh {virtual_server_setup_dos.vs_host} {dos_setup.req_url}"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        print("Attack for 30 seconds")
        wait_before_test(30)

        print("Stop Attack")
        p_attack.terminate()

        print("wait max 200 seconds after attack stop, to get attack ended")
        find_in_log(
            kube_apis,
            log_loc,
            syslog_pod,
            ingress_controller_prerequisites.namespace,
            200,
            'attack_event="Attack ended"',
        )

        log_contents = get_file_contents(kube_apis.v1, log_loc, syslog_pod, ingress_controller_prerequisites.namespace)
        log_info_dic = log_content_to_dic(log_contents)

        # Analyze the log
        no_attack = False
        attack_started = False
        under_attack = False
        attack_ended = False
        for log in log_info_dic:
            # Start with no attack
            if log["attack_event"] == "No Attack" and int(log["dos_attack_id"]) == 0 and not no_attack:
                no_attack = True
            # Attack started
            elif log["attack_event"] == "Attack started" and int(log["dos_attack_id"]) > 0 and not attack_started:
                attack_started = True
            # Under attack
            elif log["attack_event"] == "Under Attack" and int(log["dos_attack_id"]) > 0 and not under_attack:
                under_attack = True
            # Attack ended
            elif log["attack_event"] == "Attack ended" and int(log["dos_attack_id"]) > 0 and not attack_ended:
                attack_ended = True

        assert no_attack and attack_started and under_attack and attack_ended

    @pytest.mark.skip
    def test_dos_under_attack_with_learning(
        self,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_dos,
        virtual_server_setup_dos,
        dos_setup,
        test_namespace,
    ):
        """
        Test App Protect Dos: Block bad clients attack with learning
        """
        log_loc = f"/var/log/messages"
        print("----------------------- Get syslog pod name ----------------------")
        syslog_pod = self.getPodNameThatContains(kube_apis, ingress_controller_prerequisites.namespace, "syslog")
        assert "syslog" in syslog_pod
        clear_file_contents(kube_apis.v1, log_loc, syslog_pod, ingress_controller_prerequisites.namespace)

        print("------------------------- Learning Phase -----------------------------")
        print("start good clients requests")
        p_good_client = subprocess.Popen(
            [f"exec {TEST_DATA}/dos/good_clients_xff.sh {virtual_server_setup_dos.vs_host} {dos_setup.req_url}"],
            preexec_fn=os.setsid,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        print("Learning for max 15 minutes")
        nginx_ingress_pod_name = self.getPodNameThatContains(
            kube_apis, ingress_controller_prerequisites.namespace, "nginx"
        )
        check_learning_status_with_admd_s(
            kube_apis,
            nginx_ingress_pod_name,
            ingress_controller_prerequisites.namespace,
            900,
        )

        print("------------------------- Attack -----------------------------")
        print("start bad clients requests")
        p_attack = subprocess.Popen(
            [f"exec {TEST_DATA}/dos/bad_clients_xff.sh {virtual_server_setup_dos.vs_host} {dos_setup.req_url}"],
            preexec_fn=os.setsid,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        print("Wait max 5 Min until finding 3 bad clients")
        find_in_log(
            kube_apis,
            log_loc,
            syslog_pod,
            ingress_controller_prerequisites.namespace,
            300,
            'bad_actors="3"',
        )

        print("Stop Attack")
        p_attack.terminate()

        print("wait max 200 seconds after attack stop, to get attack ended")
        find_in_log(
            kube_apis,
            log_loc,
            syslog_pod,
            ingress_controller_prerequisites.namespace,
            200,
            'attack_event="Attack ended"',
        )

        print("Stop Good Client")
        p_good_client.terminate()

        log_contents = get_file_contents(kube_apis.v1, log_loc, syslog_pod, ingress_controller_prerequisites.namespace)
        log_info_dic = log_content_to_dic(log_contents)

        # Analyze the log
        no_attack = False
        attack_started = False
        under_attack = False
        attack_ended = False
        bad_actor_detected = False
        signature_detected = False
        health_ok = False
        bad_ip = ["1.1.1.1", "1.1.1.2", "1.1.1.3"]
        fmt = "%b %d %Y %H:%M:%S"
        for log in log_info_dic:
            if log["attack_event"] == "No Attack":
                if int(log["dos_attack_id"]) == 0 and not no_attack:
                    no_attack = True
            elif log["attack_event"] == "Attack started":
                if int(log["dos_attack_id"]) > 0 and not attack_started:
                    attack_started = True
                    start_attack_time = datetime.strptime(log["date_time"], fmt)
            elif log["attack_event"] == "Under Attack":
                under_attack = True
                if not health_ok and float(log["stress_level"]) < 0.6:
                    health_ok = True
                    health_ok_time = datetime.strptime(log["date_time"], fmt)
                    if not signature_detected and int(log["mitigated_by_signatures"]) > 0:
                        signature_detected = True
            elif log["attack_event"] == "Bad actors detected":
                if under_attack:
                    bad_actor_detected = True
            elif log["attack_event"] == "Bad actor detection":
                if under_attack and log["source_ip"] in bad_ip:
                    bad_ip.remove(log["source_ip"])
            elif log["attack_event"] == "Attack ended":
                attack_ended = True

        assert (
            no_attack
            and attack_started
            and under_attack
            and attack_ended
            and health_ok
            and (health_ok_time - start_attack_time).total_seconds() < 150
            and signature_detected
            and bad_actor_detected
            and len(bad_ip) <= 1
        )

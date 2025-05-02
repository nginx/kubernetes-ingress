import pytest
import requests
import yaml
from settings import CRDS, TEST_DATA
from suite.utils.ap_resources_utils import (
    create_ap_logconf_from_yaml,
    create_ap_policy_from_yaml,
    create_ap_usersig_from_yaml,
    delete_and_create_ap_policy_from_yaml,
    delete_ap_logconf,
    delete_ap_policy,
    read_ap_custom_resource,
)
from suite.utils.resources_utils import (
    clear_file_contents,
    create_example_app,
    create_ingress,
    create_ingress_with_ap_annotations,
    create_items_from_yaml,
    delete_common_app,
    delete_items_from_yaml,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    get_file_contents,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    get_last_reload_time,
    get_pod_name_that_contains,
    get_pods_amount,
    get_test_file_name,
    scale_deployment,
    wait_before_test,
    wait_until_all_pods_are_ready,
    write_to_json,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml

src_ing_yaml = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"
ap_policy = "dataguard-alarm"
ap_policy_uds = "dataguard-alarm-uds"
uds_crd = f"{CRDS}/appprotect.f5.com_apusersigs.yaml"
uds_crd_resource = f"{TEST_DATA}/appprotect/ap-ic-uds.yaml"
valid_resp_addr = "Server address:"
valid_resp_name = "Server name:"
invalid_resp_title = "Request Rejected"
invalid_resp_body = "The requested URL was rejected. Please consult with your administrator."
reload_times = {}


class AppProtectSetup:
    """
    Encapsulate the example details.
    Attributes:
        req_url (str):
        metrics_url (str):
    """

    def __init__(self, req_url, metrics_url):
        self.req_url = req_url
        self.metrics_url = metrics_url


@pytest.fixture(scope="class")
def appprotect_setup(request, kube_apis, ingress_controller_endpoint, test_namespace) -> AppProtectSetup:
    """
    Deploy simple application and all the AppProtect(dataguard-alarm) resources under test in one namespace.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :param test_namespace:
    :return: BackendSetup
    """
    print("------------------------- Deploy simple backend application -------------------------")
    create_example_app(kube_apis, "simple", test_namespace)
    req_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"
    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )

    print("------------------------- Deploy Secret -----------------------------")
    src_sec_yaml = f"{TEST_DATA}/appprotect/appprotect-secret.yaml"
    create_items_from_yaml(kube_apis, src_sec_yaml, test_namespace)

    print("------------------------- Deploy logconf -----------------------------")
    src_log_yaml = f"{TEST_DATA}/appprotect/logconf.yaml"
    log_name = create_ap_logconf_from_yaml(kube_apis.custom_objects, src_log_yaml, test_namespace)

    print("------------------------- Deploy dataguard-alarm appolicy ---------------------------")
    src_pol_yaml = f"{TEST_DATA}/appprotect/{ap_policy}.yaml"
    pol_name = create_ap_policy_from_yaml(kube_apis.custom_objects, src_pol_yaml, test_namespace)

    print("------------------------- Deploy syslog server ---------------------------")
    src_syslog_yaml = f"{TEST_DATA}/appprotect/syslog.yaml"
    create_items_from_yaml(kube_apis, src_syslog_yaml, test_namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            delete_items_from_yaml(kube_apis, src_syslog_yaml, test_namespace)
            delete_ap_policy(kube_apis.custom_objects, pol_name, test_namespace)
            delete_ap_logconf(kube_apis.custom_objects, log_name, test_namespace)
            delete_common_app(kube_apis, "simple", test_namespace)
            src_sec_yaml = f"{TEST_DATA}/appprotect/appprotect-secret.yaml"
            delete_items_from_yaml(kube_apis, src_sec_yaml, test_namespace)
            write_to_json(f"reload-{get_test_file_name(request.node.fspath)}.json", reload_times)

    request.addfinalizer(fin)

    return AppProtectSetup(req_url, metrics_url)


def assert_ap_crd_info(ap_crd_info, policy_name) -> None:
    """
    Assert fields in AppProtect policy documents
    :param ap_crd_info: CRD output from k8s API
    """
    assert ap_crd_info["kind"] == "APPolicy"
    assert ap_crd_info["metadata"]["name"] == policy_name
    assert ap_crd_info["spec"]["policy"]["enforcementMode"] == "blocking"
    assert ap_crd_info["spec"]["policy"]["blocking-settings"]["violations"][0]["name"] == "VIOL_DATA_GUARD"


def assert_invalid_responses(response) -> None:
    """
    Assert responses when policy config is blocking requests
    :param response: Response
    """
    assert invalid_resp_title in response.text
    assert invalid_resp_body in response.text
    assert response.status_code == 200


def assert_valid_responses(response) -> None:
    """
    Assert responses when policy config is allowing requests
    :param response: Response
    """
    assert valid_resp_name in response.text
    assert valid_resp_addr in response.text
    assert response.status_code == 200


@pytest.mark.skip_for_nginx_oss
@pytest.mark.appprotect
@pytest.mark.appprotect_integration
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
    [
        {
            "extra_args": [
                "-enable-custom-resources",
                "-enable-app-protect",
                "-enable-prometheus-metrics",
            ]
        }
    ],
    indirect=["crd_ingress_controller_with_ap"],
)
class TestAppProtect:
    def test_ap_nginx_config_entries(self, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace):
        """
        Test to verify AppProtect annotations in nginx config
        """
        conf_annotations = [
            "app_protect_enable on;",
            f"app_protect_policy_file /etc/nginx/waf/nac-policies/{test_namespace}_{ap_policy};",
            "app_protect_security_log_enable on;",
            f"app_protect_security_log /etc/nginx/waf/nac-logconfs/{test_namespace}_logconf syslog:server=127.0.0.1:514;",
        ]

        create_ingress_with_ap_annotations(
            kube_apis, src_ing_yaml, test_namespace, ap_policy, "True", "True", "127.0.0.1:514"
        )

        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host, check404=True)

        pod_name = get_first_pod_name(kube_apis.v1, "nginx-ingress")

        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1, test_namespace, "appprotect-ingress", pod_name, "nginx-ingress"
        )
        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)

        for _ in conf_annotations:
            assert _ in result_conf

    @pytest.mark.smoke
    def test_ap_enable_true_policy_correct(
        self, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    ):
        """
        Test malicious script request is rejected while AppProtect is enabled in Ingress
        """
        create_ingress_with_ap_annotations(
            kube_apis, src_ing_yaml, test_namespace, ap_policy, "True", "True", "127.0.0.1:514"
        )
        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

        print("--------- Run test while AppProtect module is enabled with correct policy ---------")

        ap_crd_info = read_ap_custom_resource(kube_apis.custom_objects, test_namespace, "appolicies", ap_policy)
        assert_ap_crd_info(ap_crd_info, ap_policy)
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host, check404=True)

        print("----------------------- Send request ----------------------")
        response = requests.get(appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False)
        print(response.text)
        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
        assert_invalid_responses(response)

    def test_ap_enable_false_policy_correct(
        self, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    ):
        """
        Test malicious script request is working normally while AppProtect is disabled in Ingress
        """
        create_ingress_with_ap_annotations(
            kube_apis, src_ing_yaml, test_namespace, ap_policy, "False", "True", "127.0.0.1:514"
        )
        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

        print("--------- Run test while AppProtect module is disabled with correct policy ---------")

        ap_crd_info = read_ap_custom_resource(kube_apis.custom_objects, test_namespace, "appolicies", ap_policy)
        assert_ap_crd_info(ap_crd_info, ap_policy)
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host, check404=True)
        wait_before_test(5)

        print("----------------------- Send request ----------------------")
        response = requests.get(appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False)
        print(response.text)
        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
        assert_valid_responses(response)

    def test_ap_enable_true_policy_incorrect(
        self, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    ):
        """
        Test malicious script request is blocked by default policy while AppProtect is enabled with incorrect policy in ingress
        """
        create_ingress_with_ap_annotations(
            kube_apis,
            src_ing_yaml,
            test_namespace,
            "invalid-policy",
            "True",
            "True",
            "127.0.0.1:514",
        )
        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

        print("--------- Run test while AppProtect module is enabled with incorrect policy ---------")

        ensure_response_from_backend(appprotect_setup.req_url, ingress_host, check404=True)

        print("----------------------- Send request ----------------------")
        response = requests.get(appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False)
        print(response.text)
        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
        assert_invalid_responses(response)

    def test_ap_enable_false_policy_incorrect(
        self, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    ):
        """
        Test malicious script request is working normally while AppProtect is disabled in with incorrect policy in ingress
        """
        create_ingress_with_ap_annotations(
            kube_apis,
            src_ing_yaml,
            test_namespace,
            "invalid-policy",
            "False",
            "True",
            "127.0.0.1:514",
        )
        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

        print("--------- Run test while AppProtect module is disabled with incorrect policy ---------")

        ensure_response_from_backend(appprotect_setup.req_url, ingress_host, check404=True)

        print("----------------------- Send request ----------------------")
        wait_before_test(5)
        response = requests.get(appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False)
        print(response.text)
        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
        assert_valid_responses(response)

    @pytest.mark.startup
    def test_ap_pod_startup(
        self,
        request,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_ap,
        appprotect_setup,
        test_namespace,
    ):
        """
        Log pod startup time while scaling up from 0 to 1
        """
        syslog_dst = f"syslog-svc.{test_namespace}"

        create_ingress_with_ap_annotations(
            kube_apis, src_ing_yaml, test_namespace, ap_policy, "True", "True", f"{syslog_dst}:514"
        )
        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)
        print("--------- AppProtect module is enabled with correct policy ---------")
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host, check404=True)

        ns = ingress_controller_prerequisites.namespace

        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ns, 0)
        while get_pods_amount(kube_apis.v1, ns) != 0:
            print(f"Number of replicas not 0, retrying...")
            wait_before_test()
        num = scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ns, 1)
        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)

        assert num is None

    @pytest.mark.flaky(max_runs=3)
    def test_ap_multi_sec_logs(
        self, request, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    ):
        """
        Test corresponding log entries with multiple log destinations (in this case, two syslog servers)
        """
        src_syslog2_yaml = f"{TEST_DATA}/appprotect/syslog2.yaml"
        log_loc = "/var/log/messages"

        print("Create a second syslog server")
        create_items_from_yaml(kube_apis, src_syslog2_yaml, test_namespace)

        syslog_dst = f"syslog-svc.{test_namespace}"
        syslog2_dst = f"syslog2-svc.{test_namespace}"

        with open(src_ing_yaml) as f:
            doc = yaml.safe_load(f)

            doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-policy"] = ap_policy
            doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-enable"] = "True"
            doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-security-log-enable"] = "True"

            # both lists need to be the same length, if one of the referenced configs is invalid/non-existent then no logconfs are applied.
            doc["metadata"]["annotations"][
                "appprotect.f5.com/app-protect-security-log"
            ] = f"{test_namespace}/logconf,{test_namespace}/logconf"

            doc["metadata"]["annotations"][
                "appprotect.f5.com/app-protect-security-log-destination"
            ] = f"syslog:server={syslog_dst}:514,syslog:server={syslog2_dst}:514"

        create_ingress(kube_apis.networking_v1, test_namespace, doc)

        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

        wait_before_test(30)
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host, check404=True)

        print("----------------------- Send request ----------------------")
        response = requests.get(appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False)
        print(response.text)
        syslog_pod = get_pod_name_that_contains(kube_apis.v1, test_namespace, "syslog-")
        syslog2_pod = get_pod_name_that_contains(kube_apis.v1, test_namespace, "syslog2")
        log_contents = ""
        log2_contents = ""
        retry = 0
        while "ASM:attack_type" not in log_contents and "ASM:attack_type" not in log2_contents and retry <= 60:
            log_contents = get_file_contents(kube_apis.v1, log_loc, syslog_pod, test_namespace)
            log2_contents = get_file_contents(kube_apis.v1, log_loc, syslog2_pod, test_namespace)
            retry += 1
            wait_before_test(1)
            print(f"Security log not updated, retrying... #{retry}")

        reload_ms = get_last_reload_time(appprotect_setup.metrics_url, "nginx")
        print(f"last reload duration: {reload_ms} ms")
        reload_times[f"{request.node.name}"] = f"last reload duration: {reload_ms} ms"

        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
        delete_items_from_yaml(kube_apis, src_syslog2_yaml, test_namespace)
        clear_file_contents(kube_apis.v1, log_loc, syslog_pod, test_namespace)

        assert_invalid_responses(response)
        # check logs in dest. #1 i.e. syslog server #1
        assert (
            "ASM:attack_type=" in str(log_contents)
            and "severity=" in str(log_contents)
            and "request_status=" in str(log_contents)
            and "outcome=" in str(log_contents)
        )
        # check logs in dest. #2 i.e. syslog server #2
        assert (
            "ASM:attack_type=" in str(log2_contents)
            and "severity=" in str(log2_contents)
            and "request_status=" in str(log2_contents)
            and "outcome=" in str(log2_contents)
        )

    @pytest.mark.flaky(max_runs=3)
    def test_ap_enable_true_policy_correct_uds(
        self, request, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    ):
        """
        Test request with UDS rule string is rejected while AppProtect with User Defined Signatures is enabled in Ingress
        """

        create_ap_usersig_from_yaml(kube_apis.custom_objects, uds_crd_resource, test_namespace)
        # Apply dataguard-alarm AP policy with UDS
        delete_and_create_ap_policy_from_yaml(
            kube_apis.custom_objects,
            ap_policy,
            f"{TEST_DATA}/appprotect/{ap_policy_uds}.yaml",
            test_namespace,
        )
        wait_before_test()

        create_ingress_with_ap_annotations(
            kube_apis, src_ing_yaml, test_namespace, ap_policy, "True", "True", "127.0.0.1:514"
        )
        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

        print("--------- Run test while AppProtect module is enabled with correct policy and UDS ---------")

        ap_crd_info = read_ap_custom_resource(kube_apis.custom_objects, test_namespace, "appolicies", ap_policy)

        wait_before_test(120)
        ensure_response_from_backend(appprotect_setup.req_url, ingress_host, check404=True)
        print("----------------------- Send request ----------------------")
        response1 = requests.get(appprotect_setup.req_url, headers={"host": ingress_host}, verify=False, data="kic")
        print(response1.text)
        response2 = requests.get(appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False)
        print(response2.text)
        reload_ms = get_last_reload_time(appprotect_setup.metrics_url, "nginx")
        print(f"last reload duration: {reload_ms} ms")
        reload_times[f"{request.node.name}"] = f"last reload duration: {reload_ms} ms"

        # Restore default dataguard-alarm policy
        delete_and_create_ap_policy_from_yaml(
            kube_apis.custom_objects,
            ap_policy,
            f"{TEST_DATA}/appprotect/{ap_policy}.yaml",
            test_namespace,
        )
        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)

        assert_ap_crd_info(ap_crd_info, ap_policy)
        assert_invalid_responses(response1)
        assert_invalid_responses(response2)

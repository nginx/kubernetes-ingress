import pytest
import requests
import yaml
from settings import TEST_DATA
from suite.utils.ap_resources_utils import (
    create_ap_logconf_from_yaml,
    create_ap_policy_from_yaml,
    create_ap_usersig_from_yaml,
    create_ap_waf_policy_from_yaml,
    delete_ap_logconf,
    delete_ap_policy,
    delete_ap_usersig,
)
from suite.utils.policy_resources_utils import delete_policy
from suite.utils.resources_utils import (
    create_example_app,
    create_ingress,
    create_ingress_with_ap_annotations,
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_common_app,
    delete_ingress,
    delete_items_from_yaml,
    delete_secret,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    get_last_reload_status,
    get_pods_amount,
    get_total_ingresses,
    get_total_vs,
    get_total_vsr,
    scale_deployment,
    wait_before_test,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import (
    create_v_s_route,
    create_virtual_server,
    delete_virtual_server,
    patch_virtual_server_from_yaml,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml


class IngressSetup:
    """
    Encapsulate the Smoke Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        ingress_host (str):
    """

    def __init__(self, req_url, metrics_url, ingress_host):
        self.req_url = req_url
        self.metrics_url = metrics_url
        self.ingress_host = ingress_host


@pytest.fixture(scope="class")
def simple_ingress_setup(
    request,
    kube_apis,
    ingress_controller_endpoint,
    test_namespace,
    ingress_controller,
) -> IngressSetup:
    """
    Deploy simple application and all the Ingress resources under test in one namespace.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :param test_namespace:
    :return: BackendSetup
    """
    req_url = f"https://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port_ssl}/backend1"
    metrics_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"

    secret_name = create_secret_from_yaml(kube_apis.v1, test_namespace, f"{TEST_DATA}/smoke/smoke-secret.yaml")
    create_example_app(kube_apis, "simple", test_namespace)
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml", test_namespace)

    ingress_host = get_first_ingress_host_from_yaml(f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml")
    wait_until_all_pods_are_ready(kube_apis.v1, test_namespace)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )

    def fin():
        print("Clean up the Application:")
        delete_common_app(kube_apis, "simple", test_namespace)
        delete_secret(kube_apis.v1, secret_name, test_namespace)
        delete_items_from_yaml(kube_apis, f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml", test_namespace)

    request.addfinalizer(fin)

    return IngressSetup(req_url, metrics_url, ingress_host)


@pytest.mark.batch_start
class TestMultipleSimpleIngress:
    @pytest.mark.parametrize(
        "ingress_controller",
        [
            pytest.param(
                {"extra_args": ["-enable-prometheus-metrics"]},
            )
        ],
        indirect=["ingress_controller"],
    )
    def test_simple_ingress_batch_start(
        self,
        request,
        kube_apis,
        ingress_controller_prerequisites,
        ingress_controller,
        test_namespace,
        simple_ingress_setup,
    ):
        """
        Pod startup time with simple Ingress
        """
        ensure_response_from_backend(simple_ingress_setup.req_url, simple_ingress_setup.ingress_host, check404=True)

        total_ing = int(request.config.getoption("--batch-resources"))
        manifest = f"{TEST_DATA}/smoke/standard/smoke-ingress.yaml"
        for i in range(1, total_ing + 1):
            with open(manifest) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"smoke-ingress-{i}"
                doc["spec"]["rules"][0]["host"] = f"smoke-{i}.example.com"
                create_ingress(kube_apis.networking_v1, test_namespace, doc)
        print(f"Total resources deployed is {total_ing}")
        wait_before_test()
        ic_ns = ingress_controller_prerequisites.namespace
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ic_ns, 0)
        while get_pods_amount(kube_apis.v1, ic_ns) != 0:
            print(f"Number of replicas not 0, retrying...")
            wait_before_test()
        num = scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ic_ns, 1)
        assert (
            get_total_ingresses(simple_ingress_setup.metrics_url, "nginx") == str(total_ing + 1)
            and get_last_reload_status(simple_ingress_setup.metrics_url, "nginx") == "1"
        )

        for i in range(1, total_ing + 1):
            delete_ingress(kube_apis.networking_v1, f"smoke-ingress-{i}", test_namespace)

        assert num is None


##############################################################################################################


@pytest.fixture(scope="class")
def ap_ingress_setup(request, kube_apis, ingress_controller_endpoint, test_namespace) -> IngressSetup:
    """
    Deploy a simple application and AppProtect manifests.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :param test_namespace:
    :return: BackendSetup
    """
    print("------------------------- Deploy backend application -------------------------")
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

    print(f"------------------------- Deploy appolicy: ---------------------------")
    src_pol_yaml = f"{TEST_DATA}/appprotect/dataguard-alarm.yaml"
    pol_name = create_ap_policy_from_yaml(kube_apis.custom_objects, src_pol_yaml, test_namespace)

    print("------------------------- Deploy ingress -----------------------------")
    ingress_host = {}
    src_ing_yaml = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"
    create_ingress_with_ap_annotations(
        kube_apis, src_ing_yaml, test_namespace, "dataguard-alarm", "True", "True", "127.0.0.1:514"
    )
    ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)
    wait_before_test()

    def fin():
        print("Clean up:")
        src_ing_yaml = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"
        delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
        delete_ap_policy(kube_apis.custom_objects, pol_name, test_namespace)
        delete_ap_logconf(kube_apis.custom_objects, log_name, test_namespace)
        delete_common_app(kube_apis, "simple", test_namespace)
        src_sec_yaml = f"{TEST_DATA}/appprotect/appprotect-secret.yaml"
        delete_items_from_yaml(kube_apis, src_sec_yaml, test_namespace)

    request.addfinalizer(fin)

    return IngressSetup(req_url, metrics_url, ingress_host)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.batch_start
@pytest.mark.appprotect
@pytest.mark.appprotect_batch
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
    [
        {
            "extra_args": [
                f"-enable-custom-resources",
                f"-enable-app-protect",
                f"-enable-prometheus-metrics",
            ]
        }
    ],
    indirect=True,
)
class TestAppProtect:
    def test_ap_ingress_batch_start(
        self,
        request,
        kube_apis,
        crd_ingress_controller_with_ap,
        ap_ingress_setup,
        ingress_controller_prerequisites,
        test_namespace,
    ):
        """
        Pod startup time with AP Ingress
        """
        print("------------- Run test for AP policy: dataguard-alarm --------------")
        print(f"Request URL: {ap_ingress_setup.req_url} and Host: {ap_ingress_setup.ingress_host}")

        ensure_response_from_backend(ap_ingress_setup.req_url, ap_ingress_setup.ingress_host, check404=True)

        total_ing = int(request.config.getoption("--batch-resources"))

        manifest = f"{TEST_DATA}/appprotect/appprotect-ingress.yaml"
        for i in range(1, total_ing + 1):
            with open(manifest) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"appprotect-ingress-{i}"
                doc["spec"]["rules"][0]["host"] = f"appprotect-{i}.example.com"
                create_ingress(kube_apis.networking_v1, test_namespace, doc)
        print(f"Total resources deployed is {total_ing}")
        wait_before_test()
        ic_ns = ingress_controller_prerequisites.namespace
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ic_ns, 0)
        while get_pods_amount(kube_apis.v1, ic_ns) != 0:
            print(f"Number of replicas not 0, retrying...")
            wait_before_test()
        num = scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ic_ns, 1)
        wait_before_test(30)

        assert (
            get_total_ingresses(ap_ingress_setup.metrics_url, "nginx") == str(total_ing + 1)
            and get_last_reload_status(ap_ingress_setup.metrics_url, "nginx") == "1"
        )

        for i in range(1, total_ing + 1):
            delete_ingress(kube_apis.networking_v1, f"appprotect-ingress-{i}", test_namespace)

        assert num is None


##############################################################################################################


@pytest.mark.batch_start
@pytest.mark.parametrize(
    "crd_ingress_controller, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [f"-enable-custom-resources", f"-enable-prometheus-metrics"],
            },
            {"example": "virtual-server", "app_type": "simple"},
        )
    ],
    indirect=True,
)
class TestVirtualServer:
    def test_vs_batch_start(
        self,
        request,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        virtual_server_setup,
        test_namespace,
    ):
        """
        Pod startup time with simple VS
        """
        resp = requests.get(virtual_server_setup.backend_1_url, headers={"host": virtual_server_setup.vs_host})
        assert resp.status_code == 200
        total_vs = int(request.config.getoption("--batch-resources"))
        manifest = f"{TEST_DATA}/virtual-server/standard/virtual-server.yaml"
        for i in range(1, total_vs + 1):
            with open(manifest) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"virtual-server-{i}"
                doc["spec"]["host"] = f"virtual-server-{i}.example.com"
                kube_apis.custom_objects.create_namespaced_custom_object(
                    "k8s.nginx.org", "v1", test_namespace, "virtualservers", doc
                )
                print(f"VirtualServer created with name '{doc['metadata']['name']}'")
        print(f"Total resources deployed is {total_vs}")
        wait_before_test()
        ic_ns = ingress_controller_prerequisites.namespace
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ic_ns, 0)
        while get_pods_amount(kube_apis.v1, ic_ns) != 0:
            print(f"Number of replicas not 0, retrying...")
            wait_before_test()
        num = scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ic_ns, 1)
        assert (
            get_total_vs(virtual_server_setup.metrics_url, "nginx") == str(total_vs + 1)
            and get_last_reload_status(virtual_server_setup.metrics_url, "nginx") == "1"
        )

        for i in range(1, total_vs + 1):
            delete_virtual_server(kube_apis.custom_objects, f"virtual-server-{i}", test_namespace)

        assert num is None


##############################################################################################################


@pytest.fixture(scope="class")
def appprotect_waf_setup(request, kube_apis, test_namespace) -> None:
    """
    Deploy simple application and all the AppProtect(dataguard-alarm) resources under test in one namespace.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :param test_namespace:
    """
    uds_crd_resource = f"{TEST_DATA}/ap-waf/ap-ic-uds.yaml"
    ap_policy_uds = "dataguard-alarm-uds"
    print("------------------------- Deploy logconf -----------------------------")
    src_log_yaml = f"{TEST_DATA}/ap-waf/logconf.yaml"
    global log_name
    log_name = create_ap_logconf_from_yaml(kube_apis.custom_objects, src_log_yaml, test_namespace)

    print("------------------------- Create UserSig CRD resource-----------------------------")
    usersig_name = create_ap_usersig_from_yaml(kube_apis.custom_objects, uds_crd_resource, test_namespace)

    print(f"------------------------- Deploy dataguard-alarm appolicy ---------------------------")
    src_pol_yaml = f"{TEST_DATA}/ap-waf/{ap_policy_uds}.yaml"
    global ap_pol_name
    ap_pol_name = create_ap_policy_from_yaml(kube_apis.custom_objects, src_pol_yaml, test_namespace)

    def fin():
        print("Clean up:")
        delete_ap_policy(kube_apis.custom_objects, ap_pol_name, test_namespace)
        delete_ap_usersig(kube_apis.custom_objects, usersig_name, test_namespace)
        delete_ap_logconf(kube_apis.custom_objects, log_name, test_namespace)

    request.addfinalizer(fin)


@pytest.mark.skip_for_nginx_oss
@pytest.mark.batch_start
@pytest.mark.appprotect
@pytest.mark.appprotect_batch
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                    f"-enable-app-protect",
                    f"-enable-prometheus-metrics",
                ],
            },
            {
                "example": "ap-waf",
                "app_type": "simple",
            },
        )
    ],
    indirect=True,
)
class TestAppProtectWAFPolicyVS:
    def test_ap_waf_policy_vs_batch_start(
        self,
        request,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller_with_ap,
        virtual_server_setup,
        appprotect_waf_setup,
        test_namespace,
    ):
        """
        Pod startup time with AP WAF Policy
        """
        waf_spec_vs_src = f"{TEST_DATA}/ap-waf/virtual-server-waf-spec.yaml"
        waf_pol_dataguard_src = f"{TEST_DATA}/ap-waf/policies/waf-dataguard.yaml"
        print(f"Create waf policy")
        create_ap_waf_policy_from_yaml(
            kube_apis.custom_objects,
            waf_pol_dataguard_src,
            test_namespace,
            test_namespace,
            True,
            False,
            ap_pol_name,
            log_name,
            "syslog:server=127.0.0.1:514",
        )
        wait_before_test()
        print(f"Patch vs with policy: {waf_spec_vs_src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            waf_spec_vs_src,
            virtual_server_setup.namespace,
        )
        wait_before_test(120)
        print("----------------------- Send request with embedded malicious script----------------------")
        response1 = requests.get(
            virtual_server_setup.backend_1_url + "</script>",
            headers={"host": virtual_server_setup.vs_host},
        )
        print(response1.status_code)

        print("----------------------- Send request with blocked keyword in UDS----------------------")
        response2 = requests.get(
            virtual_server_setup.backend_1_url,
            headers={"host": virtual_server_setup.vs_host},
            data="kic",
        )

        total_vs = int(request.config.getoption("--batch-resources"))
        print(response2.status_code)
        for i in range(1, total_vs + 1):
            with open(waf_spec_vs_src) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"virtual-server-{i}"
                doc["spec"]["host"] = f"virtual-server-{i}.example.com"
                kube_apis.custom_objects.create_namespaced_custom_object(
                    "k8s.nginx.org", "v1", test_namespace, "virtualservers", doc
                )
                print(f"VirtualServer created with name '{doc['metadata']['name']}'")

        print(f"Total resources deployed is {total_vs}")
        wait_before_test()
        ic_ns = ingress_controller_prerequisites.namespace
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ic_ns, 0)
        while get_pods_amount(kube_apis.v1, ic_ns) != 0:
            print(f"Number of replicas not 0, retrying...")
            wait_before_test()
        num = scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ic_ns, 1)
        assert (
            get_total_vs(virtual_server_setup.metrics_url, "nginx") == str(total_vs + 1)
            and get_last_reload_status(virtual_server_setup.metrics_url, "nginx") == "1"
        )

        for i in range(1, total_vs + 1):
            delete_virtual_server(kube_apis.custom_objects, f"virtual-server-{i}", test_namespace)
        delete_policy(kube_apis.custom_objects, "waf-policy", test_namespace)

        assert num is None


##############################################################################################################


@pytest.fixture(scope="class")
def vs_vsr_setup(
    request,
    kube_apis,
    test_namespace,
    ingress_controller_endpoint,
):
    """
    Deploy one VS with multiple VSRs.

    :param kube_apis: client apis
    :param test_namespace:
    :param ingress_controller_endpoint: public endpoint
    :return:
    """
    total_vsr = int(request.config.getoption("--batch-resources"))

    vsr_source = f"{TEST_DATA}/startup/virtual-server-routes/route.yaml"

    with open(vsr_source) as f:
        vsr = yaml.safe_load(f)

        for i in range(1, total_vsr + 1):
            vsr["metadata"]["name"] = f"route-{i}"
            vsr["spec"]["subroutes"][0]["path"] = f"/route-{i}"

            create_v_s_route(kube_apis.custom_objects, vsr, test_namespace)

    vs_source = f"{TEST_DATA}/startup/virtual-server-routes/virtual-server.yaml"

    with open(vs_source) as f:
        vs = yaml.safe_load(f)

        routes = []
        for i in range(1, total_vsr + 1):
            route = {"path": f"/route-{i}", "route": f"route-{i}"}
            routes.append(route)

        vs["spec"]["routes"] = routes
        create_virtual_server(kube_apis.custom_objects, vs, test_namespace)


@pytest.mark.batch_start
@pytest.mark.parametrize(
    "crd_ingress_controller",
    [
        pytest.param(
            {
                "type": "complete",
                "extra_args": [
                    "-enable-custom-resources",
                    "-enable-prometheus-metrics",
                    "-enable-leader-election=false",
                ],
            },
        )
    ],
    indirect=True,
)
class TestSingleVSMultipleVSRs:
    def test_startup_time(
        self,
        request,
        kube_apis,
        ingress_controller_prerequisites,
        crd_ingress_controller,
        ingress_controller_endpoint,
        vs_vsr_setup,
    ):
        """
        Pod startup time with 1 VS and multiple VSRs.
        """
        total_vsr = int(request.config.getoption("--batch-resources"))

        ic_ns = ingress_controller_prerequisites.namespace
        scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ic_ns, 0)
        while get_pods_amount(kube_apis.v1, ic_ns) != 0:
            print(f"Number of replicas not 0, retrying...")
            wait_before_test()
        num = scale_deployment(kube_apis.v1, kube_apis.apps_v1_api, "nginx-ingress", ic_ns, 1)

        metrics_url = (
            f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.metrics_port}/metrics"
        )

        assert (
            get_total_vs(metrics_url, "nginx") == "1"
            and get_total_vsr(metrics_url, "nginx") == str(total_vsr)
            and get_last_reload_status(metrics_url, "nginx") == "1"
        )

        assert num is None

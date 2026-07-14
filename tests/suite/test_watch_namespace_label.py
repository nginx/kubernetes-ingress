import pytest
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_example_app,
    create_items_from_yaml,
    create_namespace_with_name_from_yaml,
    delete_namespace,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    patch_namespace_with_label,
    retry_get_until_status_code,
    wait_until_all_pods_are_ready,
)
from suite.utils.vs_vsr_resources_utils import create_virtual_server_from_yaml
from suite.utils.yaml_utils import get_first_host_from_yaml, get_first_ingress_host_from_yaml


class BackendSetup:
    """
    Encapsulate the example details.

    Attributes:
        req_url (str):
        resource_hosts (dict):
    """

    def __init__(self, req_url, resource_hosts):
        self.req_url = req_url
        self.resource_hosts = resource_hosts


@pytest.fixture(scope="class")
def backend_setup(request, kube_apis, ingress_controller_endpoint) -> BackendSetup:
    """
    Create 3 namespaces and deploy simple applications in them.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :return: BackendSetup
    """
    resource_hosts = {}
    namespaces = []
    for ns in ["watched-ns", "foreign-ns", "watched-ns2"]:
        namespace, ingress_host = create_and_setup_namespace(kube_apis, ingress_controller_endpoint, ns)
        resource_hosts[f"{ns}-ingress"] = ingress_host
        namespaces.append(namespace)

    req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"
    # add label to namespaces
    patch_namespace_with_label(kube_apis.v1, "watched-ns", "watch", f"{TEST_DATA}/common/ns-patch.yaml")
    patch_namespace_with_label(kube_apis.v1, "watched-ns2", "watch", f"{TEST_DATA}/common/ns-patch.yaml")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            for ns in namespaces:
                delete_namespace(kube_apis.v1, ns)

    request.addfinalizer(fin)

    return BackendSetup(req_url, resource_hosts)


@pytest.fixture(scope="class")
def backend_setup_vs(request, kube_apis, ingress_controller_endpoint) -> BackendSetup:
    """
    Create 3 namespaces and deploy simple applications in them.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :return: BackendSetup
    """
    resource_hosts = {}
    namespaces = []
    for ns in ["watched-ns", "foreign-ns", "watched-ns2"]:
        namespace, vs_host = create_and_setup_namespace(kube_apis, ingress_controller_endpoint, ns, is_vs=True)
        resource_hosts[f"{ns}-vs"] = vs_host
        namespaces.append(namespace)

    req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"
    # add label to namespaces
    patch_namespace_with_label(kube_apis.v1, "watched-ns", "watch", f"{TEST_DATA}/common/ns-patch.yaml")
    patch_namespace_with_label(kube_apis.v1, "watched-ns2", "watch", f"{TEST_DATA}/common/ns-patch.yaml")

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            for ns in namespaces:
                delete_namespace(kube_apis.v1, ns)

    request.addfinalizer(fin)

    return BackendSetup(req_url, resource_hosts)


def create_and_setup_namespace(kube_apis, ingress_controller_endpoint, ns_name, is_vs=False):
    ns = create_namespace_with_name_from_yaml(kube_apis.v1, ns_name, f"{TEST_DATA}/common/ns.yaml")
    print(f"------------------------- Deploy the backend in {ns} -----------------------------------")
    create_example_app(kube_apis, "simple", ns)
    src_ing_yaml = f"{TEST_DATA}/watch-namespace/{ns}-ingress.yaml"
    src_vs_yaml = f"{TEST_DATA}/watch-namespace/{ns}-virtual-server.yaml"
    if not is_vs:
        create_items_from_yaml(kube_apis, src_ing_yaml, ns)
        ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)
    if is_vs:
        create_virtual_server_from_yaml(kube_apis.custom_objects, src_vs_yaml, ns)
        ingress_host = get_first_host_from_yaml(src_vs_yaml)
    req_url = f"http://{ingress_controller_endpoint.public_ip}:{ingress_controller_endpoint.port}/backend1"
    wait_until_all_pods_are_ready(kube_apis.v1, ns)
    ensure_connection_to_public_endpoint(
        ingress_controller_endpoint.public_ip,
        ingress_controller_endpoint.port,
        ingress_controller_endpoint.port_ssl,
    )
    return ns, ingress_host


@pytest.mark.ingresses
@pytest.mark.watch_namespace
@pytest.mark.parametrize(
    "ingress_controller, expected_responses",
    [
        pytest.param(
            {"extra_args": ["-watch-namespace-label=app=watch"]},
            {"watched-ns-ingress": 200, "watched-ns2-ingress": 200, "foreign-ns-ingress": 404},
        )
    ],
    indirect=["ingress_controller"],
)
class TestWatchNamespaceLabelIngress:
    def test_response_codes(self, kube_apis, ingress_controller, backend_setup, expected_responses):
        for ing in ["watched-ns-ingress", "watched-ns2-ingress", "foreign-ns-ingress"]:
            ensure_response_from_backend(backend_setup.req_url, backend_setup.resource_hosts[ing])
            # Tolerate connections dropped by an NGINX reload from the namespace label change.
            resp = retry_get_until_status_code(
                backend_setup.req_url, backend_setup.resource_hosts[ing], expected_responses[ing], retries=3
            )
            assert (
                resp.status_code == expected_responses[ing]
            ), f"Expected: {expected_responses[ing]} response code for {backend_setup.resource_hosts[ing]}"

        # Add label to foreign-ns-ingress and show traffic being served
        patch_namespace_with_label(kube_apis.v1, "foreign-ns", "watch", f"{TEST_DATA}/common/ns-patch.yaml")
        ensure_response_from_backend(backend_setup.req_url, backend_setup.resource_hosts[ing])
        ing = "foreign-ns-ingress"
        # Tolerate connections dropped by the NGINX reload from the namespace label change.
        resp = retry_get_until_status_code(backend_setup.req_url, backend_setup.resource_hosts[ing], 200, retries=3)
        assert (
            resp.status_code == 200
        ), f"Expected: 200 response code for {backend_setup.resource_hosts[ing]} after adding the correct label"

        # Remove label from foreign-ns-ingress and show traffic being ignored again
        patch_namespace_with_label(kube_apis.v1, "foreign-ns", "nowatch", f"{TEST_DATA}/common/ns-patch.yaml")
        ensure_response_from_backend(backend_setup.req_url, backend_setup.resource_hosts[ing])
        # Tolerate connections dropped by the NGINX reload from the namespace label change.
        resp = retry_get_until_status_code(
            backend_setup.req_url, backend_setup.resource_hosts[ing], expected_responses[ing], retries=3
        )
        assert (
            resp.status_code == expected_responses[ing]
        ), f"Expected: {expected_responses[ing]} response code for {backend_setup.resource_hosts[ing]} after removing the watched label"


@pytest.mark.vs
@pytest.mark.vs_responses
@pytest.mark.parametrize(
    "crd_ingress_controller, expected_responses",
    [
        pytest.param(
            {"type": "complete", "extra_args": ["-watch-namespace-label=app=watch", "-enable-custom-resources=true"]},
            {"watched-ns-vs": 200, "watched-ns2-vs": 200, "foreign-ns-vs": 404},
        )
    ],
    indirect=["crd_ingress_controller"],
)
class TestWatchNamespaceLabelVS:
    def test_response_codes(self, kube_apis, crd_ingress_controller, backend_setup_vs, expected_responses):
        for vs in ["watched-ns-vs", "watched-ns2-vs", "foreign-ns-vs"]:
            ensure_response_from_backend(backend_setup_vs.req_url, backend_setup_vs.resource_hosts[vs])
            # Tolerate connections dropped by an NGINX reload from the namespace label change.
            resp = retry_get_until_status_code(
                backend_setup_vs.req_url, backend_setup_vs.resource_hosts[vs], expected_responses[vs], retries=3
            )
            assert (
                resp.status_code == expected_responses[vs]
            ), f"Expected: {expected_responses[vs]} response code for {backend_setup_vs.resource_hosts[vs]}"

        # Add label to foreign-ns-vs and show traffic being served
        patch_namespace_with_label(kube_apis.v1, "foreign-ns", "watch", f"{TEST_DATA}/common/ns-patch.yaml")
        ensure_response_from_backend(backend_setup_vs.req_url, backend_setup_vs.resource_hosts[vs])
        vs = "foreign-ns-vs"
        # Tolerate connections dropped by the NGINX reload from the namespace label change.
        resp = retry_get_until_status_code(
            backend_setup_vs.req_url, backend_setup_vs.resource_hosts[vs], 200, retries=3
        )
        assert (
            resp.status_code == 200
        ), f"Expected: 200 response code for {backend_setup_vs.resource_hosts[vs]} after adding the correct label"

        # Remove label from foreign-ns-vs and show traffic being ignored again
        patch_namespace_with_label(kube_apis.v1, "foreign-ns", "nowatch", f"{TEST_DATA}/common/ns-patch.yaml")
        ensure_response_from_backend(backend_setup_vs.req_url, backend_setup_vs.resource_hosts[vs])
        # Tolerate connections dropped by the NGINX reload from the namespace label change.
        resp = retry_get_until_status_code(
            backend_setup_vs.req_url, backend_setup_vs.resource_hosts[vs], expected_responses[vs], retries=3
        )
        assert (
            resp.status_code == expected_responses[vs]
        ), f"Expected: {expected_responses[vs]} response code for {backend_setup_vs.resource_hosts[vs]} after removing the watched label"

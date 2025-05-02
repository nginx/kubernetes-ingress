import pytest
from settings import TEST_DATA
from suite.utils.resources_utils import (
    create_namespace_with_name_from_yaml,
    create_secret_from_yaml,
    delete_namespace,
    delete_secret,
    get_pod_name_that_contains,
    is_secret_present,
    wait_before_test,
)


@pytest.fixture(scope="class")
def setup_single_secret_and_ns(request, kube_apis):
    filtered_ns_1 = create_namespace_with_name_from_yaml(kube_apis.v1, f"filtered-ns-1", f"{TEST_DATA}/common/ns.yaml")
    filtered_secret_1 = create_secret_from_yaml(
        kube_apis.v1, filtered_ns_1, f"{TEST_DATA}/filter-secrets/filtered-secret-1.yaml"
    )
    wait_before_test(1)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            if is_secret_present(kube_apis.v1, filtered_secret_1, filtered_ns_1):
                delete_secret(kube_apis.v1, filtered_secret_1, filtered_ns_1)
            delete_namespace(kube_apis.v1, filtered_ns_1)

    request.addfinalizer(fin)


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller",
    [pytest.param({"extra_args": ["-log-level=debug"]})],
    indirect=["ingress_controller"],
)
class TestFilterSecret:
    def test_filter_secret_single_namespace(self, request, kube_apis, ingress_controller, setup_single_secret_and_ns):
        pod_name = get_pod_name_that_contains(kube_apis.v1, "nginx-ingress", "nginx-ingress")
        logs = kube_apis.v1.read_namespaced_pod_log(pod_name, "nginx-ingress")
        assert "helm.sh/release.v1" not in logs


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller",
    [pytest.param({"extra_args": ["-log-level=debug"]})],
    indirect=["ingress_controller"],
)
class TestFilterAfterIcCreated:
    def test_filter_secret_created_after_ic(self, request, kube_apis, ingress_controller):
        filtered_ns_1 = create_namespace_with_name_from_yaml(
            kube_apis.v1, f"filtered-ns-1", f"{TEST_DATA}/common/ns.yaml"
        )
        filtered_secret_1 = create_secret_from_yaml(
            kube_apis.v1, filtered_ns_1, f"{TEST_DATA}/filter-secrets/filtered-secret-1.yaml"
        )
        pod_name = get_pod_name_that_contains(kube_apis.v1, "nginx-ingress", "nginx-ingress")
        logs = kube_apis.v1.read_namespaced_pod_log(pod_name, "nginx-ingress")
        assert "helm.sh/release.v1" not in logs

        if is_secret_present(kube_apis.v1, filtered_secret_1, filtered_ns_1):
            delete_secret(kube_apis.v1, filtered_secret_1, filtered_ns_1)
        delete_namespace(kube_apis.v1, filtered_ns_1)


@pytest.fixture(scope="class")
def setup_multiple_ns_and_multiple_secrets(request, kube_apis):
    filtered_ns_1 = create_namespace_with_name_from_yaml(kube_apis.v1, f"filtered-ns-1", f"{TEST_DATA}/common/ns.yaml")
    filtered_ns_2 = create_namespace_with_name_from_yaml(kube_apis.v1, f"filtered-ns-2", f"{TEST_DATA}/common/ns.yaml")

    filtered_secret_1 = create_secret_from_yaml(
        kube_apis.v1, filtered_ns_1, f"{TEST_DATA}/filter-secrets/filtered-secret-1.yaml"
    )
    filtered_secret_2 = create_secret_from_yaml(
        kube_apis.v1, filtered_ns_2, f"{TEST_DATA}/filter-secrets/filtered-secret-2.yaml"
    )
    nginx_ingress_secret = create_secret_from_yaml(
        kube_apis.v1, "nginx-ingress", f"{TEST_DATA}/filter-secrets/nginx-ingress-secret.yaml"
    )
    wait_before_test(1)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up:")
            if is_secret_present(kube_apis.v1, filtered_secret_1, filtered_ns_1):
                delete_secret(kube_apis.v1, filtered_secret_1, filtered_ns_1)
            if is_secret_present(kube_apis.v1, filtered_secret_2, filtered_ns_2):
                delete_secret(kube_apis.v1, filtered_secret_2, filtered_ns_2)
            if is_secret_present(kube_apis.v1, nginx_ingress_secret, "nginx-ingress"):
                delete_secret(kube_apis.v1, nginx_ingress_secret, "nginx-ingress")
            delete_namespace(kube_apis.v1, filtered_ns_1)
            delete_namespace(kube_apis.v1, filtered_ns_2)

    request.addfinalizer(fin)


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller",
    [pytest.param({"extra_args": ["-log-level=debug", "-watch-namespace=filtered-ns-1,filtered-ns-2"]})],
    indirect=["ingress_controller"],
)
class TestFilterSecretMultipuleNamespace:
    def test_filter_secret_multi_namespace(
        self, request, kube_apis, ingress_controller, setup_multiple_ns_and_multiple_secrets
    ):
        pod_name = get_pod_name_that_contains(kube_apis.v1, "nginx-ingress", "nginx-ingress")
        logs = kube_apis.v1.read_namespaced_pod_log(pod_name, "nginx-ingress")
        assert "helm.sh/release.v1" not in logs


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "ingress_controller",
    [pytest.param({"extra_args": ["-log-level=debug", "-watch-namespace=filtered-ns-1,filtered-ns-2"]})],
    indirect=["ingress_controller"],
)
class TestFilterSecretMultipleNamespaceAfterIcCreated:
    def test_filter_secret_multiplue_created_after_ic(self, request, kube_apis, ingress_controller):
        filtered_ns_1 = create_namespace_with_name_from_yaml(
            kube_apis.v1, f"filtered-ns-1", f"{TEST_DATA}/common/ns.yaml"
        )
        filtered_ns_2 = create_namespace_with_name_from_yaml(
            kube_apis.v1, f"filtered-ns-2", f"{TEST_DATA}/common/ns.yaml"
        )

        filtered_secret_1 = create_secret_from_yaml(
            kube_apis.v1, filtered_ns_1, f"{TEST_DATA}/filter-secrets/filtered-secret-1.yaml"
        )
        filtered_secret_2 = create_secret_from_yaml(
            kube_apis.v1, filtered_ns_2, f"{TEST_DATA}/filter-secrets/filtered-secret-2.yaml"
        )
        nginx_ingress_secret = create_secret_from_yaml(
            kube_apis.v1, "nginx-ingress", f"{TEST_DATA}/filter-secrets/nginx-ingress-secret.yaml"
        )

        pod_name = get_pod_name_that_contains(kube_apis.v1, "nginx-ingress", "nginx-ingress")
        logs = kube_apis.v1.read_namespaced_pod_log(pod_name, "nginx-ingress")

        if is_secret_present(kube_apis.v1, filtered_secret_1, filtered_ns_1):
            delete_secret(kube_apis.v1, filtered_secret_1, filtered_ns_1)
        if is_secret_present(kube_apis.v1, filtered_secret_2, filtered_ns_2):
            delete_secret(kube_apis.v1, filtered_secret_2, filtered_ns_2)
        if is_secret_present(kube_apis.v1, nginx_ingress_secret, "nginx-ingress"):
            delete_secret(kube_apis.v1, nginx_ingress_secret, "nginx-ingress")
        delete_namespace(kube_apis.v1, filtered_ns_1)
        delete_namespace(kube_apis.v1, filtered_ns_2)

        assert "helm.sh/release.v1" not in logs

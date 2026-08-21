import pytest
from settings import DEPLOYMENTS, TEST_DATA
from suite.fixtures.fixtures import PublicEndpoint
from suite.utils.resources_utils import (
    create_items_from_yaml,
    delete_items_from_yaml,
    get_first_pod_name,
    get_ingress_nginx_template_conf,
    replace_configmap_from_yaml,
    wait_before_test,
)
from suite.utils.yaml_utils import get_first_ingress_host_from_yaml, get_name_from_yaml


class CustomAnnotationsSetup:
    """
    Encapsulate Custom Annotations Example details.

    Attributes:
        public_endpoint (PublicEndpoint):
        namespace (str):
        ingress_host (str):
    """

    def __init__(self, public_endpoint: PublicEndpoint, ingress_name, namespace, ingress_host, ic_pod_name):
        self.public_endpoint = public_endpoint
        self.namespace = namespace
        self.ingress_name = ingress_name
        self.ingress_host = ingress_host
        self.ic_pod_name = ic_pod_name
        self.backend_1_url = f"http://{public_endpoint.public_ip}:{public_endpoint.port}/backend1"
        self.backend_2_url = f"http://{public_endpoint.public_ip}:{public_endpoint.port}/backend2"


@pytest.fixture(scope="class")
def custom_annotations_setup(
    request,
    kube_apis,
    ingress_controller_prerequisites,
    ingress_controller,
    ingress_controller_endpoint,
    test_namespace,
) -> CustomAnnotationsSetup:
    ing_type = request.param
    print("------------------------- Deploy ConfigMap with custom template -----------------------------------")
    replace_configmap_from_yaml(
        kube_apis.v1,
        ingress_controller_prerequisites.config_map["metadata"]["name"],
        ingress_controller_prerequisites.namespace,
        f"{TEST_DATA}/custom-annotations/{ing_type}/nginx-config.yaml",
    )
    print("------------------------- Deploy Custom Annotations Ingress -----------------------------------")
    ing_src = f"{TEST_DATA}/custom-annotations/{ing_type}/annotations-ingress.yaml"
    create_items_from_yaml(kube_apis, ing_src, test_namespace)
    host = get_first_ingress_host_from_yaml(ing_src)
    ingress_name = get_name_from_yaml(ing_src)
    wait_before_test(1)

    ic_pod_name = get_first_pod_name(kube_apis.v1, ingress_controller_prerequisites.namespace)

    def fin():
        if request.config.getoption("--skip-fixture-teardown") == "no":
            print("Clean up Custom Annotations Example:")
            replace_configmap_from_yaml(
                kube_apis.v1,
                ingress_controller_prerequisites.config_map["metadata"]["name"],
                ingress_controller_prerequisites.namespace,
                f"{DEPLOYMENTS}/common/nginx-config.yaml",
            )
            delete_items_from_yaml(kube_apis, ing_src, test_namespace)

    request.addfinalizer(fin)

    return CustomAnnotationsSetup(ingress_controller_endpoint, ingress_name, test_namespace, host, ic_pod_name)


@pytest.mark.ingresses
@pytest.mark.parametrize(
    "custom_annotations_setup, expected_texts",
    [
        pytest.param(
            "standard",
            [
                "# This is TEST configuration for custom-annotations-ingress/",
                "# Insert config for test-split-feature: 192.168.1.1;",
                "# Insert config for test-split-feature: some-ip;",
                "# Insert config for feature A if the annotation is set",
                "# Print the value assigned to the annotation: 512",
            ],
            id="standard-ingress",
        ),
        pytest.param(
            "mergeable",
            [
                "# This is TEST configuration for custom-annotations-ingress-master/",
                "# Insert config for test-split-feature: master.ip;",
                "# Insert config for test-split-feature: master;",
                "# Insert config for test-split-feature minion: minion1;",
                "# Insert config for test-split-feature minion: minion2;",
                "# Insert config for feature A if the annotation is set",
                "# Print the value assigned to the annotation: 512",
            ],
            id="mergeable-ingress",
        ),
    ],
    indirect=["custom_annotations_setup"],
)
class TestCustomAnnotations:
    def test_nginx_config(
        self, kube_apis, ingress_controller_prerequisites, ingress_controller, custom_annotations_setup, expected_texts
    ):
        result_conf = get_ingress_nginx_template_conf(
            kube_apis.v1,
            custom_annotations_setup.namespace,
            custom_annotations_setup.ingress_name,
            custom_annotations_setup.ic_pod_name,
            ingress_controller_prerequisites.namespace,
        )
        for line in expected_texts:
            assert line in result_conf

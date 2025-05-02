import os
import tempfile

import pytest
import yaml
from settings import TEST_DATA
from suite.utils.custom_resources_utils import create_resource_from_manifest
from suite.utils.resources_utils import create_ingress, create_items_from_yaml, create_namespace, delete_namespace
from suite.utils.vs_vsr_resources_utils import create_virtual_server

tcp_deployment = f"{TEST_DATA}/upgrade-test-resources/tcp-deployment.yaml"
deployment = f"{TEST_DATA}/upgrade-test-resources/deployment.yaml"
service = f"{TEST_DATA}/upgrade-test-resources/service.yaml"
ns = f"{TEST_DATA}/upgrade-test-resources/ns.yaml"
ingress = f"{TEST_DATA}/upgrade-test-resources/ingress.yaml"
vs = f"{TEST_DATA}/upgrade-test-resources/virtual-server.yaml"
ts = f"{TEST_DATA}/upgrade-test-resources/transport-server.yaml"
secret = f"{TEST_DATA}/upgrade-test-resources/secret.yaml"

"""
Test class below only deployes resources for upgrade testing, NIC deployment should be done manually via helm.
Run `make upgrade-resources PYTEST_ARGS="create OR delete"` to create OR delete resources.
"""


@pytest.mark.upgrade
class TestUpgrade:
    @pytest.mark.create
    def test_create(self, request, kube_apis):
        count = int(request.config.getoption("--num"))

        for i in range(1, count + 1):
            with open(ns) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"ns-{i}"
                with tempfile.NamedTemporaryFile(mode="w+", suffix=".yml", delete=False) as temp:
                    temp.write(yaml.safe_dump(doc) + "---\n")
                namespace = create_namespace(kube_apis.v1, doc)
                os.remove(temp.name)

            with open(deployment) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"backend-{i}"
                doc["spec"]["selector"]["matchLabels"]["app"] = f"backend-{i}"
                doc["spec"]["template"]["metadata"]["labels"]["app"] = f"backend-{i}"
                doc["metadata"]["name"] = f"backend-{i}"
                with tempfile.NamedTemporaryFile(mode="w+", suffix=".yml", delete=False) as temp:
                    temp.write(yaml.safe_dump(doc) + "---\n")
                create_items_from_yaml(kube_apis, temp.name, namespace)
                os.remove(temp.name)

            with open(service) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"backend-svc-{i}"
                doc["spec"]["selector"]["app"] = f"backend-{i}"
                with tempfile.NamedTemporaryFile(mode="w+", suffix=".yml", delete=False) as temp:
                    temp.write(yaml.safe_dump(doc) + "---\n")
                create_items_from_yaml(kube_apis, temp.name, namespace)
                os.remove(temp.name)

            with open(secret) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"secret-{i}"
                with tempfile.NamedTemporaryFile(mode="w+", suffix=".yml", delete=False) as temp:
                    temp.write(yaml.safe_dump(doc) + "---\n")
                create_items_from_yaml(kube_apis, temp.name, namespace)
                os.remove(temp.name)

            # VirtualServer
            with open(vs) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"vs-{i}"
                doc["spec"]["host"] = f"vs-{i}.example.com"
                doc["spec"]["tls"]["secret"] = f"secret-{i}"
                doc["spec"]["upstreams"][0]["name"] = f"backend-{i}"
                doc["spec"]["upstreams"][0]["service"] = f"backend-svc-{i}"
                doc["spec"]["routes"][0]["action"]["pass"] = f"backend-{i}"
                create_virtual_server(kube_apis.custom_objects, doc, namespace)

            # Ingress
            with open(ingress) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"ingress-{i}"
                doc["spec"]["tls"][0]["hosts"][0] = f"ingress-{i}.example.com"
                doc["spec"]["tls"][0]["secretName"] = f"secret-{i}"
                doc["spec"]["rules"][0]["host"] = f"ingress-{i}.example.com"
                doc["spec"]["rules"][0]["http"]["paths"][0]["path"] = f"/backend-{i}"
                doc["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"] = f"backend-svc-{i}"
                create_ingress(kube_apis.networking_v1, namespace, doc)

            # TransportServer
            with open(tcp_deployment) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"tcp-{i}"
                doc["spec"]["selector"]["matchLabels"]["app"] = f"tcp-{i}"
                doc["spec"]["template"]["metadata"]["labels"]["app"] = f"tcp-{i}"
                with tempfile.NamedTemporaryFile(mode="w+", suffix=".yml", delete=False) as temp:
                    temp.write(yaml.safe_dump(doc) + "---\n")
                create_items_from_yaml(kube_apis, temp.name, namespace)
                os.remove(temp.name)

            with open(service) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"tcp-svc-{i}"
                doc["spec"]["selector"]["app"] = f"tcp-{i}"
                with tempfile.NamedTemporaryFile(mode="w+", suffix=".yml", delete=False) as temp:
                    temp.write(yaml.safe_dump(doc) + "---\n")
                create_items_from_yaml(kube_apis, temp.name, namespace)
                os.remove(temp.name)

            with open(ts) as f:
                doc = yaml.safe_load(f)
                doc["metadata"]["name"] = f"ts-{i}"
                doc["spec"]["listener"]["name"] = "dns-tcp"
                doc["spec"]["upstreams"][0]["name"] = f"tcp-{i}"
                doc["spec"]["upstreams"][0]["service"] = f"tcp-svc-{i}"
                doc["spec"]["upstreams"][0]["port"] = 5353
                doc["spec"]["action"]["pass"] = f"tcp-{i}"
                create_resource_from_manifest(kube_apis.custom_objects, doc, namespace, "transportservers")

    @pytest.mark.delete
    def test_delete(self, request, kube_apis):
        count = int(request.config.getoption("--num"))
        # delete namespaces
        for i in range(1, count + 1):
            delete_namespace(kube_apis.v1, f"ns-{i}")

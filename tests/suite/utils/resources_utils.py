"""Describe methods to utilize the kubernetes-client."""

import base64
import json
import os
import re
import time
from unittest import mock

import pytest
import requests
import yaml
from kubernetes.client import (
    AppsV1Api,
    CoreV1Api,
    NetworkingV1Api,
    RbacAuthorizationV1Api,
    V1Ingress,
    V1ObjectMeta,
    V1Secret,
    V1Service,
)
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from more_itertools import first
from settings import DEPLOYMENTS, NGX_REG, PROJECT_ROOT, RECONFIGURATION_DELAY, TEST_DATA, WAF_V5_VERSION
from suite.utils.ssl_utils import create_sni_session


class RBACAuthorization:
    """
    Encapsulate RBAC details.

    Attributes:
        role (str): cluster role name
        binding (str): cluster role binding name
    """

    def __init__(self, role: str, binding: str):
        self.role = role
        self.binding = binding


def configure_rbac(rbac_v1: RbacAuthorizationV1Api) -> RBACAuthorization:
    """
    Create cluster and binding.

    :param rbac_v1: RbacAuthorizationV1Api
    :return: RBACAuthorization
    """
    with open(f"{DEPLOYMENTS}/rbac/rbac.yaml") as f:
        docs = yaml.safe_load_all(f)
        role_name = ""
        binding_name = ""
        for dep in docs:
            if dep["kind"] == "ClusterRole":
                print("Create cluster role")
                role_name = dep["metadata"]["name"]
                rbac_v1.create_cluster_role(dep)
                print(f"Created role '{role_name}'")
            elif dep["kind"] == "ClusterRoleBinding":
                print("Create binding")
                binding_name = dep["metadata"]["name"]
                rbac_v1.create_cluster_role_binding(dep)
                print(f"Created binding '{binding_name}'")
        return RBACAuthorization(role_name, binding_name)


def configure_rbac_with_ap(rbac_v1: RbacAuthorizationV1Api) -> RBACAuthorization:
    """
    Create cluster and binding for AppProtect module.
    :param rbac_v1: RbacAuthorizationV1Api
    :return: RBACAuthorization
    """
    with open(f"{DEPLOYMENTS}/rbac/ap-rbac.yaml") as f:
        docs = yaml.safe_load_all(f)
        role_name = ""
        binding_name = ""
        for dep in docs:
            if dep["kind"] == "ClusterRole":
                print("Create cluster role for AppProtect")
                role_name = dep["metadata"]["name"]
                rbac_v1.create_cluster_role(dep)
                print(f"Created role '{role_name}'")
            elif dep["kind"] == "ClusterRoleBinding":
                print("Create binding for AppProtect")
                binding_name = dep["metadata"]["name"]
                rbac_v1.create_cluster_role_binding(dep)
                print(f"Created binding '{binding_name}'")
        return RBACAuthorization(role_name, binding_name)


def configure_rbac_with_dos(rbac_v1: RbacAuthorizationV1Api) -> RBACAuthorization:
    """
    Create cluster and binding for Dos module.
    :param rbac_v1: RbacAuthorizationV1Api
    :return: RBACAuthorization
    """
    with open(f"{DEPLOYMENTS}/rbac/apdos-rbac.yaml") as f:
        docs = yaml.safe_load_all(f)
        role_name = ""
        binding_name = ""
        for dep in docs:
            if dep["kind"] == "ClusterRole":
                print("Create cluster role for DOS")
                role_name = dep["metadata"]["name"]
                rbac_v1.create_cluster_role(dep)
                print(f"Created role '{role_name}'")
            elif dep["kind"] == "ClusterRoleBinding":
                print("Create binding for DOS")
                binding_name = dep["metadata"]["name"]
                rbac_v1.create_cluster_role_binding(dep)
                print(f"Created binding '{binding_name}'")
        return RBACAuthorization(role_name, binding_name)


def patch_rbac(rbac_v1: RbacAuthorizationV1Api, yaml_manifest) -> RBACAuthorization:
    """
    Patch a clusterrole and a binding.

    :param rbac_v1: RbacAuthorizationV1Api
    :param yaml_manifest: an absolute path to yaml manifest
    :return: RBACAuthorization
    """
    with open(yaml_manifest) as f:
        docs = yaml.safe_load_all(f)
        role_name = ""
        binding_name = ""
        for dep in docs:
            if dep["kind"] == "ClusterRole":
                print("Patch the cluster role")
                role_name = dep["metadata"]["name"]
                rbac_v1.patch_cluster_role(role_name, dep)
                print(f"Patched the role '{role_name}'")
            elif dep["kind"] == "ClusterRoleBinding":
                print("Patch the binding")
                binding_name = dep["metadata"]["name"]
                rbac_v1.patch_cluster_role_binding(binding_name, dep)
                print(f"Patched the binding '{binding_name}'")
        return RBACAuthorization(role_name, binding_name)


def cleanup_rbac(rbac_v1: RbacAuthorizationV1Api, rbac: RBACAuthorization) -> None:
    """
    Delete binding and cluster role.

    :param rbac_v1: RbacAuthorizationV1Api
    :param rbac: RBACAuthorization
    :return:
    """
    print("Delete binding and cluster role")
    rbac_v1.delete_cluster_role_binding(rbac.binding)
    rbac_v1.delete_cluster_role(rbac.role)


def create_deployment_from_yaml(apps_v1_api: AppsV1Api, namespace, yaml_manifest) -> str:
    """
    Create a deployment based on yaml file.

    :param apps_v1_api: AppsV1Api
    :param namespace: namespace name
    :param yaml_manifest: absolute path to file
    :return: str
    """
    print(f"Load {yaml_manifest}")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    return create_deployment(apps_v1_api, namespace, dep)


def patch_deployment_from_yaml(apps_v1_api: AppsV1Api, namespace, yaml_manifest) -> str:
    """
    Create a deployment based on yaml file.

    :param apps_v1_api: AppsV1Api
    :param namespace: namespace name
    :param yaml_manifest: absolute path to file
    :return: str
    """
    print(f"Load {yaml_manifest}")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    return patch_deployment(apps_v1_api, namespace, dep)


def patch_deployment(apps_v1_api: AppsV1Api, namespace, body) -> str:
    """
    Create a deployment based on a dict.

    :param apps_v1_api: AppsV1Api
    :param namespace: namespace name
    :param body: dict
    :return: str
    """
    print("Patch a deployment:")
    apps_v1_api.patch_namespaced_deployment(body["metadata"]["name"], namespace, body)
    print(f"Deployment patched with name '{body['metadata']['name']}'")
    return body["metadata"]["name"]


def create_deployment(apps_v1_api: AppsV1Api, namespace, body) -> str:
    """
    Create a deployment based on a dict.

    :param apps_v1_api: AppsV1Api
    :param namespace: namespace name
    :param body: dict
    :return: str
    """
    print("Create a deployment:")
    apps_v1_api.create_namespaced_deployment(namespace, body)
    print(f"Deployment created with name '{body['metadata']['name']}'")
    return body["metadata"]["name"]


def create_deployment_with_name(apps_v1_api: AppsV1Api, namespace, name) -> str:
    """
    Create a deployment with a specific name based on common yaml file.

    :param apps_v1_api: AppsV1Api
    :param namespace: namespace name
    :param name:
    :return: str
    """
    print(f"Create a Deployment with a specific name: {name}")
    with open(f"{TEST_DATA}/common/backend1.yaml") as f:
        dep = yaml.safe_load(f)
        dep["metadata"]["name"] = name
        dep["spec"]["selector"]["matchLabels"]["app"] = name
        dep["spec"]["template"]["metadata"]["labels"]["app"] = name
        dep["spec"]["template"]["spec"]["containers"][0]["name"] = name
        return create_deployment(apps_v1_api, namespace, dep)


def scale_deployment(v1: CoreV1Api, apps_v1_api: AppsV1Api, name, namespace, value) -> int:
    """
    Scale a deployment.

    :param apps_v1_api: AppsV1Api
    :param namespace: namespace name
    :param name: deployment name
    :param value: int
    :return: original: int the original amount of replicas
    """
    body = apps_v1_api.read_namespaced_deployment_scale(name, namespace)
    original = body.spec.replicas
    print(f"Original number of replicas is {original}")
    print(f"Scaling deployment '{name}' to {value} replica(s)")
    body.spec.replicas = value
    apps_v1_api.patch_namespaced_deployment_scale(name, namespace, body)
    if value != 0:
        now = time.time()
        wait_until_all_pods_are_ready(v1, namespace)
        later = time.time()
        print(f"All pods came up in {int(later - now)} seconds")

    elif value == 0:
        replica_num = (apps_v1_api.read_namespaced_deployment_scale(name, namespace)).spec.replicas
        while replica_num is not None:
            replica_num = (apps_v1_api.read_namespaced_deployment_scale(name, namespace)).spec.replicas
            time.sleep(1)
            print("Number of replicas is not 0, retrying...")

    else:
        pytest.fail("wrong argument")

    print(f"Scale a deployment '{name}': complete")
    return original


def create_daemon_set(apps_v1_api: AppsV1Api, namespace, body) -> str:
    """
    Create a daemon-set based on a dict.

    :param apps_v1_api: AppsV1Api
    :param namespace: namespace name
    :param body: dict
    :return: str
    """
    print("Create a daemon-set:")
    apps_v1_api.create_namespaced_daemon_set(namespace, body)
    print(f"Daemon-Set created with name '{body['metadata']['name']}'")
    return body["metadata"]["name"]


def create_stateful_set(apps_v1_api, namespace, body) -> str:
    """
    Create a stateful-set based on a dict.

    :param apps_v1_api: AppsV1Api
    :param namespace: namespace name
    :param body: dict
    :return: str
    """
    print("Create a statefulset:")
    apps_v1_api.create_namespaced_stateful_set(namespace, body)
    print(f"StatefulSet created with name '{body['metadata']['name']}'")
    return body["metadata"]["name"]


class PodNotReadyException(Exception):
    def __init__(self, message="After several seconds the pods aren't ContainerReady. Exiting!"):
        self.message = message
        super().__init__(self.message)


def wait_until_all_pods_are_ready(v1: CoreV1Api, namespace) -> None:
    """
    Wait for all the pods to be 'Ready'.

    :param v1: CoreV1Api
    :param namespace: namespace of a pod
    :return:
    """
    print("Start waiting for all pods in a namespace to be Ready")
    counter = 0
    while not are_all_pods_in_ready_state(v1, namespace) and counter < 200:
        # remove counter based condition from line #264 and #269 if --batch-start="True"
        print("There are pods that are not Ready. Wait for 1 sec...")
        wait_before_test()
        counter = counter + 1
    if counter >= 300:
        print("\n===================== IC Logs Start =====================")
        try:
            pod_name = get_pod_name_that_contains(kube_apis.v1, "nginx-ingress", "nginx-ingress")
            logs = kube_apis.v1.read_namespaced_pod_log(pod_name, "nginx-ingress")
            print(logs)
        except:
            print("Failed to load logs for nginx-ingress pod")
        print("\n===================== IC Logs End =====================")
        raise PodNotReadyException()
    print("All pods are Ready")


def get_pod_list(v1: CoreV1Api, namespace) -> []:
    """
    Get a list of pods in a namespace.

    :param v1: CoreV1Api
    :param namespace: namespace
    :return: []
    """
    return v1.list_namespaced_pod(namespace).items


def get_first_pod_name(v1: CoreV1Api, namespace) -> str:
    """
    Return 1st pod_name in a list of pods in a namespace.

    :param v1: CoreV1Api
    :param namespace:
    :return: str
    """
    resp = v1.list_namespaced_pod(namespace)
    return resp.items[0].metadata.name


def are_all_pods_in_ready_state(v1: CoreV1Api, namespace) -> bool:
    """
    Check if all the pods have Ready condition.

    :param v1: CoreV1Api
    :param namespace: namespace
    :return: bool
    """
    pods = v1.list_namespaced_pod(namespace)
    if not pods.items:
        return False
    pod_ready_amount = 0
    for pod in pods.items:
        print(f"Pod {pod.metadata.name} has image {pod.spec.containers[0].image}")
        if pod.status.conditions is None:
            return False
        for condition in pod.status.conditions:
            if condition.type == "Ready" and condition.status == "True":
                pod_ready_amount = pod_ready_amount + 1
                break
    return pod_ready_amount == len(pods.items)


def get_pods_amount(v1: CoreV1Api, namespace) -> int:
    """
    Get an amount of pods.

    :param v1: CoreV1Api
    :param namespace: namespace
    :return: int
    """
    pods = v1.list_namespaced_pod(namespace)
    return 0 if not pods.items else len(pods.items)


def get_pods_amount_with_name(v1: CoreV1Api, namespace, name) -> int:
    """
    Get an amount of pods.

    :param v1: CoreV1Api
    :param namespace: namespace
    :param name: name
    :return: int
    """
    pods = v1.list_namespaced_pod(namespace)
    count = 0
    if pods and pods.items:
        for item in pods.items:
            if name in item.metadata.name:
                count += 1
    return count


def get_pod_name_that_contains(v1: CoreV1Api, namespace, contains_string) -> str:
    """
    Get an amount of pods.

    :param v1: CoreV1Api
    :param namespace: namespace
    :param contains_string: string to search on
    :return: string
    """
    for item in v1.list_namespaced_pod(namespace).items:
        if contains_string in item.metadata.name:
            return item.metadata.name
    return ""


def create_service_from_yaml(v1: CoreV1Api, namespace, yaml_manifest) -> str:
    """
    Create a service based on yaml file.

    :param v1: CoreV1Api
    :param namespace: namespace name
    :param yaml_manifest: absolute path to file
    :return: str
    """
    print(f"Load {yaml_manifest}")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    return create_service(v1, namespace, dep)


def create_service(v1: CoreV1Api, namespace, body) -> str:
    """
    Create a service based on a dict.

    :param v1: CoreV1Api
    :param namespace: namespace
    :param body: a dict
    :return: str
    """
    print("Create a Service:")
    resp = v1.create_namespaced_service(namespace, body)
    print(f"Service created with name '{body['metadata']['name']}'")
    return resp.metadata.name


def create_service_with_name(v1: CoreV1Api, namespace, name, port=80, targetPort=8080) -> str:
    """
    Create a service with a specific name based on a common yaml manifest.

    :param v1: CoreV1Api
    :param namespace: namespace name
    :param name: name
    :return: str
    """
    print(f"Create a Service with a specific name: {name}")
    with open(f"{TEST_DATA}/common/backend1-svc.yaml") as f:
        dep = yaml.safe_load(f)
        dep["metadata"]["name"] = name
        dep["spec"]["selector"]["app"] = name.replace("-svc", "")
        dep["spec"]["ports"][0]["port"] = port
        dep["spec"]["ports"][0]["targetPort"] = targetPort
        return create_service(v1, namespace, dep)


def create_secure_app_deployment_with_name(apps_v1_api: AppsV1Api, namespace, name) -> str:
    """
    Deploys app in /common/app/secure in the configured name and namespace

    :param v1: CoreV1Api
    :param namespace: namespace name
    :param name: name
    :return: str
    """
    print(f"Create a Service with a specific name: {name}")
    with open(f"{TEST_DATA}/common/app/secure/deployment/secure-app.yaml") as f:
        dep = yaml.safe_load(f)
        dep["metadata"]["name"] = name
        dep["spec"]["selector"]["matchLabels"]["app"] = name
        dep["spec"]["template"]["metadata"]["labels"]["app"] = name
        dep["spec"]["template"]["spec"]["containers"][0]["name"] = name
        return create_deployment(apps_v1_api, namespace, dep)


def get_service_node_ports(v1: CoreV1Api, name, namespace) -> (int, int, int, int, int, int, int):
    """
    Get service allocated node_ports.

    :param v1: CoreV1Api
    :param name:
    :param namespace:
    :return: (plain_port, ssl_port, api_port, exporter_port)
    """
    resp = v1.read_namespaced_service(name, namespace)
    if len(resp.spec.ports) == 7:
        print("An unexpected amount of ports in a service. Check the configuration")

    print(f"Service with an HTTP port: {resp.spec.ports[0].node_port}")
    print(f"Service with an HTTPS port: {resp.spec.ports[1].node_port}")
    print(f"Service with an API port: {resp.spec.ports[2].node_port}")
    print(f"Service with an Exporter port: {resp.spec.ports[3].node_port}")
    print(f"Service with an TPC server port: {resp.spec.ports[4].node_port}")
    print(f"Service with an UDP server port: {resp.spec.ports[5].node_port}")
    print(f"Service with an Service Insight port: {resp.spec.ports[6].node_port}")
    print(f"Service with an custom SSL port: {resp.spec.ports[7].node_port}")
    print(f"Service with an custom http listener port: {resp.spec.ports[8].node_port}")
    print(f"Service with an custom https listener port: {resp.spec.ports[9].node_port}")
    return (
        resp.spec.ports[0].node_port,
        resp.spec.ports[1].node_port,
        resp.spec.ports[2].node_port,
        resp.spec.ports[3].node_port,
        resp.spec.ports[4].node_port,
        resp.spec.ports[5].node_port,
        resp.spec.ports[6].node_port,
        resp.spec.ports[7].node_port,
        resp.spec.ports[8].node_port,
        resp.spec.ports[9].node_port,
    )


def wait_for_public_ip(v1: CoreV1Api, namespace: str) -> str:
    """
    Wait for LoadBalancer to get the public ip.

    :param v1: CoreV1Api
    :param namespace: namespace
    :return: str
    """
    resp = v1.list_namespaced_service(namespace)
    counter = 0
    svc_item = first(x for x in resp.items if x.metadata.name == "nginx-ingress")
    while str(svc_item.status.load_balancer.ingress) == "None" and counter < 20:
        time.sleep(5)
        resp = v1.list_namespaced_service(namespace)
        svc_item = first(x for x in resp.items if x.metadata.name == "nginx-ingress")
        counter = counter + 1
    if counter == 20:
        pytest.fail("After 100 seconds the LB still doesn't have a Public IP. Exiting...")
    print(f"Public IP ='{svc_item.status.load_balancer.ingress[0].ip}'")
    return str(svc_item.status.load_balancer.ingress[0].ip)


def create_secret_from_yaml(v1: CoreV1Api, namespace, yaml_manifest) -> str:
    """
    Create a secret based on yaml file.

    :param v1: CoreV1Api
    :param namespace: namespace name
    :param yaml_manifest: an absolute path to file
    :return: str
    """
    print(f"Load {yaml_manifest}")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    return create_secret(v1, namespace, dep)


def create_secret(v1: CoreV1Api, namespace, body) -> str:
    """
    Create a secret based on a dict.

    :param v1: CoreV1Api
    :param namespace: namespace
    :param body: a dict
    :return: str
    """
    print("Create a secret:")
    v1.create_namespaced_secret(namespace, body)
    print(f"Secret created: {body['metadata']['name']}")
    return body["metadata"]["name"]


def create_license(v1: CoreV1Api, namespace, jwt, license_token_name="license-token") -> str:
    sec = V1Secret()
    sec.type = "nginx.com/license"
    sec.metadata = V1ObjectMeta(name=license_token_name)
    sec.data = {"license.jwt": base64.b64encode(jwt.encode("ascii")).decode()}
    v1.create_namespaced_secret(namespace=namespace, body=sec)
    return license_token_name


def replace_secret(v1: CoreV1Api, name, namespace, yaml_manifest) -> str:
    """
    Replace a secret based on yaml file.

    :param v1: CoreV1Api
    :param name: secret name
    :param namespace: namespace name
    :param yaml_manifest: an absolute path to file
    :return: str
    """
    print(f"Replace a secret: '{name}'' in a namespace: '{namespace}'")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
        v1.replace_namespaced_secret(name, namespace, dep)
        print("Secret replaced")
    return name


def is_secret_present(v1: CoreV1Api, name, namespace) -> bool:
    """
    Check if a namespace has a secret.

    :param v1: CoreV1Api
    :param name:
    :param namespace:
    :return: bool
    """
    try:
        v1.read_namespaced_secret(name, namespace)
    except ApiException as ex:
        if ex.status == 404:
            print(f"No secret '{name}' found.")
            return False
    return True


def delete_secret(v1: CoreV1Api, name, namespace) -> None:
    """
    Delete a secret.

    :param v1: CoreV1Api
    :param name: secret name
    :param namespace: namespace name
    :return:
    """
    delete_options = {
        "grace_period_seconds": 0,
        "propagation_policy": "Foreground",
    }
    print(f"Delete a secret: {name}")
    v1.delete_namespaced_secret(name, namespace, **delete_options)
    ensure_item_removal(v1.read_namespaced_secret, name, namespace)
    print(f"Secret was removed with name '{name}'")


def ensure_item_removal(get_item, *args, **kwargs) -> None:
    """
    Wait for item to be removed.

    :param get_item: a call to get an item
    :param args: *args
    :param kwargs: **kwargs
    :return:
    """
    try:
        counter = 0
        while counter < 120:
            time.sleep(1)
            get_item(*args, **kwargs)
            counter = counter + 1
        if counter >= 120:
            # Due to k8s issue with namespaces, they sometimes get stuck in Terminating state, skip such cases
            if "_namespace " in str(get_item):
                print(f"Failed to remove namespace '{args}' after 120 seconds, skip removal. Remove manually.")
            else:
                pytest.fail("Failed to remove the item after 120 seconds")
    except ApiException as ex:
        if ex.status == 404:
            print("Item was removed")


def create_ingress_from_yaml(networking_v1: NetworkingV1Api, namespace, yaml_manifest) -> str:
    """
    Create an ingress based on yaml file.

    :param networking_v1: NetworkingV1Api
    :param namespace: namespace name
    :param yaml_manifest: an absolute path to file
    :return: str
    """
    print(f"Load {yaml_manifest}")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
        return create_ingress(networking_v1, namespace, dep)


def create_ingress(networking_v1: NetworkingV1Api, namespace, body) -> str:
    """
    Create an ingress based on a dict.

    :param networking_v1: NetworkingV1Api
    :param namespace: namespace name
    :param body: a dict
    :return: str
    """
    print("Create an ingress:")
    networking_v1.create_namespaced_ingress(namespace, body)
    print(f"Ingress created with name '{body['metadata']['name']}'")
    return body["metadata"]["name"]


def delete_ingress(networking_v1: NetworkingV1Api, name, namespace) -> None:
    """
    Delete an ingress.

    :param networking_v1: NetworkingV1Api
    :param namespace: namespace
    :param name:
    :return:
    """
    print(f"Delete an ingress: {name}")
    networking_v1.delete_namespaced_ingress(name, namespace)
    ensure_item_removal(networking_v1.read_namespaced_ingress, name, namespace)
    print(f"Ingress was removed with name '{name}'")


def generate_ingresses_with_annotation(yaml_manifest, annotations) -> []:
    """
    Generate an Ingress item with an annotation.

    :param yaml_manifest: an absolute path to a file
    :param annotations:
    :return: []
    """
    res = []
    with open(yaml_manifest) as f:
        docs = yaml.safe_load_all(f)
        for doc in docs:
            if doc["kind"] == "Ingress":
                doc["metadata"]["annotations"].update(annotations)
                res.append(doc)
    return res


def replace_ingress(networking_v1: NetworkingV1Api, name, namespace, body) -> str:
    """
    Replace an Ingress based on a dict.

    :param networking_v1: NetworkingV1Api
    :param name:
    :param namespace: namespace
    :param body: dict
    :return: str
    """
    print(f"Replace a Ingress: {name}")
    resp = networking_v1.replace_namespaced_ingress(name, namespace, body)
    print(f"Ingress replaced with name '{name}'")
    return resp.metadata.name


def create_namespace_from_yaml(v1: CoreV1Api, yaml_manifest) -> str:
    """
    Create a namespace based on yaml file.

    :param v1: CoreV1Api
    :param yaml_manifest: an absolute path to file
    :return: str
    """
    print(f"Load {yaml_manifest}")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
        create_namespace(v1, dep)
        return dep["metadata"]["name"]


def create_namespace(v1: CoreV1Api, body) -> str:
    """
    Create an ingress based on a dict.

    :param v1: CoreV1Api
    :param body: a dict
    :return: str
    """
    print("Create a namespace:")
    v1.create_namespace(body)
    print(f"Namespace created with name '{body['metadata']['name']}'")
    return body["metadata"]["name"]


def create_namespace_with_name_from_yaml(v1: CoreV1Api, name, yaml_manifest) -> str:
    """
    Create a namespace with a specific name based on a yaml manifest.

    :param v1: CoreV1Api
    :param name: name
    :param yaml_manifest: an absolute path to file
    :return: str
    """
    print(f"Create a namespace with specific name: {name}")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
        dep["metadata"]["name"] = name
        v1.create_namespace(dep)
        print(f"Namespace created with name '{str(dep['metadata']['name'])}'")
        return dep["metadata"]["name"]


def patch_namespace_with_label(v1: CoreV1Api, name, label, yaml_manifest) -> str:
    """
    Update a namespace with a specific label based on a yaml manifest.

    :param v1: CoreV1Api
    :param name: name
    :param label: the name of the label
    :param yaml_manifest: an absolute path to file
    :return: str
    """
    print(f"Update namespace {name} with label app={label}")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
        dep["metadata"]["labels"]["app"] = label
        v1.patch_namespace(name, dep)
        print(f"Namespace {name} updated with label: {label}")


def create_service_account(v1: CoreV1Api, namespace, body) -> None:
    """
    Create a ServiceAccount based on a dict.

    :param v1: CoreV1Api
    :param namespace: namespace name
    :param body: a dict
    :return:
    """
    print("Create a SA:")
    v1.create_namespaced_service_account(namespace, body)
    print(f"Service account created with name '{body['metadata']['name']}'")


def create_configmap_from_yaml(v1: CoreV1Api, namespace, yaml_manifest) -> str:
    """
    Create a config-map based on yaml file.

    :param v1: CoreV1Api
    :param namespace: namespace name
    :param yaml_manifest: an absolute path to file
    :return: str
    """
    print(f"Load {yaml_manifest}")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    return create_configmap(v1, namespace, dep)


def create_configmap(v1: CoreV1Api, namespace, body) -> str:
    """
    Create a config-map based on a dict.

    :param v1: CoreV1Api
    :param namespace: namespace name
    :param body: a dict
    :return: str
    """
    print("Create a configMap:")
    v1.create_namespaced_config_map(namespace, body)
    print(f"Config map created with name '{body['metadata']['name']}'")
    return body["metadata"]["name"]


def replace_configmap_from_yaml(v1: CoreV1Api, name, namespace, yaml_manifest) -> None:
    """
    Replace a config-map based on a yaml file.

    :param v1: CoreV1Api
    :param name:
    :param namespace: namespace name
    :param yaml_manifest: an absolute path to file
    :return:
    """
    print(f"Replace a configMap: '{name}'")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
        v1.replace_namespaced_config_map(name, namespace, dep)
        print("ConfigMap replaced")


def replace_configmap(v1: CoreV1Api, name, namespace, body) -> None:
    """
    Replace a config-map based on a dict.

    :param v1: CoreV1Api
    :param name:
    :param namespace:
    :param body: a dict
    :return:
    """
    print(f"Replace a configMap: '{name}'")
    v1.replace_namespaced_config_map(name, namespace, body)
    print("ConfigMap replaced")


def delete_configmap(v1: CoreV1Api, name, namespace) -> None:
    """
    Delete a ConfigMap.

    :param v1: CoreV1Api
    :param name: ConfigMap name
    :param namespace: namespace name
    :return:
    """
    delete_options = {
        "grace_period_seconds": 0,
        "propagation_policy": "Foreground",
    }
    print(f"Delete a ConfigMap: {name}")
    v1.delete_namespaced_config_map(name, namespace, **delete_options)
    ensure_item_removal(v1.read_namespaced_config_map, name, namespace)
    print(f"ConfigMap was removed with name '{name}'")


def delete_namespace(v1: CoreV1Api, namespace) -> None:
    """
    Delete a namespace.

    :param v1: CoreV1Api
    :param namespace: namespace name
    :return:
    """
    delete_options = {
        "grace_period_seconds": 0,
        "propagation_policy": "Foreground",
    }
    print(f"Delete a namespace: {namespace}")
    v1.delete_namespace(namespace, **delete_options)
    ensure_item_removal(v1.read_namespace, namespace)
    print(f"Namespace was removed with name '{namespace}'")


def delete_testing_namespaces(v1: CoreV1Api) -> []:
    """
    List and remove all the testing namespaces.

    Testing namespaces are the ones starting with "test-namespace-"

    :param v1: CoreV1Api
    :return:
    """
    namespaces_list = v1.list_namespace()
    for namespace in list(filter(lambda ns: ns.metadata.name.startswith("test-namespace-"), namespaces_list.items)):
        delete_namespace(v1, namespace.metadata.name)


def get_file_contents(v1: CoreV1Api, file_path, pod_name, pod_namespace, print_log=True) -> str:
    """
    Execute 'cat file_path' command in a pod.

    :param v1: CoreV1Api
    :param pod_name: pod name
    :param pod_namespace: pod namespace
    :param file_path: an absolute path to a file in the pod
    :param print_log: bool to decide if print log or not
    :return: str
    """
    command = ["cat", file_path]
    retries = 0
    while retries <= 3:
        wait_before_test()
        try:
            resp = stream(
                v1.connect_get_namespaced_pod_exec,
                pod_name,
                pod_namespace,
                command=command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
            )
            break
        except Exception as e:
            print(f"Error: {e}")
            retries += 1
            if retries == 3:
                raise e
    result_conf = str(resp)
    if print_log:
        print("\nFile contents:\n" + result_conf)
    return result_conf


def nginx_reload(v1: CoreV1Api, pod_name, pod_namespace) -> str:
    """
    Execute 'nginx -s reload' command in a pod.

    :param v1: CoreV1Api
    :param pod_name: pod name
    :param pod_namespace: pod namespace
    :return: str
    """
    command = ["nginx", "-s", "reload"]
    resp = stream(
        v1.connect_get_namespaced_pod_exec,
        pod_name,
        pod_namespace,
        command=command,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
    )
    result_conf = str(resp)

    return result_conf


def clear_file_contents(v1: CoreV1Api, file_path, pod_name, pod_namespace):
    """
    Execute 'cat /dev/null > file_path' command in a pod.

    :param v1: CoreV1Api
    :param pod_name: pod name
    :param pod_namespace: pod namespace
    :param file_path: an absolute path to a file in the pod
    """
    command = ["cat /dev/null > ", file_path]
    resp = stream(
        v1.connect_get_namespaced_pod_exec,
        pod_name,
        pod_namespace,
        command=command,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
    )


def get_nginx_template_conf(v1: CoreV1Api, ingress_namespace, ic_pod_name=None, print_log=True) -> str:
    """
    Get contents of /etc/nginx/nginx.conf in the pod
    :param v1: CoreV1Api
    :param ingress_namespace: str
    :param ic_pod_name: str
    :return: str
    """
    if ic_pod_name is None:
        ic_pod_name = get_first_pod_name(v1, ingress_namespace)
    file_path = "/etc/nginx/nginx.conf"
    return get_file_contents(v1, file_path, ic_pod_name, ingress_namespace, print_log)


def get_ingress_nginx_template_conf(v1: CoreV1Api, ingress_namespace, ingress_name, pod_name, pod_namespace) -> str:
    """
    Get contents of /etc/nginx/conf.d/{namespace}-{ingress_name}.conf in the pod.

    :param v1: CoreV1Api
    :param ingress_namespace:
    :param ingress_name:
    :param pod_name:
    :param pod_namespace:
    :return: str
    """
    file_path = f"/etc/nginx/conf.d/{ingress_namespace}-{ingress_name}.conf"
    return get_file_contents(v1, file_path, pod_name, pod_namespace)


def get_vs_nginx_template_conf(v1: CoreV1Api, vs_namespace, vs_name, pod_name, pod_namespace) -> str:
    """
    Get contents of /etc/nginx/conf.d/vs_{namespace}_{ingress_name}.conf in the pod.

    :param v1: CoreV1Api
    :param ingress_namespace:
    :param ingress_name:
    :param pod_name:
    :param pod_namespace:
    :return: str
    """
    file_path = f"/etc/nginx/conf.d/vs_{vs_namespace}_{vs_name}.conf"
    return get_file_contents(v1, file_path, pod_name, pod_namespace)


def get_ts_nginx_template_conf(v1: CoreV1Api, resource_namespace, resource_name, pod_name, pod_namespace) -> str:
    """
    Get contents of /etc/nginx/stream-conf.d/ts_{namespace}-{resource_name}.conf in the pod.

    :param v1: CoreV1Api
    :param resource_namespace:
    :param resource_name:
    :param pod_name:
    :param pod_namespace:
    :return: str
    """
    file_path = f"/etc/nginx/stream-conf.d/ts_{resource_namespace}_{resource_name}.conf"
    return get_file_contents(v1, file_path, pod_name, pod_namespace)


def extract_block(nginx_config, block_name):
    """
    Extract a block of configuration from the nginx config file.

    :param nginx_config: The nginx config file content as a string.
    :param block_name: The name of the block to extract.
    :return: The extracted block as a string.
    """
    start = nginx_config.find(block_name)
    end = nginx_config.find("}", start) + 1
    return nginx_config[start:end]


def create_example_app(kube_apis, app_type, namespace) -> None:
    """
    Create a backend application.

    An application consists of 3 backend services.

    :param kube_apis: client apis
    :param app_type: type of the application (simple|split)
    :param namespace: namespace name
    :return:
    """
    create_items_from_yaml(kube_apis, f"{TEST_DATA}/common/app/{app_type}/app.yaml", namespace)


def delete_common_app(kube_apis, app_type, namespace) -> None:
    """
    Delete a common simple application.

    :param kube_apis:
    :param app_type:
    :param namespace: namespace name
    :return:
    """
    delete_items_from_yaml(kube_apis, f"{TEST_DATA}/common/app/{app_type}/app.yaml", namespace)


def delete_service(v1: CoreV1Api, name, namespace) -> None:
    """
    Delete a service.

    :param v1: CoreV1Api
    :param name:
    :param namespace:
    :return:
    """
    print(f"Delete a service: {name}")
    v1.delete_namespaced_service(name, namespace)
    ensure_item_removal(v1.read_namespaced_service_status, name, namespace)
    print(f"Service was removed with name '{name}'")


def delete_deployment(apps_v1_api: AppsV1Api, name, namespace) -> None:
    """
    Delete a deployment.

    :param apps_v1_api: AppsV1Api
    :param name:
    :param namespace:
    :return:
    """
    delete_options = {
        "grace_period_seconds": 0,
        "propagation_policy": "Foreground",
    }
    print(f"Delete a deployment: {name}")
    apps_v1_api.delete_namespaced_deployment(name, namespace, **delete_options)
    ensure_item_removal(apps_v1_api.read_namespaced_deployment_status, name, namespace)
    print(f"Deployment was removed with name '{name}'")


def delete_daemon_set(apps_v1_api: AppsV1Api, name, namespace) -> None:
    """
    Delete a daemon-set.

    :param apps_v1_api: AppsV1Api
    :param name:
    :param namespace:
    :return:
    """
    delete_options = {
        "grace_period_seconds": 0,
        "propagation_policy": "Foreground",
    }
    print(f"Delete a daemon-set: {name}")
    apps_v1_api.delete_namespaced_daemon_set(name, namespace, **delete_options)
    ensure_item_removal(apps_v1_api.read_namespaced_daemon_set_status, name, namespace)
    print(f"Daemon-set was removed with name '{name}'")


def delete_stateful_set(apps_v1_api: AppsV1Api, name, namespace) -> None:
    """
    Delete a stateful-set.

    :param apps_v1_api: AppsV1Api
    :param name:
    :param namespace:
    :return:
    """
    delete_options = {
        "grace_period_seconds": 0,
        "propagation_policy": "Foreground",
    }
    print(f"Delete a statefulset: {name}")
    apps_v1_api.delete_namespaced_stateful_set(name, namespace, **delete_options)
    ensure_item_removal(apps_v1_api.read_namespaced_stateful_set_status, name, namespace)
    print(f"StatefulSet was removed with name '{name}'")


def wait_before_test(delay=RECONFIGURATION_DELAY) -> None:
    """
    Wait for a time in seconds.

    :param delay: a delay in seconds
    :return:
    """
    time.sleep(delay)


def wait_for_event_increment(kube_apis, namespace, event_count, offset) -> bool:
    """
    Wait for event count to increase.

    :param kube_apis: Kubernetes API
    :param namespace: event namespace
    :param event_count: Current even count
    :param offset: Number of events generated by last operation
    :return:
    """
    print(f"Current count: {event_count}")
    updated_event_count = len(get_events(kube_apis.v1, namespace))
    retry = 0
    while updated_event_count != (event_count + offset) and retry < 30:
        time.sleep(1)
        retry += 1
        updated_event_count = len(get_events(kube_apis.v1, namespace))
        print(f"Updated count: {updated_event_count}")
        print(f"Event not registered, Retry #{retry}..")
    if updated_event_count == (event_count + offset):
        return True
    else:
        print(f"Event was not registered after {retry} retries, exiting...")
        return False


def create_ingress_controller(v1: CoreV1Api, apps_v1_api: AppsV1Api, cli_arguments, namespace, args=None) -> str:
    """
    Create an Ingress Controller according to the params.

    :param v1: CoreV1Api
    :param apps_v1_api: AppsV1Api
    :param cli_arguments: context name as in kubeconfig
    :param namespace: namespace name
    :param args: a list of any extra cli arguments to start IC with
    :return: str
    """
    print(f"Create an Ingress Controller as {cli_arguments['ic-type']}")
    yaml_manifest = f"{DEPLOYMENTS}/{cli_arguments['deployment-type']}/{cli_arguments['ic-type']}.yaml"
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    dep["spec"]["replicas"] = int(cli_arguments["replicas"])
    dep["spec"]["template"]["spec"]["containers"][0]["image"] = cli_arguments["image"]
    dep["spec"]["template"]["spec"]["containers"][0]["imagePullPolicy"] = cli_arguments["image-pull-policy"]
    dep["spec"]["template"]["spec"]["containers"][0]["args"].extend(
        [
            f"-default-server-tls-secret=$(POD_NAMESPACE)/default-server-secret",
            f"-enable-telemetry-reporting=false",
        ]
    )
    if args is not None:
        dep["spec"]["template"]["spec"]["containers"][0]["args"].extend(args)
    if cli_arguments["deployment-type"] == "deployment":
        name = create_deployment(apps_v1_api, namespace, dep)
    elif cli_arguments["deployment-type"] == "daemon-set":
        name = create_daemon_set(apps_v1_api, namespace, dep)
    elif cli_arguments["deployment-type"] == "stateful-set":
        name = create_stateful_set(apps_v1_api, namespace, dep)
    else:
        raise ValueError(f"Unknown deployment-type: {cli_arguments['deployment-type']}")
    before = time.time()
    wait_until_all_pods_are_ready(v1, namespace)
    after = time.time()
    print(f"All pods came up in {int(after - before)} seconds")
    print(f"Ingress Controller was created with name '{name}'")
    return name


def create_ingress_controller_wafv5(
    v1: CoreV1Api, apps_v1_api: AppsV1Api, cli_arguments, namespace, reg_secret, args=None, rorfs=False
) -> str:
    """
    Create an Ingress Controller according to the params.

    :param v1: CoreV1Api
    :param apps_v1_api: AppsV1Api
    :param cli_arguments: context name as in kubeconfig
    :param namespace: namespace name
    :param args: a list of any extra cli arguments to start IC with
    :return: str
    """
    print(f"Create an Ingress Controller as {cli_arguments['ic-type']}")
    yaml_manifest = f"{DEPLOYMENTS}/{cli_arguments['deployment-type']}/{cli_arguments['ic-type']}.yaml"
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    dep["spec"]["replicas"] = int(cli_arguments["replicas"])
    dep["spec"]["template"]["spec"]["containers"][0]["image"] = cli_arguments["image"]
    dep["spec"]["template"]["spec"]["containers"][0]["imagePullPolicy"] = cli_arguments["image-pull-policy"]
    if "readOnlyRootFilesystem" not in dep["spec"]["template"]["spec"]["containers"][0]["securityContext"]:
        dep["spec"]["template"]["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] = rorfs

    template_spec = dep["spec"]["template"]["spec"]
    if "imagePullSecrets" not in template_spec:
        template_spec["imagePullSecrets"] = []

    template_spec["imagePullSecrets"].append({"name": f"{reg_secret}"})
    if "volumes" not in template_spec:
        template_spec["volumes"] = []

    if rorfs and "initContainers" not in template_spec:
        template_spec["initContainers"] = []
        template_spec["initContainers"].extend(
            [
                {
                    "name": "init-nginx-ingress",
                    "image": cli_arguments["image"],
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["cp", "-vdR", "/etc/nginx/.", "/mnt/etc"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "runAsUser": 101,  # nginx
                        "runAsNonRoot": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "volumeMounts": [{"mountPath": "/mnt/etc", "name": "nginx-etc"}],
                }
            ]
        )

    if rorfs:
        template_spec["volumes"].extend(
            [
                {
                    "name": "app-protect-bd-config",
                    "emptyDir": {},
                },
                {
                    "name": "app-protect-config",
                    "emptyDir": {},
                },
                {
                    "name": "app-protect-bundles",
                    "emptyDir": {},
                },
                {"name": "nginx-etc", "emptyDir": {}},
                {"name": "nginx-log", "emptyDir": {}},
                {"name": "nginx-cache", "emptyDir": {}},
                {"name": "nginx-lib", "emptyDir": {}},
                {"name": "nginx-lib-state", "emptyDir": {}},
            ]
        )
    else:
        template_spec["volumes"].extend(
            [
                {
                    "name": "app-protect-bd-config",
                    "emptyDir": {},
                },
                {
                    "name": "app-protect-config",
                    "emptyDir": {},
                },
                {
                    "name": "app-protect-bundles",
                    "emptyDir": {},
                },
            ]
        )

    container = dep["spec"]["template"]["spec"]["containers"][0]
    if "volumeMounts" not in container:
        container["volumeMounts"] = []

    if rorfs:
        container["volumeMounts"].extend(
            [
                {
                    "name": "app-protect-bd-config",
                    "mountPath": "/opt/app_protect/bd_config",
                },
                {
                    "name": "app-protect-config",
                    "mountPath": "/opt/app_protect/config",
                },
                {
                    "name": "app-protect-bundles",
                    "mountPath": "/etc/app_protect/bundles",
                },
                {"name": "nginx-etc", "mountPath": "/etc/nginx"},
                {"name": "nginx-log", "mountPath": "/var/log/nginx"},
                {"name": "nginx-cache", "mountPath": "/var/cache/nginx"},
                {"name": "nginx-lib", "mountPath": "/var/lib/nginx"},
                {"name": "nginx-lib-state", "mountPath": "/var/lib/nginx/state"},
            ]
        )
    else:
        container["volumeMounts"].extend(
            [
                {
                    "name": "app-protect-bd-config",
                    "mountPath": "/opt/app_protect/bd_config",
                },
                {
                    "name": "app-protect-config",
                    "mountPath": "/opt/app_protect/config",
                },
                {
                    "name": "app-protect-bundles",
                    "mountPath": "/etc/app_protect/bundles",
                },
            ]
        )

    dep["spec"]["template"]["spec"]["containers"][0]["args"].extend(
        [
            f"-default-server-tls-secret=$(POD_NAMESPACE)/default-server-secret",
            f"-enable-telemetry-reporting=false",
        ]
    )

    waf_cfg_mgr = {
        "name": "waf-config-mgr",
        "image": f"{NGX_REG}/nap/waf-config-mgr:{WAF_V5_VERSION}",
        "imagePullPolicy": "IfNotPresent",
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["all"]},
            "readOnlyRootFilesystem": rorfs,
        },
        "volumeMounts": [
            {
                "name": "app-protect-bd-config",
                "mountPath": "/opt/app_protect/bd_config",
            },
            {
                "name": "app-protect-config",
                "mountPath": "/opt/app_protect/config",
            },
            {
                "name": "app-protect-bundles",
                "mountPath": "/etc/app_protect/bundles",
            },
        ],
    }
    waf_enforcer = {
        "name": "waf-enforcer",
        "image": f"{NGX_REG}/nap/waf-enforcer:{WAF_V5_VERSION}",
        "imagePullPolicy": "IfNotPresent",
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["all"]},
            "readOnlyRootFilesystem": rorfs,
        },
        "env": [
            {"name": "ENFORCER_PORT", "value": "50000"},
            {"name": "ENFORCER_CONFIG_TIMEOUT", "value": "0"},
        ],
        "volumeMounts": [
            {
                "name": "app-protect-bd-config",
                "mountPath": "/opt/app_protect/bd_config",
            }
        ],
    }

    dep["spec"]["template"]["spec"]["containers"].append(waf_cfg_mgr)
    dep["spec"]["template"]["spec"]["containers"].append(waf_enforcer)

    if args is not None:
        dep["spec"]["template"]["spec"]["containers"][0]["args"].extend(args)
    if cli_arguments["deployment-type"] == "deployment":
        name = create_deployment(apps_v1_api, namespace, dep)
    elif cli_arguments["deployment-type"] == "daemon-set":
        name = create_daemon_set(apps_v1_api, namespace, dep)
    elif cli_arguments["deployment-type"] == "stateful-set":
        name = create_stateful_set(apps_v1_api, namespace, dep)
    else:
        raise ValueError(f"Unknown deployment-type: {cli_arguments['deployment-type']}")
    before = time.time()
    wait_until_all_pods_are_ready(v1, namespace)
    after = time.time()
    print(f"All pods came up in {int(after - before)} seconds")
    print(f"Ingress Controller was created with name '{name}'")
    return name


def delete_ingress_controller(apps_v1_api: AppsV1Api, name, dep_type, namespace) -> None:
    """
    Delete IC according to its type.

    :param apps_v1_api: NetworkingV1Api
    :param name: name
    :param dep_type: IC deployment type 'deployment' or 'daemon-set'
    :param namespace: namespace name
    :return:
    """
    if dep_type == "deployment":
        delete_deployment(apps_v1_api, name, namespace)
    elif dep_type == "daemon-set":
        delete_daemon_set(apps_v1_api, name, namespace)
    elif dep_type == "stateful-set":
        delete_stateful_set(apps_v1_api, name, namespace)
    else:
        raise ValueError(f"Unknown deployment-type: {dep_type}")


def create_dos_arbitrator(
    v1: CoreV1Api, apps_v1_api: AppsV1Api, namespace, deployment_yaml_manifest, svc_yaml_manifest
) -> str:
    """
    Create dos arbitrator according to the params.

    :param v1: CoreV1Api
    :param apps_v1_api: AppsV1Api
    :param namespace: namespace name
    :param deployment_yaml_manifest:  arbitrator deployment yaml file
    :param svc_yaml_manifest: arbitrator svc yaml file
    :return: str
    """

    with open(deployment_yaml_manifest) as f:
        dep = yaml.safe_load(f)

    name = create_deployment(apps_v1_api, namespace, dep)

    before = time.time()
    wait_until_all_pods_are_ready(v1, namespace)
    after = time.time()
    print(f"All pods came up in {int(after - before)} seconds")
    print(f"Dos arbitrator was created with name '{name}'")

    print("create dos svc")
    svc_name = create_service_from_yaml(
        v1,
        namespace,
        svc_yaml_manifest,
    )
    print(f"Dos arbitrator svc was created with name '{svc_name}'")
    return name


def delete_dos_arbitrator(v1: CoreV1Api, apps_v1_api: AppsV1Api, name, namespace) -> None:
    """
    Delete dos arbitrator.

    :param v1: CoreV1Api
    :param apps_v1_api: AppsV1Api
    :param name: name
    :param namespace: namespace name
    :return:
    """
    delete_deployment(apps_v1_api, name, namespace)
    delete_service(v1, "svc-appprotect-dos-arb", namespace)


def create_ns_and_sa_from_yaml(v1: CoreV1Api, yaml_manifest) -> str:
    """
    Create a namespace and a service account in that namespace.

    :param v1:
    :param yaml_manifest: an absolute path to a file
    :return: str
    """
    print("Load yaml:")
    res = {}
    with open(yaml_manifest) as f:
        docs = yaml.safe_load_all(f)
        for doc in docs:
            if doc["kind"] == "Namespace":
                res["namespace"] = create_namespace(v1, doc)
            elif doc["kind"] == "ServiceAccount":
                assert res["namespace"] is not None, "Ensure 'Namespace' is above 'SA' in the yaml manifest"
                create_service_account(v1, res["namespace"], doc)
    return res["namespace"]


def create_items_from_yaml(kube_apis, yaml_manifest, namespace) -> {}:
    """
    Apply yaml manifest with multiple items.

    :param kube_apis: KubeApis
    :param yaml_manifest: an absolute path to a file
    :param namespace:
    :return:
    """
    res = {}
    print("Load yaml:")
    with open(yaml_manifest) as f:
        docs = yaml.safe_load_all(f)
        for doc in docs:
            if doc:
                if doc["kind"] == "Secret":
                    res["Secret"] = create_secret(kube_apis.v1, namespace, doc)
                elif doc["kind"] == "ConfigMap":
                    res["ConfigMap"] = create_configmap(kube_apis.v1, namespace, doc)
                elif doc["kind"] == "Ingress":
                    res["Ingress"] = create_ingress(kube_apis.networking_v1, namespace, doc)
                elif doc["kind"] == "Service":
                    res["Service"] = create_service(kube_apis.v1, namespace, doc)
                elif doc["kind"] == "Deployment":
                    res["Deployment"] = create_deployment(kube_apis.apps_v1_api, namespace, doc)
                elif doc["kind"] == "DaemonSet":
                    res["DaemonSet"] = create_daemon_set(kube_apis.apps_v1_api, namespace, doc)
                elif doc["kind"] == "StatefulSet":
                    res["StatefulSet"] = create_stateful_set(kube_apis.apps_v1_api, namespace, doc)
                elif doc["kind"] == "Namespace":
                    res["Namespace"] = create_namespace(kube_apis.v1, doc)

    return res


def create_ingress_with_ap_annotations(
    kube_apis, yaml_manifest, namespace, policy_name, ap_pol_st, ap_log_st, syslog_ep
) -> None:
    """
    Create an ingress with AppProtect annotations
    :param kube_apis: KubeApis
    :param yaml_manifest: an absolute path to ingress yaml
    :param namespace: namespace
    :param policy_name: AppProtect policy
    :param ap_log_st: True/False for enabling/disabling AppProtect security logging
    :param ap_pol_st: True/False for enabling/disabling AppProtect module for particular ingress
    :param syslog_ep: Destination endpoint for security logs
    :return:
    """
    print("Load ingress yaml and set AppProtect annotations")
    if "/" in policy_name:
        policy = policy_name
    else:
        policy = f"{namespace}/{policy_name}"
    logconf = f"{namespace}/logconf"

    with open(yaml_manifest) as f:
        doc = yaml.safe_load(f)

        doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-policy"] = policy
        doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-enable"] = ap_pol_st
        doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-security-log-enable"] = ap_log_st
        doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-security-log"] = logconf
        doc["metadata"]["annotations"][
            "appprotect.f5.com/app-protect-security-log-destination"
        ] = f"syslog:server={syslog_ep}"
        create_ingress(kube_apis.networking_v1, namespace, doc)


def create_ingress_with_dos_annotations(kube_apis, yaml_manifest, namespace, dos_protected) -> None:
    """
    Create an ingress with AppProtect annotations
    :param dos_protected: the namespace/name of the dos protected resource
    :param kube_apis: KubeApis
    :param yaml_manifest: an absolute path to ingress yaml
    :param namespace: namespace
    :return:
    """
    print("Load ingress yaml and set DOS annotations")

    with open(yaml_manifest) as f:
        doc = yaml.safe_load(f)
        doc["metadata"]["annotations"]["appprotectdos.f5.com/app-protect-dos-resource"] = dos_protected
        create_ingress(kube_apis.networking_v1, namespace, doc)


def replace_ingress_with_ap_annotations(
    kube_apis, yaml_manifest, name, namespace, policy_name, ap_pol_st, ap_log_st, syslog_ep
) -> None:
    """
    Replace an ingress with AppProtect annotations
    :param kube_apis: KubeApis
    :param yaml_manifest: an absolute path to ingress yaml
    :param namespace: namespace
    :param policy_name: AppProtect policy
    :param ap_log_st: True/False for enabling/disabling AppProtect security logging
    :param ap_pol_st: True/False for enabling/disabling AppProtect module for particular ingress
    :param syslog_ep: Destination endpoint for security logs
    :return:
    """
    print("Load ingress yaml and set AppProtect annotations")
    policy = f"{namespace}/{policy_name}"
    logconf = f"{namespace}/logconf"

    with open(yaml_manifest) as f:
        doc = yaml.safe_load(f)

        doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-policy"] = policy
        doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-enable"] = ap_pol_st
        doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-security-log-enable"] = ap_log_st
        doc["metadata"]["annotations"]["appprotect.f5.com/app-protect-security-log"] = logconf
        doc["metadata"]["annotations"][
            "appprotect.f5.com/app-protect-security-log-destination"
        ] = f"syslog:server={syslog_ep}"
        replace_ingress(kube_apis.networking_v1, name, namespace, doc)


def delete_items_from_yaml(kube_apis, yaml_manifest, namespace) -> None:
    """
    Delete all the items found in the yaml file.

    :param kube_apis: KubeApis
    :param yaml_manifest: an absolute path to a file
    :param namespace: namespace
    :return:
    """
    print("Load yaml:")
    with open(yaml_manifest) as f:
        docs = yaml.safe_load_all(f)
        for doc in docs:
            if doc:
                if doc["kind"] == "Namespace":
                    delete_namespace(kube_apis.v1, doc["metadata"]["name"])
                elif doc["kind"] == "Secret":
                    delete_secret(kube_apis.v1, doc["metadata"]["name"], namespace)
                elif doc["kind"] == "Ingress":
                    delete_ingress(kube_apis.networking_v1, doc["metadata"]["name"], namespace)
                elif doc["kind"] == "Service":
                    delete_service(kube_apis.v1, doc["metadata"]["name"], namespace)
                elif doc["kind"] == "Deployment":
                    delete_deployment(kube_apis.apps_v1_api, doc["metadata"]["name"], namespace)
                elif doc["kind"] == "DaemonSet":
                    delete_daemon_set(kube_apis.apps_v1_api, doc["metadata"]["name"], namespace)
                elif doc["kind"] == "ConfigMap":
                    delete_configmap(kube_apis.v1, doc["metadata"]["name"], namespace)


def ensure_connection(request_url, expected_code=404, headers={}) -> None:
    """
    Wait for connection.

    :param request_url: url to request
    :param expected_code: response code
    :return:
    """
    for _ in range(10):
        try:
            resp = requests.get(request_url, headers=headers, verify=False, timeout=5)
            if resp.status_code == expected_code:
                return
        except Exception as ex:
            print(f"Warning: there was an exception {str(ex)}")
        time.sleep(3)
    pytest.fail("Connection failed after several attempts")


def ensure_connection_to_public_endpoint(ip_address, port, port_ssl) -> None:
    """
    Ensure the public endpoint doesn't refuse connections.

    :param ip_address:
    :param port:
    :param port_ssl:
    :return:
    """
    ensure_connection(f"http://{ip_address}:{port}/")
    ensure_connection(f"https://{ip_address}:{port_ssl}/")


def read_service(v1: CoreV1Api, name, namespace) -> V1Service:
    """
    Get details of a Service.

    :param v1: CoreV1Api
    :param name: service name
    :param namespace: namespace name
    :return: V1Service
    """
    print(f"Read a service named '{name}'")
    return v1.read_namespaced_service(name, namespace)


def replace_service(v1: CoreV1Api, name, namespace, body) -> str:
    """
    Patch a service based on a dict.

    :param v1: CoreV1Api
    :param name:
    :param namespace: namespace
    :param body: a dict
    :return: str
    """
    print(f"Replace a Service: {name}")
    resp = v1.replace_namespaced_service(name, namespace, body)
    print(f"Service updated with name '{name}'")
    return resp.metadata.name


def get_events_for_object(v1: CoreV1Api, namespace, object_name) -> []:
    """
    Get the list of events of an objectin a namespace.

    :param v1: CoreV1Api
    :param namespace: namespace
    :param object_name: object name
    :return: []
    """
    print(f"Get the events for {object_name} in the namespace: {namespace}")
    events = v1.list_namespaced_event(namespace)
    return [event for event in events.items if event.involved_object.name == object_name]


def get_events(v1: CoreV1Api, namespace) -> []:
    """
    Get the list of events in a namespace.

    :param v1: CoreV1Api
    :param namespace:
    :return: []
    """
    print(f"Get the events in the namespace: {namespace}")
    res = v1.list_namespaced_event(namespace)
    return res.items


def wait_for_event(v1: CoreV1Api, text, namespace, retry=30, interval=1) -> None:
    """
    Wait for an event on an object in a namespace.

    :param v1: CoreV1Api
    :param text: event text
    :param namespace: object namespace
    :param retry:
    :param interval:
    :return:
    """
    c = 0
    while c < retry:
        events = get_events(v1, namespace)
        for i in range(len(events) - 1, -1, -1):
            if text in events[i].message:
                return True
        wait_before_test(interval)
        c += 1
    return False


def ensure_response_from_backend(req_url, host, additional_headers=None, check404=False, sni=False) -> None:
    """
    Wait for 502|504|404 to disappear.

    :param req_url: url to request
    :param host:
    :param additional_headers:
    :return:
    """
    headers = {"host": host}
    if additional_headers:
        headers.update(additional_headers)

    if sni and check404:
        session = create_sni_session()
        for _ in range(60):
            try:
                resp = session.get(
                    req_url,
                    headers=headers,
                    allow_redirects=False,
                    verify=False,
                )
                if resp.status_code != 502 and resp.status_code != 504 and resp.status_code != 404:
                    print(
                        f"After {_} retries at 1 second interval, got {resp.status_code} response. Continue with tests..."
                    )
                    return
                time.sleep(1)
            except requests.exceptions.SSLError as e:
                exception = str(e)
                print(f"SSL certificate exception: {exception}")
                resp = mock.Mock()
                resp.status_code = "None"
        pytest.fail(f"Keep getting {resp.status_code} from {req_url} after 60 seconds. Exiting...")

    if check404:
        for _ in range(60):
            resp = requests.get(req_url, headers=headers, verify=False)
            if resp.status_code != 502 and resp.status_code != 504 and resp.status_code != 404:
                print(
                    f"After {_} retries at 1 second interval, got {resp.status_code} response. Continue with tests..."
                )
                return
            time.sleep(1)
        pytest.fail(f"Keep getting {resp.status_code} from {req_url} after 60 seconds. Exiting...")

    else:
        for _ in range(30):
            resp = requests.get(req_url, headers=headers, verify=False)
            if resp.status_code != 502 and resp.status_code != 504:
                print(f"After {_} retries at 1 second interval, got non 502|504 response. Continue with tests...")
                return
            wait_before_test()
        pytest.fail(f"Keep getting 502|504 from {req_url} after 60 seconds. Exiting...")


def get_service_endpoint(kube_apis, service_name, namespace) -> str:
    """
    Wait for endpoint resource to spin up.
    :param kube_apis: Kubernetes API object
    :param service_name: Service resource name
    :param namespace: test namespace
    :return: endpoint ip
    """
    found = False
    retry = 0
    ep = ""
    while not found and retry < 60:
        time.sleep(1)
        try:
            ep = kube_apis.v1.read_namespaced_endpoints(service_name, namespace).subsets[0].addresses[0].ip
            found = True
            print(f"Endpoint IP for {service_name} is {ep}")
        except TypeError as err:
            print(f"TypeError: {err}")
            retry += 1
        except ApiException as ex:
            if ex.status == 500:
                print("Reason: Internal server error and Request timed out")
                raise ApiException
    return ep


def parse_metric_data(resp_content, metric_string) -> str:
    for line in resp_content.splitlines():
        if metric_string in line:
            return re.findall(r"\d+", line)[0]


def get_last_reload_time(req_url, ingress_class) -> str:
    # return most recent reload duration in ms
    ensure_connection(req_url, 200)
    resp = requests.get(req_url)
    assert resp.status_code == 200, f"Expected 200 code for /metrics and got {resp.status_code}"
    resp_content = resp.content.decode("utf-8")
    metric_string = 'last_reload_milliseconds{class="%s"}' % ingress_class
    return parse_metric_data(resp_content, metric_string)


def get_total_ingresses(req_url, ingress_class) -> str:
    # return total number of ingresses in specified class of regular type
    ensure_connection(req_url, 200)
    resp = requests.get(req_url)
    resp_content = resp.content.decode("utf-8")
    metric_string = 'controller_ingress_resources_total{class="%s",type="regular"}' % ingress_class
    return parse_metric_data(resp_content, metric_string)


def get_total_vs(req_url, ingress_class) -> str:
    # return total number of virtualserver in specified ingress class
    ensure_connection(req_url, 200)
    resp = requests.get(req_url)
    resp_content = resp.content.decode("utf-8")
    metric_string = 'virtualserver_resources_total{class="%s"}' % ingress_class
    return parse_metric_data(resp_content, metric_string)


def get_total_vsr(req_url, ingress_class) -> str:
    # return total number of virtualserverroutes in specified ingress class
    ensure_connection(req_url, 200)
    resp = requests.get(req_url)
    resp_content = resp.content.decode("utf-8")
    metric_string = 'virtualserverroute_resources_total{class="%s"}' % ingress_class
    return parse_metric_data(resp_content, metric_string)


def get_last_reload_status(req_url, ingress_class) -> str:
    # return last reload status 0/1
    ensure_connection(req_url, 200)
    resp = requests.get(req_url)
    resp_content = resp.content.decode("utf-8")
    metric_string = 'nginx_last_reload_status{class="%s"}' % ingress_class
    return parse_metric_data(resp_content, metric_string)


def get_reload_count(req_url) -> int:
    print(req_url)
    ensure_connection(req_url, 200)
    resp = requests.get(req_url)

    assert resp.status_code == 200, f"Expected 200 code for /metrics and got {resp.status_code}"
    resp_content = resp.content.decode("utf-8")

    count = 0
    found = 0

    for line in resp_content.splitlines():
        # we search for endpoints and other reloads
        # ex:
        # nginx_ingress_controller_nginx_reloads_total{class="nginx",reason="endpoints"} 0
        # nginx_ingress_controller_nginx_reloads_total{class="nginx",reason="other"} 1
        if "nginx_ingress_controller_nginx_reloads_total{class=" in line:
            c = re.findall(r"\d+", line)[0]
            count += int(c)
            found += 1

        if found == 2:
            break

    assert found == 2

    return count


def get_test_file_name(path) -> str:
    """
    :param path: full path to the test file
    """
    return (str(path).rsplit("/", 1)[-1])[:-3]


def write_to_json(fname, data) -> None:
    """
    :param fname: filename.json
    :param data: dictionary
    """
    file_path = f"{PROJECT_ROOT}/json_files/"
    if not os.path.isdir(file_path):
        os.mkdir(file_path)
    if os.path.exists(f"{file_path}/{fname}"):
        with open(f"json_files/{fname}") as f:
            contents = json.load(f)
        contents.update(data)
        file = contents
    else:
        file = data
    with open(f"json_files/{fname}", "w+") as f:
        json.dump(file, f, ensure_ascii=False, indent=4)


def get_last_log_entry(kube_apis, pod_name, namespace) -> str:
    """
    :param kube_apis: kube apis
    :param pod_name: the name of the pod
    :param namespace: the namespace
    """
    logs = kube_apis.read_namespaced_pod_log(pod_name, namespace)
    # Our log entries end in '\n' which means the final entry when we split on a new line
    # is an empty string. Return the second to last entry instead.
    return logs.split("\n")[-2]


def get_resource_metrics(kube_apis, plural, namespace="nginx-ingress") -> str:
    """
    :param kube_apis: kube apis
    :param namespace: the namespace
    :param plural: the plural of the resource
    """
    if plural == "pods":
        metrics = kube_apis.list_namespaced_custom_object("metrics.k8s.io", "v1beta1", namespace, plural)
        while metrics["items"] == []:
            wait_before_test()
            try:
                metrics = kube_apis.list_namespaced_custom_object("metrics.k8s.io", "v1beta1", namespace, plural)
            except ApiException as e:
                print(f"Error: {e}")
    elif plural == "nodes":
        metrics = kube_apis.list_cluster_custom_object("metrics.k8s.io", "v1beta1", plural)
        while metrics["items"] == []:
            wait_before_test()
            try:
                metrics = kube_apis.list_cluster_custom_object("metrics.k8s.io", "v1beta1", plural)
            except ApiException as e:
                print(f"Error: {e}")
    else:
        return "Invalid plural specified. Please use 'pods' or 'nodes' as the plural"
    return metrics["items"]


def get_apikey_auth_secrets_from_yaml(yaml_manifest) -> list:
    """
    Get apikey auth keys from yaml file.

    :param yaml_manifest: an absolute path to file
    :return: []apikeys
    """
    api_keys = []

    with open(yaml_manifest) as file:
        data = yaml.safe_load(file)
        if "data" in data:
            for key, encoded_value in data["data"].items():
                decoded_value = base64.b64decode(encoded_value).decode("utf-8")
                api_keys.append(decoded_value)
    return api_keys


def get_apikey_policy_details_from_yaml(yaml_manifest) -> dict:
    """
    Extract headers and queries from an API key policy yaml file.

    :param yaml_manifest: an absolute path to file
    :return: dictionary with 'headers' and 'queries'
    """
    details = {"headers": [], "queries": []}

    with open(yaml_manifest) as file:
        data = yaml.safe_load(file)

        if "spec" in data and "apiKey" in data["spec"] and "suppliedIn" in data["spec"]["apiKey"]:
            if "header" in data["spec"]["apiKey"]["suppliedIn"]:
                details["headers"] = data["spec"]["apiKey"]["suppliedIn"]["header"]
            if "query" in data["spec"]["apiKey"]["suppliedIn"]:
                details["queries"] = data["spec"]["apiKey"]["suppliedIn"]["query"]

    return details


def read_ingress(v1: NetworkingV1Api, name, namespace) -> V1Ingress:
    """
    Get details of an Ingress.

    :param v1: NetworkingV1Api
    :param name: ingress name
    :param namespace: namespace name
    :return: V1Ingress
    """
    print(f"Read an ingress named '{name}'")
    return v1.read_namespaced_ingress(name, namespace)


def pod_restart(v1: CoreV1Api, namespace):
    """
    Restart all pods in a deployment.
    """
    try:
        pods = v1.list_namespaced_pod(namespace=namespace)

        print(f"Found {len(pods.items)} pods to restart")

        # Delete all pods (they will be recreated by deployment)
        for pod in pods.items:
            print(f"Deleting pod {pod.metadata.name}")
            v1.delete_namespaced_pod(name=pod.metadata.name, namespace=namespace)

        wait_until_all_pods_are_ready(v1, namespace)
        print("Pod restart complete")

    except Exception as e:
        print(f"Error in pod restart: {e}")
        raise e

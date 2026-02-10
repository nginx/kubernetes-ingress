"""Describe methods to utilize the kubernetes-client."""

import logging
import time
from pprint import pprint

import pytest
import yaml
from kubernetes.client import ApiextensionsV1Api, CustomObjectsApi
from kubernetes.client.rest import ApiException
from suite.utils.resources_utils import ensure_item_removal


def create_crd(api_extensions_v1: ApiextensionsV1Api, body) -> None:
    """
    Create a CRD based on a dict

    :param api_extensions_v1: ApiextensionsV1Api
    :param body: a dict
    """
    try:
        api_extensions_v1.create_custom_resource_definition(body)
    except ApiException as api_ex:
        raise api_ex
    except Exception as ex:
        # https://github.com/kubernetes-client/python/issues/376
        if ex.args[0] == "Invalid value for `conditions`, must not be `None`":
            print("There was an insignificant exception during the CRD creation. Continue...")
        else:
            pytest.fail(f"An unexpected exception {ex} occurred. Exiting...")


def create_crd_from_yaml(api_extensions_v1: ApiextensionsV1Api, name, yaml_manifest) -> None:
    """
    Create a specific CRD based on yaml file.

    :param api_extensions_v1: ApiextensionsV1Api
    :param name: CRD name
    :param yaml_manifest: an absolute path to file
    """
    print(f"Create a CRD with name: {name}")
    with open(yaml_manifest) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            if dep["metadata"]["name"] == name:
                create_crd(api_extensions_v1, dep)
                print("CRD was created")


def delete_crd(api_extensions_v1: ApiextensionsV1Api, name) -> None:
    """
    Delete a CRD.

    :param api_extensions_v1: ApiextensionsV1Api
    :param name:
    :return:
    """
    print(f"Delete a CRD: {name}")
    api_extensions_v1.delete_custom_resource_definition(name)
    ensure_item_removal(api_extensions_v1.read_custom_resource_definition, name)
    print(f"CRD was removed with name '{name}'")


def read_custom_resource(
    custom_objects: CustomObjectsApi, namespace, plural, name, api_group="k8s.nginx.org"
) -> object:
    """
    Get CRD information (kubectl describe output)

    :param custom_objects: CustomObjectsApi
    :param namespace: The custom resource's namespace
    :param plural: the custom resource's plural name
    :param name: the custom object's name
    :return: object
    """
    print(f"Getting info for {name} in namespace {namespace}")
    try:
        response = custom_objects.get_namespaced_custom_object(api_group, "v1", namespace, plural, name)
        return response

    except ApiException:
        logging.exception(f"Exception occurred while reading CRD")
        raise


def is_dnsendpoint_present(custom_objects: CustomObjectsApi, name, namespace) -> bool:
    """
    Check if a namespace has a dnsendpoint.

    :param v1: CoreV1Api
    :param name:
    :param namespace:
    :return: bool
    """
    try:
        read_custom_resource(custom_objects, namespace, "dnsendpoints", name, api_group="externaldns.nginx.org")
    except ApiException as ex:
        if ex.status == 404:
            print(f"No dnsendpoint '{name}' found.")
            return False
    return True


def create_resource_from_manifest(custom_objects: CustomObjectsApi, body, namespace, plural) -> None:
    """
    Create a Resource based on manifest.

    :param custom_objects: CustomObjectsApi
    :param body: manifest body
    :param namespace: namespace where the resource will be created
    :param plural: the plural of the resource
    """
    try:
        print("Create a Custom Resource: " + body["kind"])
        group, version = body["apiVersion"].split("/")
        custom_objects.create_namespaced_custom_object(group, version, namespace, plural, body)
        print(f"Custom resource {body['kind']} created with name '{body['metadata']['name']}'")
    except ApiException as ex:
        logging.exception(f"Exception: {ex} occurred while creating {body['kind']}: {body['metadata']['name']}")
        raise ex


def read_custom_resource_v1(custom_objects: CustomObjectsApi, namespace, plural, name) -> object:
    """
    Get CRD information (kubectl describe output)

    :param custom_objects: CustomObjectsApi
    :param namespace: The custom resource's namespace
    :param plural: the custom resource's plural name
    :param name: the custom object's name
    :return: object
    """
    print(f"Getting info for v1 crd {name} in namespace {namespace}")
    try:
        response = custom_objects.get_namespaced_custom_object("k8s.nginx.org", "v1", namespace, plural, name)
        pprint(response)
        return response

    except ApiException:
        logging.exception(f"Exception occurred while reading CRD")
        raise


def read_ts(custom_objects: CustomObjectsApi, namespace, name) -> object:
    """
    Read TransportService resource.
    """
    return read_custom_resource(custom_objects, namespace, "transportservers", name)


def create_ts_from_yaml(custom_objects: CustomObjectsApi, yaml_manifest, namespace) -> dict:
    """
    Create a TransportServer Resource based on yaml file.

    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return: a dictionary representing the resource
    """
    return create_resource_from_yaml(custom_objects, yaml_manifest, namespace, "transportservers")


def create_gc_from_yaml(custom_objects: CustomObjectsApi, yaml_manifest, namespace) -> dict:
    """
    Create a GlobalConfiguration Resource based on yaml file.

    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return: a dictionary representing the resource
    """
    print(f"Load {yaml_manifest}")
    return create_resource_from_yaml(custom_objects, yaml_manifest, namespace, "globalconfigurations")


def patch_gc_from_yaml(custom_objects: CustomObjectsApi, name, yaml_manifest, namespace) -> dict:
    """
    Patch a GlobalConfiguration Resource based on yaml file.

    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return: a dictionary representing the resource
    """
    print(f"Load {yaml_manifest}")
    return patch_custom_resource(custom_objects, name, yaml_manifest, namespace, "globalconfigurations")


def create_resource_from_yaml(custom_objects: CustomObjectsApi, yaml_manifest, namespace, plural) -> dict:
    """
    Create a Resource based on yaml file.

    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :param plural: the plural of the resource
    :return: a dictionary representing the resource
    """

    with open(yaml_manifest) as f:
        body = yaml.safe_load(f)
    try:
        print("Create a Custom Resource: " + body["kind"])
        group, version = body["apiVersion"].split("/")
        custom_objects.create_namespaced_custom_object(group, version, namespace, plural, body)
        print(f"Custom resource {body['kind']} created with name '{body['metadata']['name']}'")
        return body
    except ApiException as ex:
        logging.exception(f"Exception: {ex} occurred while creating {body['kind']}: {body['metadata']['name']}")
        raise


def delete_ts(custom_objects: CustomObjectsApi, resource, namespace) -> None:
    """
    Delete a TransportServer Resource.

    :param custom_objects: CustomObjectsApi
    :param namespace: namespace
    :param resource: a dictionary representation of the resource yaml
    :param namespace:
    :return:
    """
    return delete_resource(custom_objects, resource, namespace, "transportservers")


def delete_gc(custom_objects: CustomObjectsApi, resource, namespace) -> None:
    """
    Delete a GlobalConfiguration Resource.

    :param custom_objects: CustomObjectsApi
    :param namespace: namespace
    :param resource: a dictionary representation of the resource yaml
    :param namespace:
    :return:
    """
    return delete_resource(custom_objects, resource, namespace, "globalconfigurations")


def delete_resource(custom_objects: CustomObjectsApi, resource, namespace, plural) -> None:
    """
    Delete a Resource.

    :param custom_objects: CustomObjectsApi
    :param namespace: namespace
    :param resource: a dictionary representation of the resource yaml
    :param namespace:
    :param plural: the plural of the resource
    :return:
    """

    name = resource["metadata"]["name"]
    kind = resource["kind"]
    group, version = resource["apiVersion"].split("/")

    print(f"Delete a '{kind}' with name '{name}'")

    custom_objects.delete_namespaced_custom_object(group, version, namespace, plural, name)
    ensure_item_removal(
        custom_objects.get_namespaced_custom_object,
        group,
        version,
        namespace,
        plural,
        name,
    )
    print(f"Resource '{kind}' was removed with name '{name}'")


def create_dos_logconf_from_yaml(custom_objects: CustomObjectsApi, yaml_manifest, namespace) -> str:
    """
    Create a logconf for Dos, based on yaml file.
    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return: str
    """
    print("Create DOS logconf:")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    custom_objects.create_namespaced_custom_object("appprotectdos.f5.com", "v1beta1", namespace, "apdoslogconfs", dep)
    print(f"DOS logconf created with name '{dep['metadata']['name']}'")
    return dep["metadata"]["name"]


def create_dos_policy_from_yaml(custom_objects: CustomObjectsApi, yaml_manifest, namespace) -> str:
    """
    Create a policy for Dos based on yaml file.
    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return: str
    """
    print("Create Dos Policy:")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    custom_objects.create_namespaced_custom_object("appprotectdos.f5.com", "v1beta1", namespace, "apdospolicies", dep)
    print(f"DOS Policy created with name '{dep['metadata']['name']}'")
    return dep["metadata"]["name"]


def create_dos_protected_from_yaml(custom_objects: CustomObjectsApi, yaml_manifest, namespace, ing_namespace) -> str:
    """
    Create a protected resource for Dos based on yaml file.
    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return: str
    """
    print("Create Dos Protected:")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
        dep["spec"]["dosSecurityLog"]["apDosLogConf"] = dep["spec"]["dosSecurityLog"]["apDosLogConf"].replace(
            "<NAMESPACE>", namespace
        )
        dep["spec"]["dosSecurityLog"]["dosLogDest"] = dep["spec"]["dosSecurityLog"]["dosLogDest"].replace(
            "<NAMESPACE>", ing_namespace
        )
        dep["spec"]["apDosPolicy"] = dep["spec"]["apDosPolicy"].replace("<NAMESPACE>", namespace)
        dep["spec"]["dosAccessLogDest"] = dep["spec"]["dosAccessLogDest"].replace("<NAMESPACE>", ing_namespace)
    custom_objects.create_namespaced_custom_object(
        "appprotectdos.f5.com", "v1beta1", namespace, "dosprotectedresources", dep
    )
    print(f"DOS Protected resource created with name '{namespace}/{dep['metadata']['name']}'")
    return dep["metadata"]["name"]


def delete_dos_logconf(custom_objects: CustomObjectsApi, name, namespace) -> None:
    """
    Delete a Dos logconf.
    :param custom_objects: CustomObjectsApi
    :param namespace: namespace
    :param name:
    :return:
    """
    print(f"Delete DOS logconf: {name}")
    custom_objects.delete_namespaced_custom_object("appprotectdos.f5.com", "v1beta1", namespace, "apdoslogconfs", name)
    ensure_item_removal(
        custom_objects.get_namespaced_custom_object,
        "appprotectdos.f5.com",
        "v1beta1",
        namespace,
        "apdoslogconfs",
        name,
    )
    print(f"DOS logconf was removed with name: {name}")


def delete_dos_protected(custom_objects: CustomObjectsApi, name, namespace) -> None:
    """
    Delete a Dos protected.
    :param custom_objects: CustomObjectsApi
    :param namespace: namespace
    :param name:
    :return:
    """
    print(f"Delete DOS protected: {name}")
    custom_objects.delete_namespaced_custom_object(
        "appprotectdos.f5.com", "v1beta1", namespace, "dosprotectedresources", name
    )
    ensure_item_removal(
        custom_objects.get_namespaced_custom_object,
        "appprotectdos.f5.com",
        "v1beta1",
        namespace,
        "dosprotectedresources",
        name,
    )
    print(f"DOS logconf was removed with name: {name}")


def delete_dos_policy(custom_objects: CustomObjectsApi, name, namespace) -> None:
    """
    Delete a Dos policy.
    :param custom_objects: CustomObjectsApi
    :param namespace: namespace
    :param name:
    :return:
    """
    print(f"Delete a DOS policy: {name}")
    custom_objects.delete_namespaced_custom_object("appprotectdos.f5.com", "v1beta1", namespace, "apdospolicies", name)
    ensure_item_removal(
        custom_objects.get_namespaced_custom_object,
        "appprotectdos.f5.com",
        "v1beta1",
        namespace,
        "apdospolicies",
        name,
    )
    time.sleep(3)
    print(f"DOS policy was removed with name: {name}")


def patch_ts_from_yaml(custom_objects: CustomObjectsApi, name, yaml_manifest, namespace) -> None:
    """
    Patch a TransportServer based on yaml manifest
    """
    return patch_custom_resource(custom_objects, name, yaml_manifest, namespace, "transportservers")


def patch_custom_resource(custom_objects: CustomObjectsApi, name, yaml_manifest, namespace, plural) -> None:
    """
    Patch a custom resource based on yaml manifest
    """
    print(f"Update a Resource: {name}")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)

    try:
        custom_objects.patch_namespaced_custom_object("k8s.nginx.org", "v1", namespace, plural, name, dep)
    except ApiException:
        logging.exception(f"Failed with exception while patching custom resource: {name}")
        raise


def patch_ts(custom_objects: CustomObjectsApi, namespace, body) -> None:
    """
    Patch a TransportServer
    """
    name = body["metadata"]["name"]

    print(f"Update a Resource: {name}")

    try:
        custom_objects.patch_namespaced_custom_object("k8s.nginx.org", "v1", namespace, "transportservers", name, body)
    except ApiException:
        logging.exception(f"Failed with exception while patching custom resource: {name}")
        raise


def generate_item_with_upstream_options(yaml_manifest, options) -> dict:
    """
    Generate a VS/VSR item with an upstream option.

    Update all the upstreams in VS/VSR
    :param yaml_manifest: an absolute path to a file
    :param options: dict
    :return: dict
    """
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    for upstream in dep["spec"]["upstreams"]:
        upstream.update(options)
    return dep


def get_pod_metrics(request, namespace) -> list:
    retries = 0
    pod_count = int(request.config.getoption("--replicas"))
    metrics = []
    while (not metrics) and retries <= (pod_count * 60):
        metrics = CustomObjectsApi().list_namespaced_custom_object("metrics.k8s.io", "v1beta1", namespace, "pods")[
            "items"
        ]
        time.sleep(1)
        retries += 1
        print(f"Retry #{retries}")
    return metrics

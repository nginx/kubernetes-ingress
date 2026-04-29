"""Describe methods to utilize the AppProtect resources."""

import logging
import time

import yaml
from kubernetes.client import CustomObjectsApi
from kubernetes.client.rest import ApiException
from suite.utils.resources_utils import ensure_item_removal


def read_ap_custom_resource(custom_objects: CustomObjectsApi, namespace, plural, name) -> object:
    """
    Get AppProtect CRD information (kubectl describe output)
    :param custom_objects: CustomObjectsApi
    :param namespace: The custom resource's namespace
    :param plural: the custom resource's plural name
    :param name: the custom object's name
    :return: object
    """
    print(f"Getting info for {name} in namespace {namespace}")
    try:
        response = custom_objects.get_namespaced_custom_object("appprotect.f5.com", "v1beta1", namespace, plural, name)
        return response

    except ApiException as ex:
        if ex.status != 404:
            logging.error(f"Exception occurred while reading CRD", exc_info=True)
        raise


def create_ap_waf_policy_from_yaml(
    custom_objects: CustomObjectsApi,
    yaml_manifest,
    namespace,
    ap_namespace,
    waf_enable,
    log_enable,
    appolicy,
    aplogconf,
    logdest,
) -> str:
    """
    Create a Policy based on yaml file.

    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace: namespace for test resources
    :param ap_namespace: namespace for AppProtect resources
    :param waf_enable: true/false
    :param log_enable: true/false
    :param appolicy: AppProtect policy name
    :param aplogconf: Logconf name
    :param logdest: AP log destination (syslog)
    :return: str
    """
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    try:
        dep["spec"]["waf"]["enable"] = waf_enable
        dep["spec"]["waf"]["apPolicy"] = f"{ap_namespace}/{appolicy}"
        dep["spec"]["waf"]["securityLog"]["enable"] = log_enable
        dep["spec"]["waf"]["securityLog"]["apLogConf"] = f"{ap_namespace}/{aplogconf}"
        dep["spec"]["waf"]["securityLog"]["logDest"] = f"{logdest}"

        custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", namespace, "policies", dep)
        print(f"Policy created: {dep}")
        return dep["metadata"]["name"]
    except ApiException:
        logging.error(f"Exception occurred while creating Policy: {dep['metadata']['name']}", exc_info=True)
        raise


def create_ap_multilog_waf_policy_from_yaml(
    custom_objects: CustomObjectsApi,
    yaml_manifest,
    namespace,
    ap_namespace,
    waf_enable,
    log_enable,
    appolicy,
    aplogconfs,
    logdests,
) -> str:
    """
    Create a Policy based on yaml file.

    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace: namespace for test resources
    :param ap_namespace: namespace for AppProtect resources
    :param waf_enable: true/false
    :param log_enable: true/false
    :param appolicy: AppProtect policy name
    :param aplogconfs: List of Logconf names
    :param logdests: List of AP log destinations (syslog)
    :return: str
    """
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    try:
        dep["spec"]["waf"]["enable"] = waf_enable
        dep["spec"]["waf"]["apPolicy"] = f"{ap_namespace}/{appolicy}"
        seclogs = []
        try:
            for i in range(len(aplogconfs)):
                seclogs.append(
                    {"enable": True, "apLogConf": f"{ap_namespace}/{aplogconfs[i]}", "logDest": f"{logdests[i]}"}
                )
            dep["spec"]["waf"]["securityLogs"] = seclogs
        except KeyError:
            logging.error(f"Exception occurred while creating Policy: {dep['metadata']['name']}", exc_info=True)
            raise
        del dep["spec"]["waf"]["securityLog"]

        custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", namespace, "policies", dep)
        print(f"Policy created: {dep}")
        return dep["metadata"]["name"]
    except ApiException:
        logging.error(f"Exception occurred while creating Policy: {dep['metadata']['name']}", exc_info=True)
        raise


def create_ap_logconf_from_yaml(custom_objects: CustomObjectsApi, yaml_manifest, namespace) -> str:
    """
    Create a logconf for AppProtect based on yaml file.
    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return: str
    """
    print("Create Ap logconf:")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    custom_objects.create_namespaced_custom_object("appprotect.f5.com", "v1beta1", namespace, "aplogconfs", dep)
    print(f"AP logconf created with name '{dep['metadata']['name']}'")
    return dep["metadata"]["name"]


def create_ap_policy_from_yaml(custom_objects: CustomObjectsApi, yaml_manifest, namespace) -> str:
    """
    Create a policy for AppProtect based on yaml file.
    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return: str
    """
    print("Create AP Policy:")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    custom_objects.create_namespaced_custom_object("appprotect.f5.com", "v1beta1", namespace, "appolicies", dep)
    print(f"AP Policy created with name '{dep['metadata']['name']}'")
    return dep["metadata"]["name"]


def create_ap_usersig_from_yaml(custom_objects: CustomObjectsApi, yaml_manifest, namespace) -> str:
    """
    Create a UserSig for AppProtect based on yaml file.
    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return: str
    """
    print("Create AP UserSig:")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    custom_objects.create_namespaced_custom_object("appprotect.f5.com", "v1beta1", namespace, "apusersigs", dep)
    print(f"AP UserSig created with name '{dep['metadata']['name']}'")
    return dep["metadata"]["name"]


def delete_and_create_ap_policy_from_yaml(custom_objects: CustomObjectsApi, name, yaml_manifest, namespace) -> None:
    """
    Patch a AP Policy based on yaml manifest
    :param custom_objects: CustomObjectsApi
    :param name:
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return:
    """
    print(f"Update an AP Policy: {name}")

    try:
        delete_ap_policy(custom_objects, name, namespace)
        create_ap_policy_from_yaml(custom_objects, yaml_manifest, namespace)
    except ApiException:
        logging.error(f"Failed with exception while patching AP Policy: {name}", exc_info=True)
        raise


def delete_ap_usersig(custom_objects: CustomObjectsApi, name, namespace) -> None:
    """
    Delete a AppProtect usersig.
    :param custom_objects: CustomObjectsApi
    :param namespace: namespace
    :param name:
    :return:
    """
    print(f"Delete AP UserSig: {name}")
    custom_objects.delete_namespaced_custom_object("appprotect.f5.com", "v1beta1", namespace, "apusersigs", name)
    ensure_item_removal(
        custom_objects.get_namespaced_custom_object,
        "appprotect.f5.com",
        "v1beta1",
        namespace,
        "apusersigs",
        name,
    )
    print(f"AP UserSig was removed with name: {name}")


def delete_ap_logconf(custom_objects: CustomObjectsApi, name, namespace) -> None:
    """
    Delete a AppProtect logconf.
    :param custom_objects: CustomObjectsApi
    :param namespace: namespace
    :param name:
    :return:
    """
    print(f"Delete AP logconf: {name}")
    custom_objects.delete_namespaced_custom_object("appprotect.f5.com", "v1beta1", namespace, "aplogconfs", name)
    ensure_item_removal(
        custom_objects.get_namespaced_custom_object,
        "appprotect.f5.com",
        "v1beta1",
        namespace,
        "aplogconfs",
        name,
    )
    print(f"AP logconf was removed with name: {name}")


def delete_ap_policy(custom_objects: CustomObjectsApi, name, namespace) -> None:
    """
    Delete a AppProtect policy.
    :param custom_objects: CustomObjectsApi
    :param namespace: namespace
    :param name:
    :return:
    """
    print(f"Delete a AP policy: {name}")
    custom_objects.delete_namespaced_custom_object("appprotect.f5.com", "v1beta1", namespace, "appolicies", name)
    ensure_item_removal(
        custom_objects.get_namespaced_custom_object,
        "appprotect.f5.com",
        "v1beta1",
        namespace,
        "appolicies",
        name,
    )
    time.sleep(3)
    print(f"AP policy was removed with name: {name}")

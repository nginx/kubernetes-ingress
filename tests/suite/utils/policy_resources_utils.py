"""Describe methods to utilize the Policy resource."""

import logging

import yaml
from kubernetes.client import CustomObjectsApi
from kubernetes.client.rest import ApiException
from suite.utils.custom_resources_utils import read_custom_resource
from suite.utils.resources_utils import (
    create_items_from_yaml,
    create_secret_from_yaml,
    delete_items_from_yaml,
    delete_secret,
    ensure_item_removal,
    get_service_endpoint,
    wait_before_test,
    wait_until_all_pods_are_ready,
)


def read_policy(custom_objects: CustomObjectsApi, namespace, name) -> object:
    """
    Read Policy resource.
    """
    return read_custom_resource(custom_objects, namespace, "policies", name)


def create_policy_from_yaml(custom_objects: CustomObjectsApi, yaml_manifest, namespace) -> str:
    """
    Create a Policy based on yaml file.

    :param custom_objects: CustomObjectsApi
    :param yaml_manifest: an absolute path to file
    :param namespace:
    :return: str
    """
    print("Create a Policy:")
    with open(yaml_manifest) as f:
        dep = yaml.safe_load(f)
    try:
        custom_objects.create_namespaced_custom_object("k8s.nginx.org", "v1", namespace, "policies", dep)
        print(f"Policy created with name '{dep['metadata']['name']}'")
        return dep["metadata"]["name"]
    except ApiException:
        logging.error(f"Exception occurred while creating Policy: {dep['metadata']['name']}")
        raise


def delete_policy(custom_objects: CustomObjectsApi, name, namespace) -> None:
    """
    Delete a Policy.

    :param custom_objects: CustomObjectsApi
    :param namespace: namespace
    :param name:
    :return:
    """
    print(f"Delete a Policy: {name}")

    custom_objects.delete_namespaced_custom_object("k8s.nginx.org", "v1", namespace, "policies", name)
    ensure_item_removal(
        custom_objects.get_namespaced_custom_object,
        "k8s.nginx.org",
        "v1",
        namespace,
        "policies",
        name,
    )
    print(f"Policy was removed with name '{name}'")


def apply_and_wait_for_valid_policy(kube_apis, namespace, policy_yaml, retry_count=30, interval=1) -> str:
    pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_yaml, namespace)

    policy_info = {}
    for _ in range(retry_count):
        policy_info = read_custom_resource(kube_apis.custom_objects, namespace, "policies", pol_name)
        if (
            "status" in policy_info
            and policy_info["status"]["reason"] == "AddedOrUpdated"
            and policy_info["status"]["state"] == "Valid"
        ):
            return pol_name
        wait_before_test(interval)

    raise TimeoutError(
        f"Policy '{pol_name}' failed to become Valid after {retry_count * interval}s. "
        f"Last observed status: {policy_info.get('status', 'no status field')}"
    )


def setup_policy_backend(
    kube_apis, namespace, *, secret_yamls, backend_yaml, policy_yamls, validate_policies=True, wait_for_service=None
):
    """Deploy a backend with secrets and create policies.

    Generic setup function that can be used for any policy type (external-auth,
    rate-limit, etc.) with any combination of secrets and backends.

    Args:
        kube_apis: KubeApis instance.
        namespace: Kubernetes namespace.
        secret_yamls: List of YAML file paths for secrets to create.
        backend_yaml: YAML file path for backend deployment (ConfigMap + Deployment + Service).
        policy_yamls: List of YAML file paths for policies to create.
        validate_policies: If True (default), wait for each policy to reach Valid state.
            Set to False for tests that expect the policy to be Invalid/Rejected.
        wait_for_service: If set, wait for this service name's endpoints to be registered
            before returning. Use this when the controller must see endpoints before the
            VS/VSR is patched, to avoid a transient Warning from endpoint propagation lag.

    Returns:
        (secret_names, policy_names) -- lists of created resource names.
    """
    secret_names = []
    for yaml_path in secret_yamls:
        print(f"Create secret from {yaml_path}")
        name = create_secret_from_yaml(kube_apis.v1, namespace, yaml_path)
        secret_names.append(name)

    print(f"Deploy backend from {backend_yaml}")
    create_items_from_yaml(kube_apis, backend_yaml, namespace)
    wait_until_all_pods_are_ready(kube_apis.v1, namespace)

    if wait_for_service:
        print(f"Waiting for endpoints of service '{wait_for_service}' to be ready...")
        get_service_endpoint(kube_apis, wait_for_service, namespace)

    policy_names = []
    for yaml_path in policy_yamls:
        print(f"Create policy from {yaml_path}")
        if validate_policies:
            name = apply_and_wait_for_valid_policy(kube_apis, namespace, yaml_path)
        else:
            name = create_policy_from_yaml(kube_apis.custom_objects, yaml_path, namespace)
        policy_names.append(name)

    return secret_names, policy_names


def teardown_policy_backend(kube_apis, namespace, *, backend_yaml, secret_names, policy_names):
    """Delete policies, backend, and secrets.

    Generic teardown counterpart to setup_policy_backend.
    Each deletion is wrapped individually so that already-deleted resources
    (e.g. from destructive tests) do not prevent subsequent cleanup.

    Args:
        kube_apis: KubeApis instance.
        namespace: Kubernetes namespace.
        backend_yaml: YAML file path used to deploy the backend (for deletion).
        secret_names: List of secret names to delete.
        policy_names: List of policy names to delete.
    """
    for pol_name in policy_names:
        try:
            print(f"Delete policy: {pol_name}")
            delete_policy(kube_apis.custom_objects, pol_name, namespace)
        except Exception:
            logging.debug(f"teardown: ignoring error deleting policy {pol_name} (may already be deleted)")

    try:
        print(f"Delete backend from {backend_yaml}")
        delete_items_from_yaml(kube_apis, backend_yaml, namespace)
    except Exception:
        logging.debug(f"teardown: ignoring error deleting backend {backend_yaml} (may already be deleted)")

    for secret_name in secret_names:
        try:
            print(f"Delete secret: {secret_name}")
            delete_secret(kube_apis.v1, secret_name, namespace)
        except Exception:
            logging.debug(f"teardown: ignoring error deleting secret {secret_name} (may already be deleted)")


def apply_and_assert_valid_policy(kube_apis, namespace, policy_yaml, debug=False) -> str:
    pol_name = create_policy_from_yaml(kube_apis.custom_objects, policy_yaml, namespace)
    wait_before_test(1)
    policy_info = read_custom_resource(kube_apis.custom_objects, namespace, "policies", pol_name)
    if debug:
        print(f"Policy '{pol_name}' info: {policy_info}")
    assert (
        "status" in policy_info
        and policy_info["status"]["reason"] == "AddedOrUpdated"
        and policy_info["status"]["state"] == "Valid"
    )

    return pol_name

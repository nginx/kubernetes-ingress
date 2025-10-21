"""Describe methods to work with yaml files"""

import yaml


def get_first_ingress_host_from_yaml(file) -> str:
    """
    Parse yaml file and return first spec.rules[0].host appeared.

    :param file: an absolute path to file
    :return: str
    """
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            return dep["spec"]["rules"][0]["host"]


def get_name_from_yaml(file) -> str:
    """
    Parse yaml file and return first metadata.name appeared.

    :param file: an absolute path to file
    :return: str
    """
    res = ""
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            return dep["metadata"]["name"]
    return res


def get_namespace_from_yaml(file) -> str:
    """
    Parse yaml file and return first metadata.name appeared.

    :param file: an absolute path to file
    :return: str
    """
    res = ""
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            try:
                res = dep["metadata"]["namespace"]
                break
            except KeyError:
                continue
    return res


def get_paths_from_vs_yaml(file) -> []:
    """
    Parse yaml file and return all the found spec.routes.path.

    :param file: an absolute path to file
    :return: []
    """
    res = []
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            for route in dep["spec"]["routes"]:
                res.append(route["path"])
    return res


def get_first_host_from_yaml(file) -> str:
    """
    Parse yaml file and return first spec.host appeared.

    :param file: an absolute path to file
    :return: str
    """
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            return dep["spec"]["host"]


def get_configmap_fields_from_yaml(file) -> {}:
    """
    Parse yaml file and return a dict of ConfigMap data fields.

    :param file: an absolute path to a file
    :return: {}
    """
    with open(file) as f:
        dep = yaml.safe_load(f)
        return dep["data"]


def get_route_namespace_from_vs_yaml(file) -> []:
    """
    Parse yaml file and return namespaces of all spec.routes.route.

    :param file: an absolute path to file
    :return: []
    """
    res = []
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            for route in dep["spec"]["routes"]:
                res.append(route["route"].split("/")[0])
    return res

def get_upstream_namespace_from_vs_yaml(file, default_namespace) -> []:
    """
    Parse yaml file and return namespaces of all spec.upstreams.service that contain namespace references.

    :param file: an absolute path to file
    :return: []
    """
    res = []
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            if "upstreams" in dep["spec"]:
                for upstream in dep["spec"]["upstreams"]:
                    service = upstream["service"]
                    if "/" in service:  # namespace/service format
                        namespace = service.split("/")[0]
                    else:
                        namespace = default_namespace
                        # if namespace not in res:
                    res.append(namespace)
    return res

def get_paths_from_vsr_yaml(file) -> []:
    """
    Parse yaml file and return all the found spec.subroutes.path.

    :param file: an absolute path to file
    :return: []
    """
    res = []
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            for route in dep["spec"]["subroutes"]:
                res.append(route["path"])
    return res


def get_secret_name_from_vs_or_ts_yaml(file) -> str:
    """
    Parse yaml file and return the tls secret name.

    :param file: an absolute path to file
    :return: str
    """
    res = ""
    with open(file) as f:
        docs = yaml.safe_load_all(f)
        for dep in docs:
            return dep["spec"]["tls"]["secret"]
    return res

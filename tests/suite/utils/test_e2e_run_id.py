import re
import tempfile
from unittest.mock import Mock, patch

import pytest
import yaml
from suite.fixtures.fixtures import create_generic_from_yaml
from suite.utils.resources_utils import (
    E2E_RUN_ID_LABEL,
    add_e2e_run_id_to_workload,
    create_daemon_set,
    create_deployment,
    create_stateful_set,
    generate_e2e_run_id,
    get_e2e_run_selector,
)


@pytest.mark.parametrize("kind", ["Deployment", "DaemonSet", "StatefulSet"])
def test_add_e2e_run_id_to_workload_updates_only_pod_template(kind):
    workload = {
        "kind": kind,
        "metadata": {"labels": {"top-level": "unchanged"}},
        "spec": {
            "selector": {"matchLabels": {"app": "backend"}},
            "template": {"metadata": {"labels": {"app": "backend"}}},
        },
    }

    add_e2e_run_id_to_workload(workload, "run-id")

    assert workload["metadata"]["labels"] == {"top-level": "unchanged"}
    assert workload["spec"]["selector"] == {"matchLabels": {"app": "backend"}}
    assert workload["spec"]["template"]["metadata"]["labels"] == {
        "app": "backend",
        E2E_RUN_ID_LABEL: "run-id",
    }


def test_e2e_run_id_is_label_safe_and_formats_a_selector():
    e2e_run_id = generate_e2e_run_id()

    assert re.fullmatch(r"[0-9a-f]{32}", e2e_run_id)
    assert get_e2e_run_selector(e2e_run_id) == f"{E2E_RUN_ID_LABEL}={e2e_run_id}"


def test_add_e2e_run_id_to_workload_rejects_non_workloads():
    with pytest.raises(ValueError, match="Unsupported workload kind: Service"):
        add_e2e_run_id_to_workload({"kind": "Service"}, "run-id")


@pytest.mark.parametrize(
    ("creator", "api_method", "kind"),
    [
        (create_deployment, "create_namespaced_deployment", "Deployment"),
        (create_daemon_set, "create_namespaced_daemon_set", "DaemonSet"),
        (create_stateful_set, "create_namespaced_stateful_set", "StatefulSet"),
    ],
)
def test_workload_creators_add_the_supplied_run_id(creator, api_method, kind):
    workload = {
        "kind": kind,
        "metadata": {"name": "workload"},
        "spec": {"template": {"metadata": {"labels": {}}}},
    }
    api = Mock()

    creator(api, "test-namespace", workload, "run-id")

    assert workload["spec"]["template"]["metadata"]["labels"][E2E_RUN_ID_LABEL] == "run-id"
    getattr(api, api_method).assert_called_once_with("test-namespace", workload)


def test_generic_apply_labels_workloads_in_memory():
    docs = [
        {"kind": "Service", "metadata": {"name": "service"}},
        {
            "kind": "Deployment",
            "metadata": {"name": "deployment"},
            "spec": {"template": {"metadata": {"labels": {}}}},
        },
    ]
    request = Mock()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as manifest:
        yaml.safe_dump_all(docs, manifest)
        manifest.flush()
        with patch("suite.fixtures.fixtures.subprocess.run") as run:
            create_generic_from_yaml(manifest.name, request, "run-id")

    command = run.call_args.args[0]
    kwargs = run.call_args.kwargs
    assert command == ["kubectl", "apply", "-f", "-"]
    applied_docs = list(yaml.safe_load_all(kwargs["input"]))
    assert E2E_RUN_ID_LABEL not in applied_docs[0].get("metadata", {}).get("labels", {})
    assert applied_docs[1]["spec"]["template"]["metadata"]["labels"][E2E_RUN_ID_LABEL] == "run-id"

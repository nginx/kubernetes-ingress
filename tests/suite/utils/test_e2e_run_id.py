import re

import pytest
from suite.utils.resources_utils import (
    E2E_RUN_ID_LABEL,
    add_e2e_run_id_to_workload,
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

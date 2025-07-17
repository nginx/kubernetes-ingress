import pytest
from kubernetes.stream import stream
from suite.utils.resources_utils import get_first_pod_name, wait_before_test


@pytest.mark.agentv3
@pytest.mark.parametrize(
    "ingress_controller",
    [
        {
            "extra_args": [
                f"-agent=true",
            ]
        }
    ],
    indirect=["ingress_controller"],
)
class TestAgentV3:
    def test_agent(self, kube_apis, ingress_controller_prerequisites, ingress_controller):
        pod_name = get_first_pod_name(kube_apis.v1, "nginx-ingress")
        log = kube_apis.v1.read_namespaced_pod_log(pod_name, ingress_controller_prerequisites.namespace)

        command = ["/usr/bin/nginx-agent", "-v"]
        retries = 0
        while retries <= 3:
            wait_before_test()
            try:
                resp = stream(
                    kube_apis.v1.connect_get_namespaced_pod_exec,
                    pod_name,
                    ingress_controller_prerequisites.namespace,
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

        assert f"Failed to get nginx-agent version: fork/exec /usr/bin/nginx-agent" not in log
        assert "nginx-agent version v3" in result_conf

import pytest
from kubernetes.stream import stream
from settings import TEST_DATA
from suite.utils.resources_utils import get_file_contents, get_first_pod_name, wait_before_test


@pytest.mark.skip_for_nginx_oss
@pytest.mark.agentv2
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap",
    [
        {
            "extra_args": [
                "-enable-app-protect",
                "-agent=true",
                "-agent-instance-group=test-ic",
            ]
        }
    ],
    indirect=["crd_ingress_controller_with_ap"],
)
class TestAppProtectAgentV2:
    def test_ap_agent(self, kube_apis, ingress_controller_prerequisites, crd_ingress_controller_with_ap):
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
        assert "nginx-agent version v2" in result_conf

        # Integration test for agent config file - verify the agent config exists inside the NIC pod
        # Read expected config from test data file (agentv2 with AppProtect configuration)
        with open(f"{TEST_DATA}/agent/agent-v2-appprotect.conf") as f:
            expected_config = f.read().strip()

        # Get the actual config file content from the pod
        config_contents = get_file_contents(
            kube_apis.v1, "/etc/nginx-agent/nginx-agent.conf", pod_name, ingress_controller_prerequisites.namespace
        )

        # Normalize whitespace for comparison - remove trailing spaces from each line
        def normalize_config(config_text):
            return "\n".join(line.rstrip() for line in config_text.strip().split("\n"))

        config_contents_normalized = normalize_config(config_contents)
        expected_config_normalized = normalize_config(expected_config)
        assert config_contents_normalized == expected_config_normalized

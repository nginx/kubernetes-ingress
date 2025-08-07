import pytest
from kubernetes.stream import stream
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

        # Test for agent.config file - verify the agent config exists inside the NIC pod
        # The expected config that will be asserted against later
        expected_config = """#
# /etc/nginx-agent/nginx-agent.conf
#
# Configuration file for NGINX Agent.
#
# This file is to track NGINX Agent configuration values that are meant to be statically set. There
# are additional NGINX Agent configuration values that are set via the API and NGINX Agent install script
# which can be found in /var/lib/nginx-agent/agent-dynamic.conf.

log:
  # set log level (panic, fatal, error, info, debug, trace; default "info")
  level: info
  # set log path. if empty, don't log to file.
  path: /var/log/nginx-agent/
# data plane status message / 'heartbeat'
nginx:
  # path of NGINX logs to exclude
  exclude_logs: ""
  socket: "unix:/var/run/nginx-agent/nginx.sock"

dataplane:
  status:
    # poll interval for data plane status - the frequency the NGINX Agent will query the dataplane for changes
    poll_interval: 30s
    # report interval for data plane status - the maximum duration to wait before syncing dataplane information if no updates have being observed
    report_interval: 24h

metrics:
  # specify the size of a buffer to build before sending metrics
  bulk_size: 20
  # specify metrics poll interval
  report_interval: 1m
  collection_interval: 15s
  mode: aggregated

# OSS NGINX default config path
# path to aux file dirs can also be added
config_dirs: "/etc/nginx:/usr/local/etc/nginx:/usr/share/nginx/modules:/etc/nms"

  # api:
  # The port at which NGINX Agent accepts remote connections
  # The API address and port allow for remote management of NGINX and NGINX Agent
  #
  # ~~~ WARNING ~~~
  # Set API address to allow remote management
  # host: 127.0.0.1
  #
  # Set this value to a secure port number to prevent information leaks.
  # port: 8038"""
        expected_config = expected_config.strip()

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

#!/bin/bash
# Entrypoint for the NGINX + nginx-agent sidecar container.
# Starts both nginx and nginx-agent as co-processes.
# nginx-agent connects to the NIC controller's gRPC MPI server via a Unix socket.

set -euxo pipefail

handle_term() {
    echo "received TERM signal"
    echo "stopping nginx-agent ..."
    kill -TERM "${agent_pid}" 2>/dev/null
    wait -n ${agent_pid}
    echo "stopping nginx ..."
    kill -TERM "${nginx_pid}" 2>/dev/null
    wait -n ${nginx_pid}
}

handle_quit() {
    echo "received QUIT signal"
    echo "stopping nginx-agent ..."
    kill -QUIT "${agent_pid}" 2>/dev/null
    wait -n ${agent_pid}
    echo "stopping nginx ..."
    kill -QUIT "${nginx_pid}" 2>/dev/null
    wait -n ${nginx_pid}
}

trap 'handle_term' TERM
trap 'handle_quit' QUIT

# NOTE: Do NOT remove socket files from /var/run/nginx/ here.
# The agent.sock file is created by the NIC controller container's gRPC server
# which shares this directory via an emptyDir volume. The NIC gRPC server
# manages its own socket lifecycle (cleans up stale sockets before listening).

# In TLS mode, the NIC controller generates a self-signed CA cert and writes it
# to the shared volume. Wait for it before starting nginx-agent (which needs the
# CA to verify the gRPC server). In Unix socket mode this file won't exist and
# the variable is empty, so we skip the wait.
CA_CERT="${NGINX_AGENT_COMMAND_TLS_CA:-}"
if [ -n "${CA_CERT}" ]; then
    echo "waiting for CA cert at ${CA_CERT} ..."
    SECONDS=0
    while [ ! -f "${CA_CERT}" ]; do
        if ((SECONDS > 30)); then
            echo "timed out waiting for CA cert at ${CA_CERT}"
            exit 1
        fi
        sleep 0.5
    done
    echo "CA cert found"
fi

# Launch nginx in foreground mode
echo "starting nginx ..."

if [ "${1:-false}" = "debug" ]; then
    /usr/sbin/nginx-debug -g "daemon off;" &
else
    /usr/sbin/nginx -g "daemon off;" &
fi

nginx_pid=$!

# Wait for nginx to start accepting connections (up to 30s).
# With "daemon off;" nginx doesn't write a pid file, so we check the process
# and wait for port 80 to be listening.
SECONDS=0
while ! kill -0 "${nginx_pid}" 2>/dev/null || ! [ -e /proc/${nginx_pid}/fd ]; do
    if ((SECONDS > 30)); then
        echo "couldn't find nginx master process"
        exit 1
    fi
    sleep 1
done
echo "nginx is running (pid=${nginx_pid})"

# Start nginx-agent. It will connect to NIC's gRPC MPI server
# via the Unix socket configured through environment variables:
#   NGINX_AGENT_COMMAND_SERVER_SOCKET=/var/run/nginx/agent.sock
echo "starting nginx-agent ..."
nginx-agent &

agent_pid=$!

if [ $? != 0 ]; then
    echo "couldn't start the agent, please check the log file"
    exit 1
fi

wait_term() {
    wait ${agent_pid}
    trap - TERM
    kill -QUIT "${nginx_pid}" 2>/dev/null
    echo "waiting for nginx to stop..."
    wait ${nginx_pid}
}

wait_term

echo "nginx-agent process has stopped, exiting."

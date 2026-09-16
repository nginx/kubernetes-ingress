#!/usr/bin/env bash

# Local convenience wrapper around check-packages.py.
#
# Verifies that dependencies declared in build/Dockerfile and Helm charts
# are published and complete across target distros and architectures.
#
# ENVIRONMENT:
#   CERT          Path to client certificate (default: nginx-repo.crt)
#   KEY           Path to client key (default: nginx-repo.key)
#   NO_COLOR      Set to disable ANSI color output (https://no-color.org)
#   CI            Disables ANSI color output automatically
#
# ARGUMENTS:
#   All arguments are passed directly to check-packages.py.
#   Run './.github/scripts/dependency-check.sh --help' for full option reference.
#
# COMMON EXAMPLES:
#   # Check OSS packages:
#   ./.github/scripts/dependency-check.sh --group oss
#
#   # Check with mTLS certificates for Plus/NAP:
#   CERT=~/certs/nginx-repo.crt KEY=~/certs/nginx-repo.key ./.github/scripts/dependency-check.sh
#
#   # Validate against staging environments:
#   ./.github/scripts/dependency-check.sh --staging
#
#   # Show extended OS availability matrix:
#   ./.github/scripts/dependency-check.sh --group oss --matrix

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CERT="${CERT:-nginx-repo.crt}"
KEY="${KEY:-nginx-repo.key}"

PYTHON_BIN="python3"
if ! command -v python3 &>/dev/null; then
    if [ -x "/usr/bin/python3" ]; then
        PYTHON_BIN="/usr/bin/python3"
    else
        echo "Error: python3 is required to run check-packages.py." >&2
        exit 1
    fi
fi

exec "$PYTHON_BIN" "${SCRIPT_DIR}/check-packages.py" --cert "$CERT" --key "$KEY" "$@"

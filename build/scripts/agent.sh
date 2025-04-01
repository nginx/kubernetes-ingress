#!/bin/sh

set -e

chown -R 101:0 /etc/nginx-agent
if [ -f "/opt/app_protect/RELEASE" ]; then
    # shellcheck disable=SC2002
    if cat "/opt/app_protect/RELEASE" | cut -d '.' -f 1 | grep -q 4; then
        NAP_VERSION=$(cat /opt/app_protect/VERSION)
        echo "Adding NAP $NAP_VERSION directories"

        mkdir -p /etc/ssl/nms /opt/nms-nap-compiler
        chown -R 101:0 /etc/ssl/nms /opt/nms-nap-compiler
        chmod -R g=u /etc/ssl/nms /opt/nms-nap-compiler

        ln -s /opt/app_protect "/opt/nms-nap-compiler/app_protect-${NAP_VERSION}"
    fi
fi

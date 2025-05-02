#!/bin/sh

set -e


if [ -z "${WAF_VERSION##*v4*}" ]; then
    NAP_VERSION=$(cat /opt/app_protect/VERSION)

    mkdir -p /etc/ssl/nms /opt/nms-nap-compiler
    chown -R 101:0 /etc/ssl/nms /opt/nms-nap-compiler
    chmod -R g=u /etc/ssl/nms /opt/nms-nap-compiler

	ln -s /opt/app_protect "/opt/nms-nap-compiler/app_protect-${NAP_VERSION}"
fi

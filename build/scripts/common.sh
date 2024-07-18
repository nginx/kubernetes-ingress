#!/bin/sh

set -e

PLUS=""
if [ -z "${BUILD_OS##*plus*}" ]; then
    mkdir -p /etc/nginx/oidc/
    cp -a /tmp/internal/configs/oidc/* /etc/nginx/oidc/
    mkdir -p /etc/nginx/state_files/
    PLUS=-plus
fi

mkdir -p /etc/nginx/njs/ && cp -a /tmp/internal/configs/njs/* /etc/nginx/njs/
mkdir -p /var/lib/nginx /etc/nginx/secrets /etc/nginx/stream-conf.d
setcap 'cap_net_bind_service=+eip' /usr/sbin/nginx 'cap_net_bind_service=+eip' /usr/sbin/nginx-debug
setcap -v 'cap_net_bind_service=+eip' /usr/sbin/nginx 'cap_net_bind_service=+eip' /usr/sbin/nginx-debug

cp -a /tmp/internal/configs/version1/nginx$PLUS.ingress.tmpl \
    /tmp/internal/configs/version1/nginx$PLUS.tmpl \
	/tmp/internal/configs/version2/nginx$PLUS.virtualserver.tmpl \
    /tmp/internal/configs/version2/nginx$PLUS.transportserver.tmpl \
    /

chown -R 101:0 /etc/nginx /var/cache/nginx /var/lib/nginx /var/log/nginx /*.tmpl
chmod -R g=u /etc/nginx /var/cache/nginx /var/lib/nginx /var/log/nginx /*.tmpl
rm -f /etc/nginx/conf.d/*

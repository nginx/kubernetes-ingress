#!/bin/sh

set -e

for i in /etc/nginx/waf/nac-policies /etc/nginx/waf/nac-logconfs /etc/nginx/waf/nac-usersigs /etc/app_protect /usr/share/ts /var/log/app_protect/ /opt/app_protect/; do
    if [ ! -d ${i} ]; then
        mkdir -p ${i}
    fi
    chown -R 101:0 ${i}
    chmod -R g=u ${i}
done

touch /etc/nginx/waf/nac-usersigs/index.conf

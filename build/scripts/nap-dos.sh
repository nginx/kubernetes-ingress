#!/bin/sh

set -e

mkdir -p /root/app_protect_dos /etc/nginx/dos/policies /etc/nginx/dos/logconfs /etc/nginx/dos/allowlist /shared/cores /var/log/adm /var/run/adm
chmod 777 /shared/cores /var/log/adm /var/run/adm /etc/app_protect_dos

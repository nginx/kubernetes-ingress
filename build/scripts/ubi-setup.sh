#!/bin/sh

set -e

microdnf --nodocs install -y shadow-utils subscription-manager
groupadd --system --gid 101 nginx
useradd --system --gid nginx --no-create-home --home-dir /nonexistent --comment "nginx user" --shell /bin/false --uid 101 nginx
rpm --import /tmp/nginx_signing.key

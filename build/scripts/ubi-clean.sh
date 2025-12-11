#!/bin/sh

set -e

microdnf remove -y shadow-utils subscription-manager python3-requests python3-cloud-what python3-subscription-manager-rhsm python3-setuptools python3-inotify python3-requests python3-urllib3 python3-idna
microdnf clean all && rm -rf /var/cache/dnf

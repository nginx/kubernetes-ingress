#!/bin/sh

set -e

microdnf remove -y shadow-utils
microdnf clean all && rm -rf /var/cache/dnf

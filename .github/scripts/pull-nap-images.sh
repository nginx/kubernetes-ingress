#!/usr/bin/env bash

set -eo pipefail

VERSION=$1
DRY_RUN=${2:-false}
NGINX_REPO=private-registry.nginx.com/nap
DEV_REPO=gcr.io/f5-gcs-7899-ptg-ingrss-ctlr/nap

docker pull "${NGINX_REPO}"/waf-config-mgr:"${VERSION}"
docker pull "${NGINX_REPO}"/waf-enforcer:"${VERSION}"
docker pull "${NGINX_REPO}"/waf-compiler:"${VERSION}"

docker tag "${NGINX_REPO}"/waf-config-mgr:"${VERSION}" "${DEV_REPO}"/waf-config-mgr:"${VERSION}"
docker tag "${NGINX_REPO}"/waf-enforcer:"${VERSION}" "${DEV_REPO}"/waf-enforcer:"${VERSION}"
docker tag "${NGINX_REPO}"/waf-compiler:"${VERSION}" "${DEV_REPO}"/waf-compiler:"${VERSION}"

if [ "${DRY_RUN}" = true ]; then
    echo "Dry run enabled, not pushing images"
    exit 0
fi
docker push "${DEV_REPO}"/waf-config-mgr:"${VERSION}"
docker push "${DEV_REPO}"/waf-enforcer:"${VERSION}"
docker push "${DEV_REPO}"/waf-compiler:"${VERSION}"

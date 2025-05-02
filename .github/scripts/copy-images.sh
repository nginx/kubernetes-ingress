#!/usr/bin/env bash

set -eo pipefail

# shellcheck disable=SC2155
export ROOTDIR=$(git rev-parse --show-toplevel || echo ".")

SKOPEO_BIN=skopeo
if [ -n "$CI" ]; then
    SKOPEO_BIN="docker run --rm -v $HOME/.docker/config.json:/tmp/auth.json $(grep skopeo "${ROOTDIR}/tests/Dockerfile" | grep FROM | cut -d ' ' -f 2)"
fi

## Setup inputs

SOURCE_TAG=${SOURCE_TAG:-stable}
TARGET_TAG=${TARGET_TAG:-edge}
ADDITIONAL_TAG=${ADDITIONAL_TAG:-""}

SOURCE_REGISTRY=${1:-"gcr.io/f5-gcs-7899-ptg-ingrss-ctlr/dev"}
TARGET_REGISTRY=${2:-"gcr.io/f5-gcs-7899-ptg-ingrss-ctlr/release"}

REGISTRY_USERNAME=${REGISTRY_USERNAME:-""}
REGISTRY_PASSWORD=${REGISTRY_PASSWORD:-""}

PUBLISH_OSS=${PUBLISH_OSS:-true}
PUBLISH_PLUS=${PUBLISH_PLUS:-true}
PUBLISH_WAF=${PUBLISH_WAF:-true}
PUBLISH_DOS=${PUBLISH_DOS:-true}
PUBLISH_WAF_DOS=${PUBLISH_WAF_DOS:-true}

DRY_RUN=${DRY_RUN:-false}

SOURCE_OSS_IMAGE_PREFIX=${SOURCE_OSS_IMAGE_PREFIX:-"nginx-ic/nginx-ingress"}

TARGET_OSS_IMAGE_PREFIX=${TARGET_OSS_IMAGE_PREFIX:-"nginx-ic/nginx-ingress"}

SOURCE_PLUS_IMAGE_PREFIX=${SOURCE_PLUS_IMAGE_PREFIX:-"nginx-ic/nginx-plus-ingress"}
SOURCE_NAP_WAF_IMAGE_PREFIX=${SOURCE_NAP_WAF_IMAGE_PREFIX:-"nginx-ic-nap/nginx-plus-ingress"}
SOURCE_NAP_WAFV5_IMAGE_PREFIX=${SOURCE_NAP_WAFV5_IMAGE_PREFIX:-"nginx-ic-nap-v5/nginx-plus-ingress"}
SOURCE_NAP_DOS_IMAGE_PREFIX=${SOURCE_NAP_DOS_IMAGE_PREFIX:-"nginx-ic-dos/nginx-plus-ingress"}
SOURCE_NAP_WAF_DOS_IMAGE_PREFIX=${SOURCE_NAP_WAF_DOS_IMAGE_PREFIX:-"nginx-ic-dos-nap/nginx-plus-ingress"}

TARGET_PLUS_IMAGE_PREFIX=${TARGET_PLUS_IMAGE_PREFIX:-"nginx-ic/nginx-plus-ingress"}
TARGET_NAP_WAF_IMAGE_PREFIX=${TARGET_NAP_WAF_IMAGE_PREFIX:-"nginx-ic-nap/nginx-plus-ingress"}
TARGET_NAP_WAFV5_IMAGE_PREFIX=${TARGET_NAP_WAFV5_IMAGE_PREFIX:-"nginx-ic-nap-v5/nginx-plus-ingress"}
TARGET_NAP_DOS_IMAGE_PREFIX=${TARGET_NAP_DOS_IMAGE_PREFIX:-"nginx-ic-dos/nginx-plus-ingress"}
TARGET_NAP_WAF_DOS_IMAGE_PREFIX=${TARGET_NAP_WAF_DOS_IMAGE_PREFIX:-"nginx-ic-dos-nap/nginx-plus-ingress"}

declare -a OSS_TAG_POSTFIX_LIST=("" "-ubi" "-alpine")
declare -a PLUS_TAG_POSTFIX_LIST=("" "-ubi" "-alpine" "-alpine-fips")
declare -a NAP_WAF_TAG_POSTFIX_LIST=("" "-ubi" "-alpine-fips")
declare -a NAP_WAFV5_TAG_POSTFIX_LIST=("" "-ubi" "-alpine-fips")
declare -a NAP_DOS_TAG_POSTFIX_LIST=("" "-ubi")
declare -a NAP_WAF_DOS_TAG_POSTFIX_LIST=("" "-ubi")

CONFIG_PATH=${CONFIG_PATH:-~/.nic-release/config}
if [ -f "$CONFIG_PATH" ]; then
    # shellcheck source=/dev/null
    . "$CONFIG_PATH"
fi

SOURCE_OPTS=${SOURCE_OPTS:-""}
if [[ $SOURCE_REGISTRY =~ mgmt ]] || [[ $SOURCE_REGISTRY =~ private ]] ; then
    if [ "${CI}" != 'true' ]; then
        SOURCE_OPTS="--src-username ${REGISTRY_USERNAME} --src-password ${REGISTRY_PASSWORD}"
    fi
fi

TARGET_OPTS=${TARGET_OPTS:-""}
if [[ $TARGET_REGISTRY =~ mgmt ]]; then
    if [ "${CI}" != 'true' ]; then
        TARGET_OPTS="--dest-username ${REGISTRY_USERNAME} --dest-password ${REGISTRY_PASSWORD}"
    fi
fi

# cannot push the same tag twice
IS_IMMUTABLE=false
if [[ $TARGET_REGISTRY =~ 709825985650.dkr.ecr ]]; then
    IS_IMMUTABLE=true
fi

ARCH_OPTS="-a"
if [[ $TARGET_REGISTRY =~ f5-7626-networks-public ]] || [[ $TARGET_REGISTRY =~ nginxmktpl ]]; then
    ARCH_OPTS="--override-os linux --override-arch amd64"
fi

## Main publish loops

if $PUBLISH_OSS; then
    for postfix in "${OSS_TAG_POSTFIX_LIST[@]}"; do
        image=${SOURCE_REGISTRY}/${SOURCE_OSS_IMAGE_PREFIX}:${SOURCE_TAG}${postfix}
        echo "Processing image ${image}"
        new_tag=${TARGET_REGISTRY}/${TARGET_OSS_IMAGE_PREFIX}:${TARGET_TAG}${postfix}
        echo "  Pushing image OSS ${new_tag}..."
        if ! $DRY_RUN; then
            ${SKOPEO_BIN} copy --retry-times 5 ${ARCH_OPTS} ${SOURCE_OPTS} ${TARGET_OPTS} docker://${image} docker://${new_tag}
        fi
    done
else
    echo "Skipping Publish OSS flow"
fi

if $PUBLISH_PLUS; then
    for postfix in "${PLUS_TAG_POSTFIX_LIST[@]}"; do
        image=${SOURCE_REGISTRY}/${SOURCE_PLUS_IMAGE_PREFIX}:${SOURCE_TAG}${postfix}
        echo "Processing image ${image}"
        new_tag=${TARGET_REGISTRY}/${TARGET_PLUS_IMAGE_PREFIX}:${TARGET_TAG}${postfix}
        if $IS_IMMUTABLE && ${SKOPEO_BIN} --override-os linux --override-arch amd64 inspect docker://${new_tag} > /dev/null 2>&1; then
            echo "  ECR is immutable & tag ${new_tag} already exists, skipping."
        else
            echo "  Pushing image Plus ${new_tag}..."
            if ! $DRY_RUN; then
                ${SKOPEO_BIN} copy --retry-times 5 ${ARCH_OPTS} ${SOURCE_OPTS} ${TARGET_OPTS} docker://${image} docker://${new_tag}
            fi
        fi
    done
else
    echo "Skipping Publish Plus flow"
fi

if $PUBLISH_WAF; then
    for postfix in "${NAP_WAF_TAG_POSTFIX_LIST[@]}"; do
        image=${SOURCE_REGISTRY}/${SOURCE_NAP_WAF_IMAGE_PREFIX}:${SOURCE_TAG}${postfix}
        echo "Processing image ${image}"
        new_tag=${TARGET_REGISTRY}/${TARGET_NAP_WAF_IMAGE_PREFIX}:${TARGET_TAG}${postfix}
        if $IS_IMMUTABLE && ${SKOPEO_BIN} --override-os linux --override-arch amd64 inspect docker://${new_tag} > /dev/null 2>&1; then
            echo "  ECR is immutable & tag ${new_tag} already exists, skipping."
        else
            echo "  Pushing image NAP WAF ${new_tag}..."
            if ! $DRY_RUN; then
                ${SKOPEO_BIN} copy --retry-times 5 ${ARCH_OPTS} ${SOURCE_OPTS} ${TARGET_OPTS} docker://${image} docker://${new_tag}
            fi
        fi
    done
    for postfix in "${NAP_WAFV5_TAG_POSTFIX_LIST[@]}"; do
        image=${SOURCE_REGISTRY}/${SOURCE_NAP_WAFV5_IMAGE_PREFIX}:${SOURCE_TAG}${postfix}
        echo "Processing image ${image}"
        new_tag=${TARGET_REGISTRY}/${TARGET_NAP_WAFV5_IMAGE_PREFIX}:${TARGET_TAG}${postfix}
        if $IS_IMMUTABLE && ${SKOPEO_BIN} --override-os linux --override-arch amd64 inspect docker://${new_tag} > /dev/null 2>&1; then
            echo "  ECR is immutable & tag ${new_tag} already exists, skipping."
        else
            echo "  Pushing image NAP WAFV5 ${new_tag}..."
            if ! $DRY_RUN; then
                ${SKOPEO_BIN} copy --retry-times 5 ${ARCH_OPTS} ${SOURCE_OPTS} ${TARGET_OPTS} docker://${image} docker://${new_tag}
            fi
        fi
    done
else
    echo "Skipping Publish Plus WAF flow"
fi

if $PUBLISH_DOS; then
    for postfix in "${NAP_DOS_TAG_POSTFIX_LIST[@]}"; do
        image=${SOURCE_REGISTRY}/${SOURCE_NAP_DOS_IMAGE_PREFIX}:${SOURCE_TAG}${postfix}
        echo "Processing image ${image}"
        new_tag=${TARGET_REGISTRY}/${TARGET_NAP_DOS_IMAGE_PREFIX}:${TARGET_TAG}${postfix}
        if $IS_IMMUTABLE && ${SKOPEO_BIN} --override-os linux --override-arch amd64 inspect docker://${new_tag} > /dev/null 2>&1; then
            echo "  ECR is immutable & tag ${new_tag} already exists, skipping."
        else
            echo "  Pushing image NAP DOS ${new_tag}..."
            if ! $DRY_RUN; then
                ${SKOPEO_BIN} copy --retry-times 5 ${ARCH_OPTS} ${SOURCE_OPTS} ${TARGET_OPTS} docker://${image} docker://${new_tag}
            fi
        fi
    done
else
    echo "Skipping Publish Plus DOS flow"
fi

if $PUBLISH_WAF_DOS; then
    for postfix in "${NAP_WAF_DOS_TAG_POSTFIX_LIST[@]}"; do
        image=${SOURCE_REGISTRY}/${SOURCE_NAP_WAF_DOS_IMAGE_PREFIX}:${SOURCE_TAG}${postfix}
        echo "Processing image ${image}"
        new_tag=${TARGET_REGISTRY}/${TARGET_NAP_WAF_DOS_IMAGE_PREFIX}:${TARGET_TAG}${postfix}
        if $IS_IMMUTABLE && ${SKOPEO_BIN} --override-os linux --override-arch amd64 inspect docker://${new_tag} > /dev/null 2>&1; then
            echo "  ECR is immutable & tag ${new_tag} already exists, skipping."
        else
            echo "  Pushing image NAP WAF/DOS ${new_tag}..."
            if ! $DRY_RUN; then
                ${SKOPEO_BIN} copy --retry-times 5 ${ARCH_OPTS} ${SOURCE_OPTS} ${TARGET_OPTS} docker://${image} docker://${new_tag}
            fi
        fi
    done
else
    echo "Skipping Publish Plus WAF/DOS flow"
fi

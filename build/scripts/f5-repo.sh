#!/bin/sh
# Routes OS package repos through the F5 Artifactory mirror for the duration of one RUN step.
#   f5-repo.sh setup               point OS repos at Artifactory; safe to re-run once new repo files appear
#   f5-repo.sh restore             put the original repo files back, so credentials never reach an image layer
#   f5-repo.sh fetch <url> <dest>  download a file, via Artifactory when it is mirrored there
# Needs F5_REPO_USER, F5_REPO_TOKEN, F5_REPO_HOST and the F5_*_REPO keys (set in the Makefile or CI variables).
# Everything falls back to the public sources when F5_REPO_TOKEN is empty.

set -e

BAK=/tmp/f5-repo   # originals live in ${BAK}/files, files created by setup are listed in ${BAK}/created

# stop with a clear message when a required setting is empty: require NAME "${NAME}"
require() {
    if [ -z "$2" ]; then
        echo "f5-repo: $1 must be set" >&2
        exit 1
    fi
}

# escape characters that are special in a sed replacement or append text
esc() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }

# keep the original of a file once; returns 1 when the file is missing or was already backed up
backup() {
    [ -f "$1" ] && [ ! -f "${BAK}/files$1" ] || return 1
    mkdir -p "${BAK}/files$(dirname "$1")" && cp -p "$1" "${BAK}/files$1"
}

# remember a file that setup creates, so restore can delete it
track() {
    mkdir -p "${BAK}" "$(dirname "$1")"
    echo "$1" >> "${BAK}/created"
}

# say what was routed where (never the credentials), so the build log shows Artifactory is in use
log() { echo "f5-repo: $*" >&2; }

# dnf repo files: add the credentials after every baseurl
creds() {
    sed -i "/^baseurl *=/a username=$(esc "${F5_REPO_USER}")\npassword=$(esc "${F5_REPO_TOKEN}")" "$1"
}

setup_alpine() {
    require F5_REPO_USER "${F5_REPO_USER}"
    require F5_REPO_HOST "${F5_REPO_HOST}"
    require F5_ALPINE_REPO "${F5_ALPINE_REPO}"
    backup /etc/apk/repositories || return 0
    # '@' in the user name (e.g. an email) must be percent-encoded inside a URL
    user=$(printf '%s' "${F5_REPO_USER}" | sed 's/@/%40/g')
    url=$(esc "https://${user}:${F5_REPO_TOKEN}@${F5_REPO_HOST}/artifactory/${F5_ALPINE_REPO}/")
    sed -i "s|https\?://dl-cdn.alpinelinux.org/alpine/|${url}|" /etc/apk/repositories
    log "/etc/apk/repositories -> https://${F5_REPO_HOST}/artifactory/${F5_ALPINE_REPO}/"
}

setup_debian() {
    require F5_REPO_USER "${F5_REPO_USER}"
    require F5_REPO_HOST "${F5_REPO_HOST}"
    require F5_DEBIAN_REPO "${F5_DEBIAN_REPO}"
    require F5_DEBIAN_SECURITY_REPO "${F5_DEBIAN_SECURITY_REPO}"
    f=/etc/apt/sources.list.d/debian.sources
    backup "$f" || return 0
    base="https://${F5_REPO_HOST}/artifactory"
    security="${base}/${F5_DEBIAN_SECURITY_REPO}"
    cat > "$f" <<EOF
Types: deb
URIs: ${base}/${F5_DEBIAN_REPO}
Suites: ${VERSION_CODENAME} ${VERSION_CODENAME}-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp

Types: deb
URIs: ${security}
Suites: ${VERSION_CODENAME}-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp
EOF
    log "${f}: main/updates -> ${base}/${F5_DEBIAN_REPO}, security -> ${security}"
    # apt matches credentials on the exact host name; the file is deleted by restore
    track /etc/apt/auth.conf.d/f5-auth.conf
    printf 'machine %s\nlogin %s\npassword %s\n' "${F5_REPO_HOST}" "${F5_REPO_USER}" "${F5_REPO_TOKEN}" > /etc/apt/auth.conf.d/f5-auth.conf
    # apt-get update only warns when a repo is unreachable, so fail there instead of at install with "Unable to locate package"
    track /etc/apt/apt.conf.d/99f5
    printf 'APT::Update::Error-Mode "any";\n' > /etc/apt/apt.conf.d/99f5
    # slim images have no CA bundle before ca-certificates is installed; the Dockerfile mounts one at /tmp/ca.crt
    if [ -f /tmp/ca.crt ]; then
        printf 'Acquire::https::%s::CaInfo "/tmp/ca.crt";\n' "${F5_REPO_HOST}" >> /etc/apt/apt.conf.d/99f5
    fi
}

setup_rhel() {
    require F5_REPO_USER "${F5_REPO_USER}"
    require F5_REPO_HOST "${F5_REPO_HOST}"
    require F5_UBI_REPO "${F5_UBI_REPO}"
    f=/etc/yum.repos.d/ubi.repo
    if backup "$f"; then
        sed -i "s|https://cdn-ubi.redhat.com/|https://${F5_REPO_HOST}/artifactory/${F5_UBI_REPO}/|" "$f"
        creds "$f"
        log "${f} -> https://${F5_REPO_HOST}/artifactory/${F5_UBI_REPO}/"
    fi

    # epel.repo only exists once epel-release is installed, so setup is called again after that
    f=/etc/yum.repos.d/epel.repo
    if backup "$f"; then
        require F5_EPEL_REPO "${F5_EPEL_REPO}"
        sed -i -e 's|^metalink *=|#metalink=|' \
            -e "s|^#baseurl *= *https://download.example/pub/epel/|baseurl=https://${F5_REPO_HOST}/artifactory/${F5_EPEL_REPO}/|" "$f"
        creds "$f"
        log "${f} -> https://${F5_REPO_HOST}/artifactory/${F5_EPEL_REPO}/"
    fi

    # shortcut: codecs.fedoraproject.org has no Artifactory mirror, so disable the repo during the build, until one exists
    f=/etc/yum.repos.d/epel-cisco-openh264.repo
    if backup "$f"; then
        sed -i 's/^enabled *= *1/enabled=0/' "$f"
        log "${f}: disabled during the build"
    fi
}

restore() {
    [ -d "${BAK}" ] || return 0
    if [ -f "${BAK}/created" ]; then
        xargs rm -f < "${BAK}/created"
    fi
    if [ -d "${BAK}/files" ]; then
        (cd "${BAK}/files" && find . -type f) | while read -r f; do
            mv "${BAK}/files/${f#./}" "/${f#./}"
        done
    fi
    rm -rf "${BAK}"
}

fetch() {
    epel=https://dl.fedoraproject.org/pub/epel/
    if [ -n "${F5_REPO_TOKEN}" ] && [ "${1#"${epel}"}" != "$1" ]; then
        require F5_REPO_USER "${F5_REPO_USER}"
        require F5_REPO_HOST "${F5_REPO_HOST}"
        require F5_FEDORA_REPO "${F5_FEDORA_REPO}"
        log "fetching ${1#"${epel}"} from https://${F5_REPO_HOST}/artifactory/${F5_FEDORA_REPO}/"
        curl -fsSL -u "${F5_REPO_USER}:${F5_REPO_TOKEN}" -o "$2" \
            "https://${F5_REPO_HOST}/artifactory/${F5_FEDORA_REPO}/${1#"${epel}"}"
    else
        curl -fsSL -o "$2" "$1"
    fi
}

case "$1" in
    fetch) fetch "$2" "$3" ;;
    setup | restore)
        if [ -z "${F5_REPO_TOKEN}" ]; then
            [ "$1" = setup ] && log "no F5_REPO_TOKEN, using the public repos"
            exit 0
        fi
        . /etc/os-release
        case "$1:${ID}" in
            setup:alpine) setup_alpine ;;
            setup:debian) setup_debian ;;
            setup:rhel) setup_rhel ;;
            restore:*) restore ;;
            setup:*) ;;
        esac
        ;;
    *) echo "usage: $0 setup|restore|fetch <url> <dest>" >&2; exit 1 ;;
esac

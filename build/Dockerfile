# syntax=docker/dockerfile:1.23
#
# Build chain reference -- trace any make target to its stage chain:
#
#   make debian-image              → local ← common ← debian              ← nginx:1.29.8 (Debian)
#   make alpine-image              → local ← common ← alpine              ← nginx:1.29.8-alpine3.23
#   make ubi-image                 → local ← common ← ubi                 ← ubi-minimal ← redhat/ubi9-minimal
#   make debian-image-plus         → local ← common ← debian-plus         ← debian-plus-only ← debian:12-slim
#   make alpine-image-plus         → local ← common ← alpine-plus         ← alpine:3.22
#   make alpine-image-plus-fips    → local ← common ← alpine-plus-fips    ← alpine-plus ← alpine:3.22
#   make alpine-image-nap-plus-fips    → local ← common ← alpine-plus-nap-fips    ← alpine:3.22
#   make alpine-image-nap-v5-plus-fips → local ← common ← alpine-plus-nap-v5-fips ← alpine:3.22
#   make debian-image-nap-plus     → local ← common ← debian-plus-nap     ← debian-plus-only ← debian:12-slim
#   make debian-image-nap-v5-plus  → local ← common ← debian-plus-nap-v5  ← debian-plus-only ← debian:12-slim
#   make debian-image-dos-plus     → local ← common ← debian-plus-nap (NAP_MODULES=dos)
#   make debian-image-nap-dos-plus → local ← common ← debian-plus-nap (NAP_MODULES=waf,dos)
#   make ubi-image-plus            → local ← common ← ubi-9-plus          ← ubi-minimal
#   make ubi-image-nap-plus        → local ← common ← ubi-9-plus-nap      ← ubi-minimal
#   make ubi-image-nap-v5-plus     → local ← common ← ubi-9-plus-nap-v5   ← ubi-minimal
#   make ubi-image-dos-plus        → local ← common ← ubi-9-plus-nap (NAP_MODULES=dos)
#   make ubi-image-nap-dos-plus    → local ← common ← ubi-9-plus-nap (NAP_MODULES=waf,dos)
#   make ubi8-image-nap-plus       → local ← common ← ubi-8-plus-nap      ← redhat/ubi8
#   make ubi8-image-nap-v5-plus    → local ← common ← ubi-8-plus-nap-v5   ← redhat/ubi8
#
# How it works:
#   1. --build-arg BUILD_OS=<stage> selects which OS base stage feeds into "common"
#   2. --target <stage> selects which final target to build (local, container, goreleaser, etc.)
#   3. Prebuilt CI targets live in build/Dockerfile.prebuilt (separate file, no shared stages)
#

ARG BUILD_OS=debian
# renovate: datasource=docker depName=nginx/nginx
ARG NGINX_OSS_VERSION=1.29.8
ARG NGINX_PLUS_VERSION=R36
ARG NAP_WAF_VERSION=36+5.607
ARG NAP_WAF_COMMON_VERSION=11.644
ARG NAP_WAF_PLUGIN_VERSION=6.28
ARG NGINX_AGENT_VERSION=3.9
ARG NAP_AGENT_VERSION=2
ARG DOWNLOAD_TAG=edge
ARG DEBIAN_FRONTEND=noninteractive
ARG IMAGE_NAME=nginx/nginx-ingress
ARG PACKAGE_REPO=pkgs.nginx.com


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1: DEPENDENCY STAGES (never built directly)
#
# Provide libraries, keys, and tools to other stages via --mount=type=bind.
# ══════════════════════════════════════════════════════════════════════════════

FROM ghcr.io/nginx/dependencies/nginx-ubi:ubi8@sha256:9defd802c1f654946b7a5bf600de9061c312ce3671860e8ec6ac55cab45edb19 AS ubi8-packages
FROM ghcr.io/nginx/dependencies/nginx-ubi:ubi9@sha256:e34a86f1d78676b28e204449ef150816d72ba74db7945d44069026e6e3e7714c AS ubi9-packages
FROM ghcr.io/nginx/alpine-fips:0.5.0-alpine3.22@sha256:f907d7541ab03453fd7d630dc0fb8d9a819717ea52a7956fe1f45b9833051177 AS alpine-fips-3.22
FROM redhat/ubi9-minimal:9.7-1778072020@sha256:b9b10f42d7eba7ad4a6d5ef26b7d34fdc892b2ffe59b8d0372ec884008569eb6 AS ubi-minimal
FROM golang:1.26.3-alpine@sha256:3a8f055e02fce9585d5e4ab5135d57f2e1a947a16e2a7e6a71a78e770c169e9b AS golang-builder


# ── nginx-files: signing keys, repo configs, build scripts ──
FROM scratch AS nginx-files
ARG IC_VERSION
ARG BUILD_OS
ARG NGINX_PLUS_VERSION
ARG PACKAGE_REPO

# the following links can be replaced with local files if needed, i.e. ADD --chown=101:0 <local_file> <container_file>
ADD --link --chown=101:0 https://cs.nginx.com/static/files/90pkgs-nginx 90pkgs-nginx
ADD --link --chown=101:0 https://cs.nginx.com/static/keys/nginx_signing.key nginx_signing.key
ADD --link --chown=101:0 https://cs.nginx.com/static/keys/nginx_signing.rsa.pub nginx_signing.rsa.pub
ADD --link --chown=101:0 https://cs.nginx.com/static/keys/app-protect-security-updates.key app-protect-security-updates.key
ADD --link --chown=101:0 https://cs.nginx.com/static/keys/app-protect-security-updates.rsa.pub app-protect-security-updates.rsa.pub
ADD --link --chown=101:0 https://cs.nginx.com/static/files/nginx-plus-8.repo nginx-plus-8.repo
ADD --link --chown=101:0 https://cs.nginx.com/static/files/plus-9.repo nginx-plus-9.repo
ADD --link --chown=101:0 https://cs.nginx.com/static/files/app-protect-8.repo app-protect-8.repo
ADD --link --chown=101:0 https://cs.nginx.com/static/files/app-protect-9.repo app-protect-9.repo
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/nap-waf-v5-ubi-8.repo app-protect-v5-8.repo
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/nap-waf-v5-ubi-9.repo app-protect-v5-9.repo
ADD --link --chown=101:0 https://cs.nginx.com/static/files/app-protect-dos-9.repo app-protect-dos-9.repo
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/plus-debian-12.repo debian-plus-12.sources
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/nap-waf-debian-12.repo nap-waf-12.sources
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/nap-dos-debian-12.repo nap-dos-12.sources
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/nap-waf-v5-debian-12.repo nap-waf-v5-12.sources
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/agent-debian-12.repo debian-agent-12.sources
ADD --link --chown=101:0 https://cs.nginx.com/static/files/nginx-agent.repo nginx-agent.repo

RUN --mount=from=busybox:musl,src=/bin/,dst=/bin/ printf "%s\n" "Acquire::https::pkgs.nginx.com::User-Agent k8s-ic-$IC_VERSION${BUILD_OS##debian-plus}-apt;" >> 90pkgs-nginx \
	&& if ! grep -q "${PACKAGE_REPO}" 90pkgs-nginx ; then cat 90pkgs-nginx | sed -e "s/pkgs.nginx.com/${PACKAGE_REPO}/g" >> 90pkgs-nginx; fi \
	&& printf "%s\n" "user_agent=k8s-ic-$IC_VERSION${BUILD_OS##ubi*plus}-dnf" | tee -a nginx-plus-*.repo \
	&& sed -i -e "s;%VERSION%;${NGINX_PLUS_VERSION};g" -e "s;pkgs.nginx.com;${PACKAGE_REPO};g" -e "s;${PACKAGE_REPO}/app-protect-security-updates;pkgs.nginx.com/app-protect-security-updates;g" *.sources \
	&& sed -i -e "y/0/1/" app-protect-v5-*.repo \
	&& sed -i -e "y/0/1/" -e "1,8s;/centos;/${NGINX_PLUS_VERSION}/centos;" -e "s;pkgs.nginx.com;${PACKAGE_REPO};g" -e "s;${PACKAGE_REPO}/app-protect-security-updates;pkgs.nginx.com/app-protect-security-updates;g" nginx-plus-*.repo app-protect-?.repo app-protect-dos-9.repo \
	&& sed -i -e "y/0/1/" -e "s;pkgs.nginx.com;${PACKAGE_REPO};g" nginx-agent.repo app-protect-v5-?.repo \
	&& echo HTTP_USER_AGENT="k8s-ic-$IC_VERSION${BUILD_OS##alpine-plus}-apk" > user_agent

ADD --link --chown=101:0 --chmod=0755 https://raw.githubusercontent.com/nginx/k8s-common/main/files/patch-os.sh patch-os.sh
ADD --link --chown=101:0 --chmod=0755 build/scripts/common.sh common.sh
ADD --link --chown=101:0 --chmod=0755 build/scripts/nap-waf.sh nap-waf.sh
ADD --link --chown=101:0 --chmod=0755 build/scripts/nap-dos.sh nap-dos.sh
ADD --link --chown=101:0 --chmod=0755 build/scripts/agent.sh agent.sh
ADD --link --chown=101:0 --chmod=0755 build/scripts/ubi-setup.sh ubi-setup.sh
ADD --link --chown=101:0 --chmod=0755 build/scripts/ubi-clean.sh ubi-clean.sh

# Startup is non-deterministic between NGINX Plus reporting usage and licence reporter initialising. This
# is a workaround to attribute the installation to nic even if licence reporter isn't ready yet.
# @See https://github.com/nginx/kubernetes-ingress/issues/7360
ADD --link --chown=101:0 --chmod=0755 build/dependencies/tracking.info.default tracking.info


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2: OSS BASE IMAGES
#
# Install NGINX OSS + agent on a distro base.
# Used as BUILD_OS for: make debian-image, alpine-image, ubi-image
# ══════════════════════════════════════════════════════════════════════════════

# ── Alpine OSS ──                                         → make alpine-image
FROM nginx:1.29.8-alpine3.23@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de AS alpine
ARG PACKAGE_REPO
ARG NGINX_OSS_VERSION
ARG NGINX_AGENT_VERSION

RUN --mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=user_agent,target=/tmp/user_agent \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	apk add --no-cache libcap libstdc++ \
	&& export $(cat /tmp/user_agent) \
	&& printf "%s%s%s\n" "http://packages.nginx.org/nginx/mainline/alpine/v" `egrep -o '^[0-9]+\.[0-9]+' /etc/alpine-release` "/main" >> /etc/apk/repositories \
	&& printf "%s%s%s\n" "http://packages.nginx.org/nginx-agent/alpine/v" `egrep -o '^[0-9]+\.[0-9]+' /etc/alpine-release` "/main" >> /etc/apk/repositories \
	&& apk add --no-cache nginx-module-otel~${NGINX_OSS_VERSION} nginx-agent~${NGINX_AGENT_VERSION} \
	&& ldconfig /usr/local/lib/ \
	&& agent.sh \
	&& sed -i -e '/nginx.org/d' /etc/apk/repositories


# ── Debian OSS ──                                         → make debian-image
FROM nginx:1.29.8@sha256:6e23479198b998e5e25921dff8455837c7636a67111a04a635cf1bb363d199dc AS debian
ARG NGINX_OSS_VERSION
ARG NGINX_AGENT_VERSION

RUN --mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y \
	gpg libcap2-bin ca-certificates lsb-release debian-archive-keyring \
	&& gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg /tmp/nginx_signing.key \
	&& echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
	http://packages.nginx.org/nginx/mainline/debian `lsb_release -cs` nginx" > /etc/apt/sources.list.d/nginx.list \
    && echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://packages.nginx.org/nginx-agent/debian `lsb_release -cs` agent" >> /etc/apt/sources.list.d/nginx.list \
	&& printf "%s" "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" > /etc/apt/preferences.d/99nginx \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y \
	nginx-agent=${NGINX_AGENT_VERSION}* \
	nginx-module-otel=${NGINX_OSS_VERSION}* \
	&& apt-get purge --auto-remove -y gpg \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/preferences.d/99nginx /etc/apt/sources.list.d/nginx.list \
	&& agent.sh


# ── UBI OSS ──                                            → make ubi-image
FROM ubi-minimal AS ubi
ARG IC_VERSION
ARG NGINX_OSS_VERSION
ARG NGINX_AGENT_VERSION

LABEL name="NGINX Ingress Controller" \
	maintainer="kubernetes@nginx.com" \
	vendor="NGINX Inc" \
	version="${IC_VERSION}" \
	release="1" \
	summary="The Ingress Controller is an application that runs in a cluster and configures an HTTP load balancer according to Ingress resources." \
	description="The Ingress Controller is an application that runs in a cluster and configures an HTTP load balancer according to Ingress resources." \
	io.k8s.description="NGINX Ingress Controller is an application that runs in a cluster and configures an HTTP load balancer according to Ingress resources." \
	io.openshift.tags="nginx,ingress-controller,ingress,controller,kubernetes,openshift"

COPY --link --chown=101:0 LICENSE /licenses/

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=ubi-setup.sh,target=/usr/local/bin/ubi-setup.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
	--mount=type=bind,from=ubi9-packages,src=/,target=/ubi-bin/ \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	ubi-setup.sh \
	&& rpm -qa --queryformat "%{NAME}\n" | sort > pkgs-installed \
	&& microdnf --nodocs --setopt=install_weak_deps=0 install -y diffutils dnf \
	&& rpm -qa --queryformat "%{NAME}\n" | sort > pkgs-new \
	&& dnf install -y /ubi-bin/*.rpm \
	&& dnf -q repoquery --resolve --requires --recursive --whatrequires nginx --queryformat "%{NAME}" > pkgs-nginx \
	&& dnf --setopt=protected_packages= remove -y $(comm -13 pkgs-installed pkgs-new | comm -13 pkgs-nginx -) \
	&& rm pkgs-installed pkgs-new pkgs-nginx \
	&& printf "%s\n" "[nginx]" "name=nginx repo" \
	"baseurl=https://packages.nginx.org/nginx/mainline/centos/9/\$basearch/" \
	"gpgcheck=1" "enabled=1" "module_hotfixes=true" > /etc/yum.repos.d/nginx.repo \
    && printf "%s\n" "[agent]" "name=agent repo" \
    "baseurl=https://packages.nginx.org/nginx-agent/centos/9/\$basearch/" \
    "gpgcheck=1" "enabled=1" "module_hotfixes=true" >> /etc/yum.repos.d/nginx.repo \
	&& microdnf --nodocs install -y nginx-${NGINX_OSS_VERSION}* nginx-module-njs-${NGINX_OSS_VERSION}* nginx-module-otel-${NGINX_OSS_VERSION}* nginx-module-image-filter-${NGINX_OSS_VERSION}* nginx-module-xslt-${NGINX_OSS_VERSION}* nginx-agent-${NGINX_AGENT_VERSION}* \
	&& rm /etc/yum.repos.d/nginx.repo \
	&& ubi-clean.sh


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3: PLUS BASE IMAGES
#
# Install NGINX Plus + agent. Requires --secret for repo creds.
# Used as BUILD_OS for: make *-image-plus
# ══════════════════════════════════════════════════════════════════════════════

# ── Alpine Plus ──                                        → make alpine-image-plus
FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS alpine-plus
ARG NGINX_PLUS_VERSION
ARG PACKAGE_REPO
ARG NGINX_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/apk/cert.pem,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/apk/cert.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=user_agent,target=/tmp/user_agent \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	export $(cat /tmp/user_agent) \
	&& printf "%s\n" "https://${PACKAGE_REPO}/plus/${NGINX_PLUS_VERSION}/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& printf "%s\n" "https://${PACKAGE_REPO}/nginx-agent/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& apk add --no-cache nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check nginx-agent~${NGINX_AGENT_VERSION} libcap libcurl \
	&& mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& agent.sh \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories


# ── Alpine Plus + FIPS ──                                 → make alpine-image-plus-fips
FROM alpine-plus AS alpine-plus-fips
ARG NGINX_PLUS_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=bind,from=alpine-fips-3.22,target=/tmp/fips/ \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /usr/ssl \
	&& cp -av /tmp/fips/usr/lib/ossl-modules/fips.so /usr/lib/ossl-modules/fips.so \
	&& cp -av /tmp/fips/usr/ssl/fipsmodule.cnf /usr/ssl/fipsmodule.cnf \
	&& cp -av /tmp/fips/etc/ssl/openssl.cnf /etc/ssl/openssl.cnf \
	&& cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info


# ── Debian Plus (intermediate: no agent) ──               (not built directly)
FROM debian:12-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252 AS debian-plus-only
ARG NGINX_PLUS_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=app-protect-security-updates.key,target=/tmp/app-protect-security-updates.key \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=debian-plus-12.sources,target=/tmp/nginx-plus.sources \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y gpg ca-certificates libcap2-bin libcurl4 \
	&& groupadd --system --gid 101 nginx \
	&& useradd --system --gid nginx --no-create-home --home-dir /nonexistent --comment "nginx user" --shell /bin/false --uid 101 nginx \
	&& gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg /tmp/nginx_signing.key \
	&& gpg --dearmor -o /usr/share/keyrings/app-protect-archive-keyring.gpg /tmp/app-protect-security-updates.key \
	&& cp /tmp/nginx-plus.sources /etc/apt/sources.list.d/nginx-plus.sources \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check \
	&& apt-get purge --auto-remove -y gpg \
	&& mkdir -p /etc/nginx/reporting/ \
	&& cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx-plus.sources


# ── Debian Plus ──                                        → make debian-image-plus
FROM debian-plus-only AS debian-plus
ARG NGINX_PLUS_VERSION
ARG NGINX_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=debian-agent-12.sources,target=/tmp/nginx-agent.sources \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	apt-get update \
	&& cp /tmp/nginx-agent.sources /etc/apt/sources.list.d/nginx-agent.sources \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y nginx-agent=${NGINX_AGENT_VERSION}* \
	&& agent.sh \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx-agent.sources


# ── UBI9 Plus ──                                          → make ubi-image-plus
FROM ubi-minimal AS ubi-9-plus
ARG NGINX_PLUS_VERSION
ARG NGINX_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-9.repo,target=/etc/yum.repos.d/nginx-plus.repo \
	--mount=type=bind,from=nginx-files,src=ubi-setup.sh,target=/usr/local/bin/ubi-setup.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	--mount=type=bind,from=ubi9-packages,src=/,target=/ubi-bin/ \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ubi-setup.sh \
	&& rpm -Uvh /ubi-bin/c-ares-*.rpm \
	&& microdnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check nginx-agent-${NGINX_AGENT_VERSION}.* \
	&& agent.sh	\
	&& ubi-clean.sh


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4: NAP BASE IMAGES
#
# Add App Protect WAF/DoS/WAFv5 on top of Plus.
# Used as BUILD_OS for: make *-image-nap-*, *-image-dos-*
# ══════════════════════════════════════════════════════════════════════════════

# ── Alpine Plus + NAP WAF + FIPS ──                       → make alpine-image-nap-plus-fips
FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS alpine-plus-nap-fips
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION
ARG PACKAGE_REPO
ARG NAP_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=bind,from=alpine-fips-3.22,target=/tmp/fips/ \
	--mount=type=secret,id=nginx-repo.crt,dst=/etc/apk/cert.pem,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/apk/cert.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=app-protect-security-updates.rsa.pub,target=/etc/apk/keys/app-protect-security-updates.rsa.pub \
	--mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	printf "%s\n" "https://${PACKAGE_REPO}/plus/${NGINX_PLUS_VERSION}/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& printf "%s\n" "https://${PACKAGE_REPO}/app-protect/${NGINX_PLUS_VERSION}/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& printf "%s\n" "https://pkgs.nginx.com/app-protect-security-updates/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& printf "%s\n" "https://${PACKAGE_REPO}/nginx-agent/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& apk add --no-cache libcap-utils libcurl nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check \
	&& apk add --no-cache nginx-agent~${NAP_AGENT_VERSION} \
	&& mkdir -p /usr/ssl \
	&& cp -av /tmp/fips/usr/lib/ossl-modules/fips.so /usr/lib/ossl-modules/fips.so \
	&& cp -av /tmp/fips/usr/ssl/fipsmodule.cnf /usr/ssl/fipsmodule.cnf \
	&& cp -av /tmp/fips/etc/ssl/openssl.cnf /etc/ssl/openssl.cnf \
	&& mkdir -p /etc/nginx/reporting/ \
	&& cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& apk add --no-cache app-protect~=${NAP_WAF_VERSION/+/.} \
      app-protect-ip-intelligence \
      app-protect-attack-signatures \
      app-protect-threat-campaigns \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories \
	&& nap-waf.sh \
	agent.sh


# ── Alpine Plus + NAP WAFv5 + FIPS ──                     → make alpine-image-nap-v5-plus-fips
FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS alpine-plus-nap-v5-fips
ARG NGINX_PLUS_VERSION
ARG PACKAGE_REPO
ARG NAP_WAF_VERSION
ARG NAP_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=bind,from=alpine-fips-3.22,target=/tmp/fips/ \
	--mount=type=secret,id=nginx-repo.crt,dst=/etc/apk/cert.pem,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/apk/cert.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	printf "%s\n" "https://${PACKAGE_REPO}/plus/${NGINX_PLUS_VERSION}/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& printf "%s\n" "https://${PACKAGE_REPO}/app-protect-x-plus/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& printf "%s\n" "https://${PACKAGE_REPO}/nginx-agent/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& apk add --no-cache libcap-utils libcurl nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check \
	&& apk add --no-cache nginx-agent~${NAP_AGENT_VERSION} \
	&& mkdir -p /usr/ssl \
	&& cp -av /tmp/fips/usr/lib/ossl-modules/fips.so /usr/lib/ossl-modules/fips.so \
	&& cp -av /tmp/fips/usr/ssl/fipsmodule.cnf /usr/ssl/fipsmodule.cnf \
	&& cp -av /tmp/fips/etc/ssl/openssl.cnf /etc/ssl/openssl.cnf \
	&& mkdir -p /etc/nginx/reporting/ \
	&& cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& apk add --no-cache app-protect-module-plus~=${NAP_WAF_VERSION/+/.} \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories \
	&& nap-waf.sh \
	agent.sh


# ── Debian Plus + NAP WAF/DoS ──                          → make debian-image-nap-plus, debian-image-dos-plus, debian-image-nap-dos-plus
FROM debian-plus-only AS debian-plus-nap
ARG NAP_MODULES
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION
ARG NAP_WAF_COMMON_VERSION
ARG NAP_WAF_PLUGIN_VERSION
ARG NAP_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=nap-waf-12.sources,target=/tmp/app-protect.sources \
	--mount=type=bind,from=nginx-files,src=nap-dos-12.sources,target=/tmp/app-protect-dos.sources \
	--mount=type=bind,from=nginx-files,src=debian-agent-12.sources,target=/tmp/nginx-agent.sources \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=nap-dos.sh,target=/usr/local/bin/nap-dos.sh \
	if [ -z "${NAP_MODULES##*waf*}" ]; then \
	cp /tmp/app-protect.sources /etc/apt/sources.list.d/app-protect.sources \
	&& cp /tmp/nginx-agent.sources /etc/apt/sources.list.d/nginx-agent.sources \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y app-protect=${NAP_WAF_VERSION}* \
	nginx-plus-module-appprotect=${NAP_WAF_VERSION}* \
	app-protect-engine=${NAP_WAF_COMMON_VERSION}* \
	app-protect-common=${NAP_WAF_COMMON_VERSION}* \
	app-protect-compiler=${NAP_WAF_COMMON_VERSION}* \
	app-protect-plugin=${NAP_WAF_PLUGIN_VERSION}* \
	app-protect-ip-intelligence \
	app-protect-attack-signatures \
	app-protect-threat-campaigns \
	nginx-agent=${NAP_AGENT_VERSION}.* \
	&& rm -f /etc/apt/sources.list.d/app-protect.sources /etc/apt/sources.list.d/nginx-agent.sources \
	&& nap-waf.sh \
	&& agent.sh; \
	fi \
	&& if [ -z "${NAP_MODULES##*dos*}" ]; then \
	cp /tmp/app-protect-dos.sources /etc/apt/sources.list.d/app-protect-dos.sources \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y app-protect-dos \
	&& rm -f /etc/apt/sources.list.d/app-protect-dos.sources \
	&& nap-dos.sh; \
	fi \
	&& rm -rf /var/lib/apt/lists/*


# ── Debian Plus + NAP WAFv5 ──                            → make debian-image-nap-v5-plus
FROM debian-plus-only AS debian-plus-nap-v5
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION
ARG NAP_WAF_PLUGIN_VERSION
ARG NAP_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=nap-waf-v5-12.sources,target=/etc/apt/sources.list.d/app-protect.sources \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=debian-agent-12.sources,target=/etc/apt/sources.list.d/nginx-agent.sources \
	apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y nginx-agent=${NAP_AGENT_VERSION}.* app-protect-module-plus=${NAP_WAF_VERSION}* nginx-plus-module-appprotect=${NAP_WAF_VERSION}* app-protect-plugin=${NAP_WAF_PLUGIN_VERSION}* \
	&& nap-waf.sh \
	&& agent.sh


# ── UBI9 Plus + NAP WAF/DoS ──                            → make ubi-image-nap-plus, ubi-image-dos-plus, ubi-image-nap-dos-plus
FROM ubi-minimal AS ubi-9-plus-nap
ARG NAP_MODULES
ARG BUILD_OS
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION
ARG NAP_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=secret,id=rhel_license,dst=/tmp/rhel_license,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-9.repo,target=/etc/yum.repos.d/nginx-plus.repo \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=app-protect-security-updates.key,target=/tmp/app-protect-security-updates.key \
	--mount=type=bind,from=nginx-files,src=app-protect-9.repo,target=/tmp/app-protect-9.repo \
	--mount=type=bind,from=nginx-files,src=app-protect-dos-9.repo,target=/tmp/app-protect-dos-9.repo \
	--mount=type=bind,from=nginx-files,src=ubi-setup.sh,target=/usr/local/bin/ubi-setup.sh \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=nap-dos.sh,target=/usr/local/bin/nap-dos.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
    --mount=type=bind,from=ubi9-packages,src=/,target=/ubi-bin/ \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ubi-setup.sh \
    && rpm -Uvh /ubi-bin/c-ares-*.rpm \
	&& microdnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-fips-check nginx-plus-module-otel nginx-agent-${NAP_AGENT_VERSION}.* \
	&& source /tmp/rhel_license \
	&& microdnf --nodocs install -y ca-certificates shadow-utils subscription-manager \
	&& rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm \
	&& subscription-manager register --org=${RHEL_ORGANIZATION} --activationkey=${RHEL_ACTIVATION_KEY} --name ${BUILD_OS}-$(uname -m) || true \
	&& subscription-manager attach \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	rpm --import /tmp/app-protect-security-updates.key \
	&& cp /tmp/app-protect-9.repo /etc/yum.repos.d/app-protect-9.repo \
	&& microdnf --enablerepo=codeready-builder-for-rhel-9-x86_64-rpms --nodocs install -y \
	app-protect-${NAP_WAF_VERSION}* \
	app-protect-ip-intelligence \
	app-protect-attack-signatures \
    app-protect-threat-campaigns \
	&& rm -f /etc/yum.repos.d/app-protect-9.repo \
	&& nap-waf.sh \
	&& agent.sh; \
	fi \
	&& if [ -z "${NAP_MODULES##*dos*}" ]; then \
	cp /tmp/app-protect-dos-9.repo /etc/yum.repos.d/app-protect-dos-9.repo \
	&& microdnf --nodocs install -y app-protect-dos \
	&& rm -f /etc/yum.repos.d/app-protect-dos-9.repo \
	&& nap-dos.sh; \
	fi \
	&& subscription-manager unregister \
	&& ubi-clean.sh


# ── UBI9 Plus + NAP WAFv5 ──                              → make ubi-image-nap-v5-plus
FROM ubi-minimal AS ubi-9-plus-nap-v5
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION
ARG NAP_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=secret,id=rhel_license,dst=/tmp/rhel_license,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-9.repo,target=/etc/yum.repos.d/nginx-plus.repo \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=app-protect-v5-9.repo,target=/etc/yum.repos.d/app-protect-9.repo \
	--mount=type=bind,from=nginx-files,src=ubi-setup.sh,target=/usr/local/bin/ubi-setup.sh \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
	--mount=type=bind,from=ubi9-packages,src=/,target=/ubi-bin/ \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ubi-setup.sh \
	&& microdnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-fips-check \
	&& source /tmp/rhel_license \
	&& rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm \
	&& rpm -Uvh /ubi-bin/c-ares-*.rpm \
	&& microdnf --nodocs install -y ca-certificates shadow-utils subscription-manager \
	&& microdnf --nodocs install -y nginx-plus-module-otel nginx-agent-${NAP_AGENT_VERSION}.* app-protect-module-plus-${NAP_WAF_VERSION}* \
	&& nap-waf.sh \
	&& ubi-clean.sh \
	&& agent.sh


# ── UBI8 Plus + NAP WAF ──                                → make ubi8-image-nap-plus
FROM redhat/ubi8@sha256:8f757bfe94700eee7d26c885cd16bf3ae9923edf38f984ef3da50d2ce937fc5e AS ubi-8-plus-nap
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION
ARG BUILD_OS
ARG NAP_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=secret,id=rhel_license,dst=/tmp/rhel_license,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-8.repo,target=/etc/yum.repos.d/nginx-plus.repo,rw \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=app-protect-security-updates.key,target=/tmp/app-protect-security-updates.key \
	--mount=type=bind,from=nginx-files,src=app-protect-8.repo,target=/etc/yum.repos.d/app-protect-8.repo \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	--mount=type=bind,from=ubi8-packages,src=/,target=/ubi-bin/ \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& source /tmp/rhel_license \
	&& groupadd --system --gid 101 nginx \
	&& useradd --system --gid nginx --no-create-home --home-dir /nonexistent --comment "nginx user" --shell /bin/false --uid 101 nginx \
	&& rpm --import /tmp/nginx_signing.key \
	&& rpm --import /tmp/app-protect-security-updates.key \
	&& rpm -Uvh /ubi-bin/c-ares-*.rpm \
	&& dnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check nginx-agent-${NAP_AGENT_VERSION}.* \
	&& sed -i 's/\(def in_container():\)/\1\n    return False/g' /usr/lib64/python*/*-packages/rhsm/config.py \
	&& subscription-manager register --org=${RHEL_ORGANIZATION} --activationkey=${RHEL_ACTIVATION_KEY} --name ${BUILD_OS}-$(uname -m) || true \
	&& subscription-manager attach \
	&& dnf config-manager --set-enabled codeready-builder-for-rhel-8-x86_64-rpms \
	&& dnf --nodocs install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm \
	&& dnf --nodocs install -y app-protect-${NAP_WAF_VERSION}* \
       app-protect-ip-intelligence \
       app-protect-attack-signatures \
       app-protect-threat-campaigns \
	&& subscription-manager unregister \
	&& nap-waf.sh \
	&& agent.sh \
	&& dnf clean all


# ── UBI8 Plus + NAP WAFv5 ──                              → make ubi8-image-nap-v5-plus
FROM redhat/ubi8@sha256:8f757bfe94700eee7d26c885cd16bf3ae9923edf38f984ef3da50d2ce937fc5e AS ubi-8-plus-nap-v5
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION
ARG NAP_AGENT_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=secret,id=rhel_license,dst=/tmp/rhel_license,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-8.repo,target=/etc/yum.repos.d/nginx-plus.repo,rw \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=app-protect-v5-8.repo,target=/etc/yum.repos.d/app-protect-8.repo \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	--mount=type=bind,from=ubi8-packages,src=/,target=/ubi-bin/ \
	source /tmp/rhel_license \
	&& mkdir -p /etc/nginx/reporting/ \
	&& cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& groupadd --system --gid 101 nginx \
	&& useradd --system --gid nginx --no-create-home --home-dir /nonexistent --comment "nginx user" --shell /bin/false --uid 101 nginx \
	&& rpm --import /tmp/nginx_signing.key \
	&& rpm -Uvh /ubi-bin/c-ares-*.rpm \
	&& dnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check nginx-agent-${NAP_AGENT_VERSION}.* \
	&& dnf --nodocs install -y app-protect-module-plus-${NAP_WAF_VERSION}* \
	&& nap-waf.sh \
	&& agent.sh \
	&& dnf clean all


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5: COMMON FUNNEL
#
# FROM ${BUILD_OS} -- selected by --build-arg BUILD_OS=<stage-name-from-above>
# Runs patch-os.sh + common.sh, sets permissions, ENTRYPOINT, USER 101.
# ══════════════════════════════════════════════════════════════════════════════

FROM ${BUILD_OS} AS common

ARG BUILD_OS
ARG IC_VERSION
ARG NGINX_VERSION
ARG TARGETPLATFORM
ARG NAP_MODULES=none

ENV BUILD_OS=${BUILD_OS}

RUN --mount=type=bind,target=/code \
	--mount=type=bind,from=nginx-files,src=common.sh,target=/usr/local/bin/common.sh \
	--mount=type=bind,from=nginx-files,src=patch-os.sh,target=/usr/local/bin/patch-os.sh \
	patch-os.sh \
	&& common.sh

EXPOSE 80 443

STOPSIGNAL SIGTERM
ENTRYPOINT ["/nginx-ingress"]
# 101 is nginx
USER 101

LABEL org.opencontainers.image.version="${IC_VERSION}" \
	org.opencontainers.image.documentation=https://docs.nginx.com/nginx-ingress-controller \
	org.opencontainers.image.vendor="NGINX Inc <kubernetes@nginx.com>" \
	org.nginx.kic.image.build.target="${TARGETPLATFORM}" \
	org.nginx.kic.image.build.os="${BUILD_OS}" \
	org.nginx.kic.image.build.nginx.version="${NGINX_VERSION}"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6: GO BINARY BUILDERS (never built directly)
# ══════════════════════════════════════════════════════════════════════════════

# ── Release binary ──
FROM golang-builder AS builder
ARG IC_VERSION
ARG TARGETARCH

WORKDIR /go/src/github.com/nginx/kubernetes-ingress/
RUN apk add --no-cache git libcap
RUN --mount=type=bind,target=/go/src/github.com/nginx/kubernetes-ingress/ --mount=type=cache,target=/root/.cache/go-build \
	go mod download
RUN --mount=type=bind,target=/go/src/github.com/nginx/kubernetes-ingress/ --mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${IC_VERSION}" \
	-o /nginx-ingress github.com/nginx/kubernetes-ingress/cmd/nginx-ingress \
	&& setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


# ── Debug binary + delve ──
FROM golang-builder AS debug-builder
ARG TARGETARCH

WORKDIR /go/src/github.com/nginx/kubernetes-ingress/
RUN apk add --no-cache git
RUN --mount=type=bind,target=/go/src/github.com/nginx/kubernetes-ingress/ --mount=type=cache,target=/root/.cache/go-build \
	go mod download
RUN --mount=type=bind,target=/go/src/github.com/nginx/kubernetes-ingress/ --mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -gcflags "all=-N -l" -o /nginx-ingress github.com/nginx/kubernetes-ingress/cmd/nginx-ingress
RUN CGO_ENABLED=0 go install -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv@latest


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7: FINAL IMAGE TARGETS
#
# These are the --target values passed by Make/CI.
# Each sits on top of "common" (which itself sits on the BUILD_OS base).
# Prebuilt variants (CI-only, skip rebuilding common) are in Dockerfile.prebuilt.
# ══════════════════════════════════════════════════════════════════════════════

# ── container: binary built inside Docker ──              --target=container
FROM common AS container

LABEL org.nginx.kic.image.build.version="container"

COPY --link --from=builder --chown=101:0 /nginx-ingress /


# ── local: binary pre-built on host ──                    --target=local (default)
FROM common AS local
ARG BUILD_OS
ENV BUILD_OS=${BUILD_OS}

LABEL org.nginx.kic.image.build.version="local"

COPY --link --chown=101:0 nginx-ingress /
# root is required for `setcap` invocation
USER 0
RUN --mount=type=bind,target=/tmp if [ -z "${BUILD_OS##*plus*}" ]; then PLUS=-plus; fi \
	&& cp -a /tmp/internal/configs/version1/nginx$PLUS.ingress.tmpl \
	/tmp/internal/configs/version1/nginx$PLUS.tmpl \
	/tmp/internal/configs/version2/nginx$PLUS.virtualserver.tmpl \
	/tmp/internal/configs/version2/nginx$PLUS.transportserver.tmpl / \
	&& if [ -z "${BUILD_OS##*plus*}" ]; then cp -a /tmp/internal/configs/version2/oidc.tmpl /; fi \
	&& chown -R 101:0 /*.tmpl \
	&& chmod -R g=u /*.tmpl \
	&& setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress
# 101 is nginx, defined above
USER 101


# ── debug: local binary + delve debugger ──               --target=debug
FROM common AS debug

LABEL org.nginx.kic.image.build.version="local"

ENV GOPATH="/work"
ENV GOROOT="/go"
ENV PATH="$PATH:${GOROOT}/bin:${GOPATH}/bin"

COPY --link --from=debug-builder --chown=101:0 /go/bin/dlv /dlv
COPY --link --chown=101:0 nginx-ingress /
# root is required for `setcap` invocation
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress && \
	setcap 'cap_net_bind_service=+ep' /dlv && setcap -v 'cap_net_bind_service=+ep' /dlv && \
	mkdir -p /nonexistent /work /go/bin /go-build && \
	chown 101:0 /nonexistent /work /go-build
COPY --link --from=debug-builder --chown=101:0 /usr/local/go/bin/go /go/bin/go
# 101 is nginx, defined above
USER 101
ENTRYPOINT ["/dlv"]


# ── debug-container: container-built binary + delve ──    --target=debug-container
FROM common AS debug-container

LABEL org.nginx.kic.image.build.version="local"

ENV GOPATH="/work"
ENV GOROOT="/go"
ENV PATH="$PATH:${GOROOT}/bin:${GOPATH}/bin"

COPY --link --from=debug-builder --chown=101:0 /go/bin/dlv /dlv
COPY --link --from=debug-builder --chown=101:0 /nginx-ingress /
# root is required for `setcap` invocation
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress && \
	setcap 'cap_net_bind_service=+ep' /dlv && setcap -v 'cap_net_bind_service=+ep' /dlv && \
	mkdir -p /nonexistent /work /go/bin /go-build && \
	chown 101:0 /nonexistent /work /go-build
COPY --link --from=debug-builder --chown=101:0 /usr/local/go/bin/go /go/bin/go
# 101 is nginx, defined above
USER 101
ENTRYPOINT ["/dlv"]


# ── goreleaser-setcap (intermediate) ──                   (not built directly)
FROM common AS goreleaser-setcap
ARG TARGETARCH

COPY --link --chown=101:0 dist/kubernetes-ingress_linux_${TARGETARCH}*/nginx-ingress /
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


# ── goreleaser ──                                         --target=goreleaser
FROM common AS goreleaser
ARG TARGETARCH

LABEL org.nginx.kic.image.build.version="goreleaser"

COPY --link --chown=101:0 --from=goreleaser-setcap /nginx-ingress /


# ── aws-setcap (intermediate) ──                          (not built directly)
FROM common AS aws-setcap
ARG TARGETARCH
ARG NAP_MODULES_AWS

COPY --link --chown=101:0 dist/aws*${NAP_MODULES_AWS}_linux_${TARGETARCH}*/nginx-ingress /
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


# ── aws ──                                                --target=aws
FROM common AS aws
ARG TARGETARCH
ARG NAP_MODULES_AWS

LABEL org.nginx.kic.image.build.version="aws"

COPY --link --chown=101:0 --from=aws-setcap /nginx-ingress /


# ── download: binary extracted from Docker Hub ──         --target=download
FROM nginx/nginx-ingress:${DOWNLOAD_TAG} AS kic

FROM common AS download

LABEL org.nginx.kic.image.build.version="binaries"

COPY --link --from=kic --chown=101:0 /nginx-ingress /


# ── patched: OS patches on existing image ──              --target=patched (make patch-os)
FROM ${IMAGE_NAME} AS patched
ARG IMAGE_NAME
ARG IC_VERSION

LABEL version="${IC_VERSION}" \
	org.opencontainers.image.version="${IC_VERSION}"

USER 0
RUN --mount=type=bind,from=nginx-files,src=patch-os.sh,target=/usr/local/bin/patch-os.sh \
	if [ -f /etc/apk/repositories ]; then sed -i -e '/nginx.com/d' /etc/apk/repositories; fi \
	&& patch-os.sh
USER 101

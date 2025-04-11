# syntax=docker/dockerfile:1.6
ARG BUILD_OS=debian
ARG NGINX_PLUS_VERSION=R34
ARG DOWNLOAD_TAG=edge
ARG DEBIAN_FRONTEND=noninteractive
ARG PREBUILT_BASE_IMG=nginx/nginx-ingress:${DOWNLOAD_TAG}
ARG NGINX_AGENT=false
ARG IMAGE_NAME=nginx/nginx-ingress
ARG WAF_VERSION=v4
ARG PACKAGE_REPO=pkgs.nginx.com


############################################# Base images containing libs for FIPS #############################################
FROM ghcr.io/nginx/dependencies/nginx-ubi-ppc64le:nginx-1.27.4@sha256:fff4dde599b89cb22e5cea5d8cfba8c47bcedaa8e6fa549f5fe74a89c733aa2f AS ubi-ppc64le
FROM ghcr.io/nginx/alpine-fips:0.2.4-alpine3.19@sha256:2a7f8451110b588b733e4cb8727a48153057b1debac5c78ef8a539ff63712fa1 AS alpine-fips-3.19
FROM ghcr.io/nginx/alpine-fips:0.2.4-alpine3.21@sha256:5221dec2e33436f2586c743c7aa3ef4626c0ec54184dc3364d101036d4f4a060 AS alpine-fips-3.21
FROM redhat/ubi9-minimal:9.5@sha256:ac61c96b93894b9169221e87718733354dd3765dd4a62b275893c7ff0d876869 AS ubi-minimal
FROM golang:1.24-alpine@sha256:7772cb5322baa875edd74705556d08f0eeca7b9c4b5367754ce3f2f00041ccee AS golang-builder


############################################# Base image for Alpine #############################################
FROM nginx:1.27.4-alpine@sha256:4ff102c5d78d254a6f0da062b3cf39eaf07f01eec0927fd21e219d0af8bc0591 AS alpine

RUN apk add --no-cache libcap libstdc++ \
    && printf "%s%s%s\n" "http://nginx.org/packages/mainline/alpine/v" `egrep -o '^[0-9]+\.[0-9]+' /etc/alpine-release` "/main" >> /etc/apk/repositories \
	&& apk add --no-cache libcap libstdc++ nginx-module-otel \
	&& sed -i -e '/nginx.org/d' /etc/apk/repositories


############################################# Base image for Debian #############################################
FROM nginx:1.27.4@sha256:09369da6b10306312cd908661320086bf87fbae1b6b0c49a1f50ba531fef2eab AS debian

RUN apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y \
	libcap2-bin curl gnupg2 ca-certificates lsb-release debian-archive-keyring \
	&& curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor > /usr/share/keyrings/nginx-archive-keyring.gpg \
	&& echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
	http://nginx.org/packages/mainline/debian `lsb_release -cs` nginx" > /etc/apt/sources.list.d/nginx.list \
	&& printf "%s" "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" > /etc/apt/preferences.d/99nginx \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y nginx-module-otel \
	&& apt-get purge --auto-remove -y gnupg2 lsb-release curl \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/preferences.d/99nginx /etc/apt/sources.list.d/nginx.list

############################################# NGINX files #############################################
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

############################################# Patch Image #############################################
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


############################################# Base image for Alpine with NGINX Plus ##############################################
FROM alpine:3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c AS alpine-plus
ARG NGINX_PLUS_VERSION
ARG PACKAGE_REPO

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/apk/cert.pem,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/apk/cert.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=user_agent,target=/tmp/user_agent \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	export $(cat /tmp/user_agent) \
	&& printf "%s\n" "https://${PACKAGE_REPO}/plus/${NGINX_PLUS_VERSION}/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& apk add --no-cache nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check libcap libcurl \
	&& mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ldconfig /usr/local/lib/ \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories


############################################# Base image for Alpine with NGINX Plus and FIPS #############################################
FROM alpine-plus AS alpine-plus-fips
ARG NGINX_PLUS_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=bind,from=alpine-fips-3.21,target=/tmp/fips/ \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /usr/ssl \
	&& cp -av /tmp/fips/usr/lib/ossl-modules/fips.so /usr/lib/ossl-modules/fips.so \
	&& cp -av /tmp/fips/usr/ssl/fipsmodule.cnf /usr/ssl/fipsmodule.cnf \
	&& cp -av /tmp/fips/etc/ssl/openssl.cnf /etc/ssl/openssl.cnf \
	&& cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info


############################################# Base image for Alpine with NGINX Plus, App Protect WAF and FIPS #############################################
FROM alpine:3.19@sha256:e5d0aea7f7d2954678a9a6269ca2d06e06591881161961ea59e974dff3f12377 AS alpine-plus-nap-fips
ARG NGINX_PLUS_VERSION
ARG NGINX_AGENT
ARG NGINX_PLUS_VERSION
ARG PACKAGE_REPO

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=bind,from=alpine-fips-3.19,target=/tmp/fips/ \
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
	&& if [ "${NGINX_AGENT}" = "true" ]; then apk add --no-cache nginx-agent; fi \
	&& mkdir -p /usr/ssl \
	&& cp -av /tmp/fips/usr/lib/ossl-modules/fips.so /usr/lib/ossl-modules/fips.so \
	&& cp -av /tmp/fips/usr/ssl/fipsmodule.cnf /usr/ssl/fipsmodule.cnf \
	&& cp -av /tmp/fips/etc/ssl/openssl.cnf /etc/ssl/openssl.cnf \
	&& mkdir -p /etc/nginx/reporting/ \
	&& cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ldconfig /usr/local/lib/ \
	&& apk add --no-cache app-protect app-protect-attack-signatures app-protect-threat-campaigns \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories \
	&& nap-waf.sh \
	&& if [ "${NGINX_AGENT}" = "true" ]; then \
	agent.sh \
	; fi


############################################# Base image for Alpine with NGINX Plus, App Protect WAFv5 and FIPS #############################################
FROM alpine:3.19@sha256:e5d0aea7f7d2954678a9a6269ca2d06e06591881161961ea59e974dff3f12377 AS alpine-plus-nap-v5-fips
ARG NGINX_PLUS_VERSION
ARG NGINX_AGENT
ARG NGINX_PLUS_VERSION
ARG PACKAGE_REPO

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=bind,from=alpine-fips-3.19,target=/tmp/fips/ \
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
	&& if [ "${NGINX_AGENT}" = "true" ]; then apk add --no-cache nginx-agent; fi \
	&& mkdir -p /usr/ssl \
	&& cp -av /tmp/fips/usr/lib/ossl-modules/fips.so /usr/lib/ossl-modules/fips.so \
	&& cp -av /tmp/fips/usr/ssl/fipsmodule.cnf /usr/ssl/fipsmodule.cnf \
	&& cp -av /tmp/fips/etc/ssl/openssl.cnf /etc/ssl/openssl.cnf \
	&& mkdir -p /etc/nginx/reporting/ \
	&& cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ldconfig /usr/local/lib/ \
	&& apk add --no-cache app-protect-module-plus~=34.5.342 \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories \
	&& nap-waf.sh \
	&& if [ "${NGINX_AGENT}" = "true" ]; then \
	agent.sh \
	; fi


############################################# Base image for Debian with NGINX Plus #############################################
FROM debian:12-slim@sha256:b1211f6d19afd012477bd34fdcabb6b663d680e0f4b0537da6e6b0fd057a3ec3 AS debian-plus
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
	&& ldconfig \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx-plus.sources


############################################# Base image for Debian with NGINX Plus and App Protect WAF/DoS #############################################
FROM debian-plus AS debian-plus-nap
ARG NAP_MODULES
ARG NGINX_AGENT
ARG NGINX_PLUS_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=nap-waf-12.sources,target=/tmp/app-protect.sources \
	--mount=type=bind,from=nginx-files,src=nap-dos-12.sources,target=/tmp/app-protect-dos.sources \
	--mount=type=bind,from=nginx-files,src=debian-agent-12.sources,target=/etc/apt/sources.list.d/nginx-agent.sources \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=nap-dos.sh,target=/usr/local/bin/nap-dos.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	cp /tmp/app-protect.sources /etc/apt/sources.list.d/app-protect.sources; \
	fi \
	&& if [ -z "${NAP_MODULES##*dos*}" ]; then \
	cp /tmp/app-protect-dos.sources /etc/apt/sources.list.d/app-protect-dos.sources; \
	fi \
	&& apt-get update \
	&& if [ "${NGINX_AGENT}" = "true" ]; then apt-get install --no-install-recommends --no-install-suggests -y nginx-agent; fi \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	apt-get install --no-install-recommends --no-install-suggests -y app-protect app-protect-attack-signatures app-protect-threat-campaigns; \
	fi \
	&& if [ -z "${NAP_MODULES##*dos*}" ]; then \
	apt-get install --no-install-recommends --no-install-suggests -y app-protect-dos; \
	fi \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	rm -f /etc/apt/sources.list.d/app-protect.sources; \
	fi \
	&& if [ -z "${NAP_MODULES##*dos*}" ]; then \
	rm -f /etc/apt/sources.list.d/app-protect-dos.sources; \
	fi \
	&& rm -rf /var/lib/apt/lists/* \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then nap-waf.sh; fi \
	&& if [ "${NGINX_AGENT}" = "true" ]; then agent.sh; fi \
	&& if [ -z "${NAP_MODULES##*dos*}" ]; then nap-dos.sh; fi

############################################# Base image for Debian with NGINX Plus and App Protect WAFv5 #############################################
FROM debian-plus AS debian-plus-nap-v5
ARG NAP_MODULES
ARG NGINX_AGENT
ARG NGINX_PLUS_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=nap-waf-v5-12.sources,target=/tmp/app-protect.sources \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=debian-agent-12.sources,target=/etc/apt/sources.list.d/nginx-agent.sources \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	cp /tmp/app-protect.sources /etc/apt/sources.list.d/app-protect.sources; \
	fi \
	&& apt-get update \
	&& if [ "${NGINX_AGENT}" = "true" ]; then apt-get install --no-install-recommends --no-install-suggests -y nginx-agent; fi \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	apt-get install --no-install-recommends --no-install-suggests -y app-protect-module-plus=34+5.342* nginx-plus-module-appprotect=34+5.342* app-protect-plugin=6.12.0*; \
	rm -f /etc/apt/sources.list.d/app-protect.sources; \
	nap-waf.sh; \
	fi \
	&& apt-get purge --auto-remove -y gpg \
	&& if [ "${NGINX_AGENT}" = "true" ]; then \
	agent.sh; \
	fi


############################################# Base image for UBI #############################################
FROM ubi-minimal AS ubi
ARG IC_VERSION

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
	--mount=type=bind,from=ubi-ppc64le,src=/,target=/ubi-bin/ \
	ubi-setup.sh; \
	if [ $(uname -p) = ppc64le ] || [ $(uname -p) = s390x ]; then \
	rpm -qa --queryformat "%{NAME}\n" | sort > pkgs-installed \
	&& microdnf --nodocs --setopt=install_weak_deps=0 install -y diffutils dnf \
	&& rpm -qa --queryformat "%{NAME}\n" | sort > pkgs-new \
	&& dnf install -y /ubi-bin/*.rpm \
	&& dnf -q repoquery --resolve --requires --recursive --whatrequires nginx --queryformat "%{NAME}" > pkgs-nginx \
	&& dnf --setopt=protected_packages= remove -y $(comm -13 pkgs-installed pkgs-new | comm -13 pkgs-nginx -) \
	&& rm pkgs-installed pkgs-new pkgs-nginx; \
	else \
	printf "%s\n" "[nginx]" "name=nginx repo" \
	"baseurl=https://nginx.org/packages/mainline/centos/9/\$basearch/" \
	"gpgcheck=1" "enabled=1" "module_hotfixes=true" > /etc/yum.repos.d/nginx.repo \
	&& microdnf --nodocs install -y nginx nginx-module-njs nginx-module-otel nginx-module-image-filter nginx-module-xslt \
	&& rm /etc/yum.repos.d/nginx.repo; \
	fi \
	&& ubi-clean.sh


############################################# Base image for UBI with NGINX Plus #############################################
FROM ubi-minimal AS ubi-9-plus
ARG NGINX_PLUS_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-9.repo,target=/etc/yum.repos.d/nginx-plus.repo \
	--mount=type=bind,from=nginx-files,src=ubi-setup.sh,target=/usr/local/bin/ubi-setup.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ubi-setup.sh \
	&& microdnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check \
	&& ubi-clean.sh


############################################# Base image for UBI with NGINX Plus and App Protect WAF & DoS #############################################
FROM ubi-9-plus AS ubi-9-plus-nap
ARG NAP_MODULES
ARG NGINX_AGENT

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=secret,id=rhel_license,dst=/tmp/rhel_license,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=app-protect-security-updates.key,target=/tmp/app-protect-security-updates.key \
	--mount=type=bind,from=nginx-files,src=app-protect-9.repo,target=/tmp/app-protect-9.repo \
	--mount=type=bind,from=nginx-files,src=app-protect-dos-9.repo,target=/tmp/app-protect-dos-9.repo \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=nap-dos.sh,target=/usr/local/bin/nap-dos.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& source /tmp/rhel_license \
	&& rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm \
	&& microdnf --nodocs install -y ca-certificates shadow-utils subscription-manager \
	&& if [ "${NGINX_AGENT}" = "true" ]; then microdnf --nodocs install -y nginx-agent; fi \
	&& subscription-manager register --org=${RHEL_ORGANIZATION} --activationkey=${RHEL_ACTIVATION_KEY} || true \
	&& subscription-manager attach \
	&& rpm --import /tmp/app-protect-security-updates.key \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	cp /tmp/app-protect-9.repo /etc/yum.repos.d/app-protect-9.repo \
	&& microdnf --enablerepo=codeready-builder-for-rhel-9-x86_64-rpms --nodocs install -y \
	app-protect app-protect-attack-signatures app-protect-threat-campaigns \
	&& rm -f /etc/yum.repos.d/app-protect-9.repo \
	&& nap-waf.sh; \
	fi \
	&& if [ -z "${NAP_MODULES##*dos*}" ]; then \
	cp /tmp/app-protect-dos-9.repo /etc/yum.repos.d/app-protect-dos-9.repo \
	&& microdnf --nodocs install -y app-protect-dos \
	&& rm -f /etc/yum.repos.d/app-protect-dos-9.repo \
	&& nap-dos.sh; \
	fi \
	&& subscription-manager unregister \
	&& ubi-clean.sh \
	&& if [ "${NGINX_AGENT}" = "true" ]; then agent.sh; fi


############################################# Base image for UBI with NGINX Plus and App Protect WAFv5 #############################################
FROM ubi-9-plus AS ubi-9-plus-nap-v5
ARG NAP_MODULES
ARG NGINX_AGENT

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=secret,id=rhel_license,dst=/tmp/rhel_license,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=app-protect-v5-9.repo,target=/tmp/app-protect-9.repo \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& source /tmp/rhel_license \
	&& rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm \
	&& microdnf --nodocs install -y ca-certificates shadow-utils subscription-manager \
	&& if [ "${NGINX_AGENT}" = "true" ]; then microdnf --nodocs install -y nginx-agent; fi \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	cp /tmp/app-protect-9.repo /etc/yum.repos.d/app-protect-9.repo \
	&& microdnf --nodocs install -y app-protect-module-plus-34+5.342* \
	&& nap-waf.sh \
	&& rm -f /etc/yum.repos.d/app-protect-9.repo; \
	fi \
	&& ubi-clean.sh \
	&& if [ "${NGINX_AGENT}" = "true" ]; then agent.sh; fi


############################################# Base image for UBI8 with NGINX Plus and App Protect WAF #############################################
FROM redhat/ubi8@sha256:8bd1b6306f8164de7fb0974031a0f903bd3ab3e6bcab835854d3d9a1a74ea5db AS ubi-8-plus-nap
ARG NAP_MODULES
ARG NGINX_AGENT
ARG NGINX_PLUS_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=secret,id=rhel_license,dst=/tmp/rhel_license,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-8.repo,target=/etc/yum.repos.d/nginx-plus.repo,rw \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=app-protect-security-updates.key,target=/tmp/app-protect-security-updates.key \
	--mount=type=bind,from=nginx-files,src=app-protect-8.repo,target=/tmp/app-protect-8.repo \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& source /tmp/rhel_license \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	cp /tmp/app-protect-8.repo /etc/yum.repos.d/app-protect-8.repo; \
	fi \
	&& groupadd --system --gid 101 nginx \
	&& useradd --system --gid nginx --no-create-home --home-dir /nonexistent --comment "nginx user" --shell /bin/false --uid 101 nginx \
	&& rpm --import /tmp/nginx_signing.key \
	&& dnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check \
	&& if [ "${NGINX_AGENT}" = "true" ]; then dnf --nodocs install -y nginx-agent; fi \
	&& sed -i 's/\(def in_container():\)/\1\n    return False/g' /usr/lib64/python*/*-packages/rhsm/config.py \
	&& subscription-manager register --org=${RHEL_ORGANIZATION} --activationkey=${RHEL_ACTIVATION_KEY} || true \
	&& subscription-manager attach \
	&& dnf config-manager --set-enabled codeready-builder-for-rhel-8-x86_64-rpms \
	&& dnf --nodocs install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm \
	&& rpm --import /tmp/app-protect-security-updates.key \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	dnf --nodocs install -y app-protect app-protect-attack-signatures app-protect-threat-campaigns; \
	fi \
	&& subscription-manager unregister \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	rm -f /etc/yum.repos.d/app-protect-8.repo \
	&& nap-waf.sh; \
	fi \
	&& if [ "${NGINX_AGENT}" = "true" ]; then agent.sh; fi \
	&& dnf clean all


############################################# Base image for UBI8 with NGINX Plus and App Protect WAFv5  #############################################
FROM redhat/ubi8@sha256:8bd1b6306f8164de7fb0974031a0f903bd3ab3e6bcab835854d3d9a1a74ea5db AS ubi-8-plus-nap-v5
ARG NAP_MODULES
ARG NGINX_AGENT
ARG NGINX_PLUS_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=secret,id=rhel_license,dst=/tmp/rhel_license,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-8.repo,target=/etc/yum.repos.d/nginx-plus.repo,rw \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=app-protect-v5-8.repo,target=/tmp/app-protect-8.repo \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& source /tmp/rhel_license \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	cp /tmp/app-protect-8.repo /etc/yum.repos.d/app-protect-8.repo; \
	fi \
	## the code below is duplicated from the ubi-plus image because NAP DOS doesn't support UBI 9 and minimal versions
	&& groupadd --system --gid 101 nginx \
	&& useradd --system --gid nginx --no-create-home --home-dir /nonexistent --comment "nginx user" --shell /bin/false --uid 101 nginx \
	&& rpm --import /tmp/nginx_signing.key \
	&& dnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check \
	&& if [ "${NGINX_AGENT}" = "true" ]; then dnf --nodocs install -y nginx-agent; fi \
	## end of duplicated code
	&& sed -i 's/\(def in_container():\)/\1\n    return False/g' /usr/lib64/python*/*-packages/rhsm/config.py \
	&& subscription-manager register --org=${RHEL_ORGANIZATION} --activationkey=${RHEL_ACTIVATION_KEY} || true \
	&& subscription-manager attach \
	&& dnf config-manager --set-enabled codeready-builder-for-rhel-8-x86_64-rpms \
	&& dnf --nodocs install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	dnf --nodocs install -y app-protect-module-plus-34+5.342*; \
	fi \
	&& subscription-manager unregister \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
	rm -f /etc/yum.repos.d/app-protect-8.repo \
	&& nap-waf.sh; \
	fi \
	&& if [ "${NGINX_AGENT}" = "true" ]; then agent.sh; fi \
	&& dnf clean all


############################################# Create common files, permissions and setcap #############################################
FROM ${BUILD_OS} AS common

ARG BUILD_OS
ARG IC_VERSION
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


############################################# Build nginx-ingress in golang container #############################################
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


############################################# Download delve #############################################
FROM golang-builder AS debug-builder
ARG TARGETARCH

WORKDIR /go/src/github.com/nginx/kubernetes-ingress/
RUN apk add --no-cache git
RUN --mount=type=bind,target=/go/src/github.com/nginx/kubernetes-ingress/ --mount=type=cache,target=/root/.cache/go-build \
	go mod download
RUN --mount=type=bind,target=/go/src/github.com/nginx/kubernetes-ingress/ --mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -gcflags "all=-N -l" -o /nginx-ingress github.com/nginx/kubernetes-ingress/cmd/nginx-ingress
RUN CGO_ENABLED=0 go install -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv@latest


############################################# Create image with nginx-ingress built in container #############################################
FROM common AS container

LABEL org.nginx.kic.image.build.version="container"

COPY --link --from=builder --chown=101:0 /nginx-ingress /


############################################# Create image with nginx-ingress built locally #############################################
FROM common AS local

LABEL org.nginx.kic.image.build.version="local"

COPY --link --chown=101:0 nginx-ingress /
# root is required for `setcap` invocation
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress
# 101 is nginx, defined above
USER 101


############################################# Create image with nginx-ingress built locally #############################################
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


############################################# Create image with nginx-ingress built locally #############################################
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


############################################# Create image with nginx-ingress built locally & using prebuilt base image #############################################
FROM ${PREBUILT_BASE_IMG} AS local-prebuilt
ARG BUILD_OS

LABEL org.nginx.kic.image.build.version="local"

COPY --link --chown=101:0 nginx-ingress /
# root is required for `setcap` invocation
USER 0
RUN --mount=type=bind,target=/tmp [ -z "${BUILD_OS##*plus*}" ] && PLUS=-plus; cp -a /tmp/internal/configs/version1/nginx$PLUS.ingress.tmpl /tmp/internal/configs/version1/nginx$PLUS.tmpl \
	/tmp/internal/configs/version2/nginx$PLUS.virtualserver.tmpl /tmp/internal/configs/version2/nginx$PLUS.transportserver.tmpl / \
	&& chown -R 101:0 /*.tmpl \
	&& chmod -R g=u /*.tmpl \
	&& setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress
# 101 is nginx, defined above
USER 101


############################################# Builder style stage to avoid duplicate layers for ingress and ingress with setcap #############################################
# Builder image for goreleaser
FROM common AS goreleaser-setcap
ARG TARGETARCH

COPY --link --chown=101:0 dist/kubernetes-ingress_linux_${TARGETARCH}*/nginx-ingress /
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


############################################# Create image with nginx-ingress built by GoReleaser #############################################
FROM common AS goreleaser
ARG TARGETARCH

LABEL org.nginx.kic.image.build.version="goreleaser"

COPY --link --chown=101:0 --from=goreleaser-setcap /nginx-ingress /


############################################# Builder style stage to avoid duplicate layers for ingress and ingress with setcap #############################################
# Builder image for goreleaser-prebuilt
FROM ${PREBUILT_BASE_IMG} AS goreleaser-setcap-prebuilt
ARG TARGETARCH

COPY --link --chown=101:0 dist/kubernetes-ingress_linux_${TARGETARCH}*/nginx-ingress /
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


############################################# Create image with nginx-ingress built by GoReleaser & using prebuilt base image #############################################
FROM ${PREBUILT_BASE_IMG} AS goreleaser-prebuilt
ARG TARGETARCH
ARG BUILD_OS

LABEL org.nginx.kic.image.build.version="goreleaser"

COPY --link --chown=101:0 --from=goreleaser-setcap-prebuilt /nginx-ingress /
# root is required for `setcap` invocation
USER 0
RUN --mount=type=bind,target=/tmp [ -z "${BUILD_OS##*plus*}" ] && PLUS=-plus; cp -a /tmp/internal/configs/version1/nginx$PLUS.ingress.tmpl /tmp/internal/configs/version1/nginx$PLUS.tmpl \
	/tmp/internal/configs/version2/nginx$PLUS.virtualserver.tmpl /tmp/internal/configs/version2/nginx$PLUS.transportserver.tmpl / \
	&& chown -R 101:0 /*.tmpl \
	&& chmod -R g=u /*.tmpl
USER 101


############################################# Builder style stage to avoid duplicate layers for ingress and ingress with setcap #############################################
# Builder image for aws
FROM common AS aws-setcap
ARG TARGETARCH
ARG NAP_MODULES_AWS

COPY --link --chown=101:0 dist/aws*${NAP_MODULES_AWS}_linux_${TARGETARCH}*/nginx-ingress /
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


############################################# Create image with nginx-ingress built by GoReleaser for AWS Marketplace #############################################
FROM common AS aws
ARG TARGETARCH
ARG NAP_MODULES_AWS

LABEL org.nginx.kic.image.build.version="aws"

COPY --link --chown=101:0 --from=aws-setcap /nginx-ingress /


############################################# Builder style stage to avoid duplicate layers for ingress and ingress with setcap #############################################
# Builder image for aws-prebuilt
FROM ${PREBUILT_BASE_IMG} AS aws-setcap-prebuilt
ARG TARGETARCH
ARG NAP_MODULES_AWS

COPY --link --chown=101:0 dist/aws*${NAP_MODULES_AWS}_linux_${TARGETARCH}*/nginx-ingress /
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


############################################# Create image with nginx-ingress built by GoReleaser for AWS Marketplace #############################################
FROM ${PREBUILT_BASE_IMG} AS aws-prebuilt
ARG TARGETARCH
ARG NAP_MODULES_AWS
ARG BUILD_OS

LABEL org.nginx.kic.image.build.version="aws"

COPY --link --chown=101:0 --from=aws-setcap-prebuilt /nginx-ingress /
USER 0
RUN --mount=type=bind,target=/tmp [ -z "${BUILD_OS##*plus*}" ] && PLUS=-plus; cp -a /tmp/internal/configs/version1/nginx$PLUS.ingress.tmpl /tmp/internal/configs/version1/nginx$PLUS.tmpl \
	/tmp/internal/configs/version2/nginx$PLUS.virtualserver.tmpl /tmp/internal/configs/version2/nginx$PLUS.transportserver.tmpl / \
	&& chown -R 101:0 /*.tmpl \
	&& chmod -R g=u /*.tmpl
USER 101


############################################# Create image with nginx-ingress extracted from image on Docker Hub #############################################
FROM nginx/nginx-ingress:${DOWNLOAD_TAG} AS kic

FROM common AS download

LABEL org.nginx.kic.image.build.version="binaries"

COPY --link --from=kic --chown=101:0 /nginx-ingress /

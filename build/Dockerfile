# syntax=docker/dockerfile:1.24
ARG BUILD_OS=debian
# renovate: datasource=docker depName=nginx/nginx
ARG NGINX_OSS_VERSION=1.31.1
ARG NGINX_PLUS_VERSION=R37.0
ARG NAP_WAF_VERSION=37.0+5.635
ARG NAP_WAF_COMMON_VERSION=11.665
ARG NAP_WAF_PLUGIN_VERSION=6.29
ARG AGENT_V3_VERSION=3
ARG AGENT_V2_VERSION=2
ARG DOWNLOAD_TAG=edge
ARG DEBIAN_FRONTEND=noninteractive
ARG PREBUILT_BASE_IMG=nginx/nginx-ingress:${DOWNLOAD_TAG}
ARG IMAGE_NAME=nginx/nginx-ingress
ARG PACKAGE_REPO=pkgs.nginx.com
ARG UBI10_PACKAGES_IMAGE=ghcr.io/nginx/dependencies/nginx-ubi:ubi10@sha256:4f9f7108f3541966a40ba06d4cb773743e80db920920bc9c8ea62bf9ae8eeb42


############################################# External dependency images #############################################
FROM golang:1.26.3-alpine@sha256:3a8f055e02fce9585d5e4ab5135d57f2e1a947a16e2a7e6a71a78e770c169e9b AS golang-builder
FROM ghcr.io/nginx/alpine-fips:0.5.0-alpine3.22@sha256:f907d7541ab03453fd7d630dc0fb8d9a819717ea52a7956fe1f45b9833051177 AS alpine-fips-3.22
FROM ${UBI10_PACKAGES_IMAGE} AS ubi10-packages
FROM redhat/ubi10-minimal:10.1-1778576723@sha256:145c54e19de7ea25d958b54d981f95762d1a22d17f45fa8f013a5ea07f8ad68c AS ubi-minimal


############################################# NGINX repo keys, .repo files, and helper scripts #############################################
FROM scratch AS nginx-files
ARG IC_VERSION
ARG BUILD_OS
ARG NGINX_PLUS_VERSION
ARG PACKAGE_REPO

# the following links can be replaced with local files if needed, i.e. ADD --chown=101:0 <local_file> <container_file>
ADD --link --chown=101:0 https://cs.nginx.com/static/files/90pkgs-nginx 90pkgs-nginx
ADD --link --chown=101:0 https://cs.nginx.com/static/keys/nginx_signing.key nginx_signing.key
ADD --link --chown=101:0 https://cs.nginx.com/static/keys/nginx_signing.rsa.pub nginx_signing.rsa.pub
ADD --link --chown=101:0 https://cs.nginx.com/static/files/plus-10.repo nginx-plus-10.repo
ADD --link --chown=101:0 https://cs.nginx.com/static/files/app-protect-10.repo app-protect-10.repo
ADD --link --chown=101:0 https://cs.nginx.com/static/keys/app-protect-security-updates.key app-protect-security-updates.key
ADD --link --chown=101:0 https://cs.nginx.com/static/keys/app-protect-security-updates.rsa.pub app-protect-security-updates.rsa.pub
ADD --link --chown=101:0 https://cs.nginx.com/static/files/app-protect-dos-10.repo app-protect-dos-10.repo
ADD --link --chown=101:0 https://cs.nginx.com/static/files/nginx-agent.repo nginx-agent.repo
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/nap-waf-v5-ubi.repo app-protect-v5.repo
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/plus-debian-13.source debian-plus-13.sources
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/nap-waf-debian-13.source nap-waf-13.sources
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/nap-dos-debian-13.source nap-dos-13.sources
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/nap-waf-v5-debian-13.source nap-waf-v5-13.sources
ADD --link --chown=101:0 https://raw.githubusercontent.com/nginx/k8s-common/main/files/agent-debian-13.source debian-agent-13.sources

RUN --mount=from=busybox:musl,src=/bin/,dst=/bin/ printf "%s\n" "Acquire::https::pkgs.nginx.com::User-Agent k8s-ic-$IC_VERSION${BUILD_OS##debian-plus}-apt;" >> 90pkgs-nginx \
	&& if ! grep -q "${PACKAGE_REPO}" 90pkgs-nginx ; then cat 90pkgs-nginx | sed -e "s/pkgs.nginx.com/${PACKAGE_REPO}/g" >> 90pkgs-nginx; fi \
	&& printf "%s\n" "user_agent=k8s-ic-$IC_VERSION${BUILD_OS##ubi*plus}-dnf" | tee -a nginx-plus-*.repo \
	&& mkdir dos \
	&& mv app-protect-dos-10.repo nap-dos-13.sources dos/ \
	&& DOS_PLUS_VERSION=${NGINX_PLUS_VERSION%%.*} sed -i -e "s;%VERSION%;${DOS_PLUS_VERSION};g" -e "s;pkgs.nginx.com;${PACKAGE_REPO};g" -e "s;${PACKAGE_REPO}/app-protect-security-updates;pkgs.nginx.com/app-protect-security-updates;g" dos/nap-dos-13.sources \
	&& DOS_PLUS_VERSION=${NGINX_PLUS_VERSION%%.*} sed -i -e "s/=0/=1/" -e "1,8s;/centos;/${DOS_PLUS_VERSION}/centos;" -e "s;pkgs.nginx.com;${PACKAGE_REPO};g" -e "s;${PACKAGE_REPO}/app-protect-security-updates;pkgs.nginx.com/app-protect-security-updates;g" dos/app-protect-dos-10.repo \
	&& sed -i -e "s;%VERSION%;${NGINX_PLUS_VERSION};g" -e "s;pkgs.nginx.com;${PACKAGE_REPO};g" -e "s;${PACKAGE_REPO}/app-protect-security-updates;pkgs.nginx.com/app-protect-security-updates;g" *.sources \
	&& sed -i -e "s/=0/=1/" app-protect-v5.repo \
	&& sed -i -e "s/=0/=1/" -e "1,8s;/centos;/${NGINX_PLUS_VERSION}/centos;" -e "s;pkgs.nginx.com;${PACKAGE_REPO};g" -e "s;${PACKAGE_REPO}/app-protect-security-updates;pkgs.nginx.com/app-protect-security-updates;g" nginx-plus-10.repo app-protect-10.repo \
	&& sed -i -e "s/=0/=1/" -e "s;pkgs.nginx.com;${PACKAGE_REPO};g" nginx-agent.repo app-protect-v5.repo \
	&& mv dos/* . \
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


############################################# NGINX OSS on Alpine Linux #############################################
# Base:    nginx:1.31.1-alpine3.23 (official NGINX OSS Alpine image, OSS pre-installed)
# Adds:    nginx-module-otel + nginx-agent v3
# Used as: BUILD_OS=alpine
FROM nginx:1.31.1-alpine3.23@sha256:8b1e78743a03dbb2c95171cc58639fef29abc8816598e27fb910ed2e621e589a AS alpine
ARG PACKAGE_REPO
ARG NGINX_OSS_VERSION
ARG AGENT_V3_VERSION

RUN --mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=user_agent,target=/tmp/user_agent \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	apk add --no-cache libcap libstdc++ \
	&& export $(cat /tmp/user_agent) \
	&& printf "%s%s%s\n" "http://packages.nginx.org/nginx/mainline/alpine/v" `egrep -o '^[0-9]+\.[0-9]+' /etc/alpine-release` "/main" >> /etc/apk/repositories \
	&& printf "%s%s%s\n" "http://packages.nginx.org/nginx-agent/alpine/v" `egrep -o '^[0-9]+\.[0-9]+' /etc/alpine-release` "/main" >> /etc/apk/repositories \
	&& apk add --no-cache nginx-module-otel~${NGINX_OSS_VERSION} nginx-agent~${AGENT_V3_VERSION} \
	&& ldconfig /usr/local/lib/ \
	&& agent.sh \
	&& sed -i -e '/nginx.org/d' /etc/apk/repositories


############################################# NGINX OSS on Debian 13 #############################################
# Base:    nginx:1.31.1 (official NGINX OSS Debian image, OSS pre-installed)
# Adds:    nginx-module-otel + nginx-agent v3
# Used as: BUILD_OS=debian (default)
FROM nginx:1.31.1@sha256:5aca99593157f4ae539a5dec1092a0ad8762f8e2eb1789085a13a0f5622369f6 AS debian
ARG NGINX_OSS_VERSION
ARG AGENT_V3_VERSION

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
	nginx-agent=${AGENT_V3_VERSION}* \
	nginx-module-otel=${NGINX_OSS_VERSION}* \
	&& apt-get purge --auto-remove -y gpg \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/preferences.d/99nginx /etc/apt/sources.list.d/nginx.list \
	&& agent.sh


############################################# NGINX OSS on Red Hat UBI 10 #############################################
# Base:    ubi-minimal (Red Hat UBI 10 minimal)
# Adds:    nginx + nginx-module-njs/otel/image-filter/xslt + nginx-agent v3
# Used as: BUILD_OS=ubi
FROM ubi-minimal AS ubi
ARG IC_VERSION
ARG NGINX_OSS_VERSION
ARG AGENT_V3_VERSION

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
	--mount=type=bind,from=ubi10-packages,src=/,target=/ubi-bin/ \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	ubi-setup.sh \
	&& rpm -qa --queryformat "%{NAME}\n" | sort > pkgs-installed \
	&& microdnf --nodocs --setopt=install_weak_deps=0 install -y diffutils dnf \
	&& rpm -qa --queryformat "%{NAME}\n" | sort > pkgs-new \
    && printf '[local-deps]\nname=Local UBI Deps\nbaseurl=file:///ubi-bin\nenabled=1\ngpgcheck=0\n' > /etc/yum.repos.d/local-deps.repo \
	&& dnf -q repoquery --resolve --requires --recursive --whatrequires nginx --queryformat "%{NAME}" > pkgs-nginx \
	&& dnf --setopt=protected_packages= remove -y $(comm -13 pkgs-installed pkgs-new | comm -13 pkgs-nginx -) \
	&& rm pkgs-installed pkgs-new pkgs-nginx \
	&& printf "%s\n" "[nginx]" "name=nginx repo" \
	"baseurl=https://packages.nginx.org/nginx/mainline/centos/10/\$basearch/" \
	"gpgcheck=1" "enabled=1" "module_hotfixes=true" > /etc/yum.repos.d/nginx.repo \
    && printf "%s\n" "[agent]" "name=agent repo" \
    "baseurl=https://packages.nginx.org/nginx-agent/centos/10/\$basearch/" \
    "gpgcheck=1" "enabled=1" "module_hotfixes=true" >> /etc/yum.repos.d/nginx.repo \
	&& microdnf --nodocs install -y nginx-${NGINX_OSS_VERSION}* nginx-module-njs-${NGINX_OSS_VERSION}* nginx-module-otel-${NGINX_OSS_VERSION}* nginx-module-image-filter-${NGINX_OSS_VERSION}* nginx-module-xslt-${NGINX_OSS_VERSION}* nginx-agent-${AGENT_V3_VERSION}* \
	&& rm -rf /etc/yum.repos.d/nginx.repo /etc/yum.repos.d/local-deps.repo \
	&& ubi-clean.sh


############################################# NGINX Plus + Agent v3 on Alpine Linux #############################################
# Base:    alpine:3.22
# Adds:    nginx-plus, nginx-plus-module-njs/otel/fips-check, nginx-agent v3, tracking.info
# Used as: BUILD_OS=alpine-plus
FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS alpine-plus
ARG NGINX_PLUS_VERSION
ARG PACKAGE_REPO
ARG AGENT_V3_VERSION

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
	&& apk add --no-cache nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check nginx-agent~${AGENT_V3_VERSION} libcap libcurl \
	&& mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& agent.sh \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories


############################################# NGINX Plus + FIPS + Agent v3 on Alpine Linux #############################################
# Base:    alpine-plus (NGINX Plus + Agent v3)
# Adds:    OpenSSL FIPS provider from alpine-fips-3.22 (fips.so, fipsmodule.cnf, openssl.cnf)
# Used as: BUILD_OS=alpine-plus-fips
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


############################################# Intermediate image — NGINX Plus + App Protect WAF v4 + FIPS on Alpine #############################################
# Base:     alpine:3.22 (fresh — does not extend alpine-plus, keeps agent layer separate)
# Installs: nginx-plus, app-protect (NAP WAF v4), attack-signatures, FIPS provider
# Extended: alpine-plus-nap-fips (Agent v2)  •  alpine-plus-nap-fips-agent (Agent v3)
FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS alpine-plus-nap-fips-base
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION
ARG PACKAGE_REPO

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=bind,from=alpine-fips-3.22,target=/tmp/fips/ \
	--mount=type=secret,id=nginx-repo.crt,dst=/etc/apk/cert.pem,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/apk/cert.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=app-protect-security-updates.rsa.pub,target=/etc/apk/keys/app-protect-security-updates.rsa.pub \
	--mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	printf "%s\n" "https://${PACKAGE_REPO}/plus/${NGINX_PLUS_VERSION}/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& printf "%s\n" "https://${PACKAGE_REPO}/app-protect/${NGINX_PLUS_VERSION}/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& printf "%s\n" "https://pkgs.nginx.com/app-protect-security-updates/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& apk add --no-cache libcap-utils libcurl nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check \
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
	&& nap-waf.sh


############################################# NGINX Plus + App Protect WAF v4 + FIPS + Agent v2 on Alpine #############################################
# Base:     alpine-plus-nap-fips-base (NGINX Plus + NAP WAF v4 + FIPS)
# Adds:     nginx-agent v2
# Used as:  BUILD_OS=alpine-plus-nap-fips
FROM alpine-plus-nap-fips-base AS alpine-plus-nap-fips
ARG AGENT_V2_VERSION
ARG PACKAGE_REPO

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/apk/cert.pem,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/apk/cert.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	printf "%s\n" "https://${PACKAGE_REPO}/nginx-agent/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& apk add --no-cache nginx-agent~${AGENT_V2_VERSION} \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories \
	&& agent.sh


############################################# NGINX Plus + App Protect WAF v4 + FIPS + Agent v3 on Alpine #############################################
# Base:     alpine-plus-nap-fips-base (NGINX Plus + NAP WAF v4 + FIPS)
# Adds:     nginx-agent v3
# Used as:  BUILD_OS=alpine-plus-nap-fips-agent
FROM alpine-plus-nap-fips-base AS alpine-plus-nap-fips-agent
ARG AGENT_V3_VERSION
ARG PACKAGE_REPO

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/apk/cert.pem,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/apk/cert.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	printf "%s\n" "https://${PACKAGE_REPO}/nginx-agent/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& apk add --no-cache nginx-agent~${AGENT_V3_VERSION} \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories \
	&& agent.sh


############################################# Intermediate image — NGINX Plus + App Protect WAF v5 + FIPS on Alpine #############################################
# Base:     alpine:3.22 (fresh — does not extend alpine-plus, keeps agent layer separate)
# Installs: nginx-plus, app-protect-module-plus (NAP WAF v5), FIPS provider
# Extended: alpine-plus-nap-v5-fips (Agent v2)  •  alpine-plus-nap-v5-fips-agent (Agent v3)
FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601 AS alpine-plus-nap-v5-fips-base
ARG NGINX_PLUS_VERSION
ARG PACKAGE_REPO
ARG NAP_WAF_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=bind,from=alpine-fips-3.22,target=/tmp/fips/ \
	--mount=type=secret,id=nginx-repo.crt,dst=/etc/apk/cert.pem,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/apk/cert.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	printf "%s\n" "https://${PACKAGE_REPO}/plus/${NGINX_PLUS_VERSION}/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& printf "%s\n" "https://${PACKAGE_REPO}/app-protect-x-plus/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& apk add --no-cache libcap-utils libcurl nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check \
	&& mkdir -p /usr/ssl \
	&& cp -av /tmp/fips/usr/lib/ossl-modules/fips.so /usr/lib/ossl-modules/fips.so \
	&& cp -av /tmp/fips/usr/ssl/fipsmodule.cnf /usr/ssl/fipsmodule.cnf \
	&& cp -av /tmp/fips/etc/ssl/openssl.cnf /etc/ssl/openssl.cnf \
	&& mkdir -p /etc/nginx/reporting/ \
	&& cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& apk add --no-cache app-protect-module-plus~=${NAP_WAF_VERSION/+/.} \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories \
	&& nap-waf.sh


############################################# NGINX Plus + App Protect WAF v5 + FIPS + Agent v2 on Alpine #############################################
# Base:     alpine-plus-nap-v5-fips-base (NGINX Plus + NAP WAF v5 + FIPS)
# Adds:     nginx-agent v2
# Used as:  BUILD_OS=alpine-plus-nap-v5-fips
FROM alpine-plus-nap-v5-fips-base AS alpine-plus-nap-v5-fips
ARG AGENT_V2_VERSION
ARG PACKAGE_REPO

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/apk/cert.pem,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/apk/cert.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	printf "%s\n" "https://${PACKAGE_REPO}/nginx-agent/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& apk add --no-cache nginx-agent~${AGENT_V2_VERSION} \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories \
	&& agent.sh


############################################# NGINX Plus + App Protect WAF v5 + FIPS + Agent v3 on Alpine #############################################
# Base:     alpine-plus-nap-v5-fips-base (NGINX Plus + NAP WAF v5 + FIPS)
# Adds:     nginx-agent v3
# Used as:  BUILD_OS=alpine-plus-nap-v5-fips-agent
FROM alpine-plus-nap-v5-fips-base AS alpine-plus-nap-v5-fips-agent
ARG AGENT_V3_VERSION
ARG PACKAGE_REPO

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/apk/cert.pem,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/apk/cert.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.rsa.pub,target=/etc/apk/keys/nginx_signing.rsa.pub \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	printf "%s\n" "https://${PACKAGE_REPO}/nginx-agent/alpine/v$(grep -E -o '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
	&& apk add --no-cache nginx-agent~${AGENT_V3_VERSION} \
	&& sed -i -e '/nginx.com/d' /etc/apk/repositories \
	&& agent.sh


############################################# Intermediate image — NGINX Plus on Debian 13 (Trixie) #############################################
# Base:     debian:13-slim
# Installs: nginx-plus, nginx-plus-module-njs/otel/fips-check, libcap2-bin, libcurl4
# Extended: debian-plus (Agent v3)  •  debian-plus-nap-base  •  debian-plus-nap-v5-base
FROM debian:13-slim@sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8 AS debian-plus-only
ARG NGINX_PLUS_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=app-protect-security-updates.key,target=/tmp/app-protect-security-updates.key \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=debian-plus-13.sources,target=/tmp/nginx-plus.sources \
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


############################################# Base image for Debian with NGINX Plus #############################################
FROM debian-plus-only AS debian-plus
ARG NGINX_PLUS_VERSION
ARG AGENT_V3_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=debian-agent-13.sources,target=/tmp/nginx-agent.sources \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	apt-get update \
	&& cp /tmp/nginx-agent.sources /etc/apt/sources.list.d/nginx-agent.sources \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y nginx-agent=${AGENT_V3_VERSION}* \
	&& agent.sh \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx-agent.sources


############################################# Intermediate image — NGINX Plus + App Protect WAF/DoS v4 on Debian 13 (Trixie) #############################################
# Base:     debian-plus-only (NGINX Plus)
# Installs: app-protect (NAP WAF/DoS v4), app-protect-ip-intelligence, attack-signatures
# Extended: debian-plus-nap (Agent v2)  •  debian-plus-nap-agent (Agent v3)
FROM debian-plus-only AS debian-plus-nap-base
ARG NAP_MODULES
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION
ARG NAP_WAF_COMMON_VERSION
ARG NAP_WAF_PLUGIN_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=nap-waf-13.sources,target=/tmp/app-protect.sources \
	--mount=type=bind,from=nginx-files,src=nap-dos-13.sources,target=/tmp/app-protect-dos.sources \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=nap-dos.sh,target=/usr/local/bin/nap-dos.sh \
	if [ -z "${NAP_MODULES##*waf*}" ]; then \
	cp /tmp/app-protect.sources /etc/apt/sources.list.d/app-protect.sources \
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
	&& rm -f /etc/apt/sources.list.d/app-protect.sources \
	&& nap-waf.sh; \
	fi \
	&& if [ -z "${NAP_MODULES##*dos*}" ]; then \
	cp /tmp/app-protect-dos.sources /etc/apt/sources.list.d/app-protect-dos.sources \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y app-protect-dos \
	&& rm -f /etc/apt/sources.list.d/app-protect-dos.sources \
	&& nap-dos.sh; \
	fi \
	&& rm -rf /var/lib/apt/lists/*


############################################# Intermediate image — NGINX Plus + App Protect WAF v5 on Debian 13 #############################################
# Base:     debian-plus-only (NGINX Plus)
# Installs: app-protect-module-plus (NAP WAF v5), nginx-plus-module-appprotect
# Extended: debian-plus-nap-v5 (Agent v2)  •  debian-plus-nap-v5-agent (Agent v3)
FROM debian-plus-only AS debian-plus-nap-v5-base
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION
ARG NAP_WAF_PLUGIN_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=nap-waf-v5-13.sources,target=/etc/apt/sources.list.d/app-protect.sources \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y app-protect-module-plus=${NAP_WAF_VERSION}* nginx-plus-module-appprotect=${NAP_WAF_VERSION}* app-protect-plugin=${NAP_WAF_PLUGIN_VERSION}* \
	&& nap-waf.sh


############################################# NGINX Plus + App Protect WAF/DoS v4 + Agent v2 on Debian 13 #############################################
# Base:     debian-plus-nap-base (NGINX Plus + NAP WAF/DoS v4)
# Adds:     nginx-agent v2
# Used as:  BUILD_OS=debian-plus-nap
FROM debian-plus-nap-base AS debian-plus-nap
ARG AGENT_V2_VERSION

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=debian-agent-13.sources,target=/tmp/nginx-agent.sources \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	cp /tmp/nginx-agent.sources /etc/apt/sources.list.d/nginx-agent.sources \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y nginx-agent=${AGENT_V2_VERSION}.* \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx-agent.sources \
	&& agent.sh


############################################# NGINX Plus + App Protect WAF/DoS v4 + Agent v3 on Debian 13 #############################################
# Base:     debian-plus-nap-base (NGINX Plus + NAP WAF/DoS v4)
# Adds:     nginx-agent v3
# Used as:  BUILD_OS=debian-plus-nap-agent
FROM debian-plus-nap-base AS debian-plus-nap-agent
ARG AGENT_V3_VERSION

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=debian-agent-13.sources,target=/tmp/nginx-agent.sources \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	cp /tmp/nginx-agent.sources /etc/apt/sources.list.d/nginx-agent.sources \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y nginx-agent=${AGENT_V3_VERSION}* \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx-agent.sources \
	&& agent.sh


############################################# NGINX Plus + App Protect WAF v5 + Agent v2 on Debian 13 #############################################
# Base:     debian-plus-nap-v5-base (NGINX Plus + NAP WAF v5)
# Adds:     nginx-agent v2
# Used as:  BUILD_OS=debian-plus-nap-v5
FROM debian-plus-nap-v5-base AS debian-plus-nap-v5
ARG AGENT_V2_VERSION

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=debian-agent-13.sources,target=/tmp/nginx-agent.sources \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	cp /tmp/nginx-agent.sources /etc/apt/sources.list.d/nginx-agent.sources \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y nginx-agent=${AGENT_V2_VERSION}.* \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx-agent.sources \
	&& agent.sh


############################################# NGINX Plus + App Protect WAF v5 + Agent v3 on Debian 13 #############################################
# Base:     debian-plus-nap-v5-base (NGINX Plus + NAP WAF v5)
# Adds:     nginx-agent v3
# Used as:  BUILD_OS=debian-plus-nap-v5-agent
FROM debian-plus-nap-v5-base AS debian-plus-nap-v5-agent
ARG AGENT_V3_VERSION

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=90pkgs-nginx,target=/etc/apt/apt.conf.d/90pkgs-nginx \
	--mount=type=bind,from=nginx-files,src=debian-agent-13.sources,target=/tmp/nginx-agent.sources \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	cp /tmp/nginx-agent.sources /etc/apt/sources.list.d/nginx-agent.sources \
	&& apt-get update \
	&& apt-get install --no-install-recommends --no-install-suggests -y nginx-agent=${AGENT_V3_VERSION}* \
	&& rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx-agent.sources \
	&& agent.sh


############################################# Base image for UBI with NGINX Plus #############################################
FROM ubi-minimal AS ubi-10-plus
ARG NGINX_PLUS_VERSION
ARG AGENT_V3_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-10.repo,target=/etc/yum.repos.d/nginx-plus.repo \
	--mount=type=bind,from=nginx-files,src=ubi-setup.sh,target=/usr/local/bin/ubi-setup.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	--mount=type=bind,from=ubi10-packages,src=/,target=/ubi-bin/ \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ubi-setup.sh \
    && printf '[local-deps]\nname=Local UBI Deps\nbaseurl=file:///ubi-bin\nenabled=1\ngpgcheck=0\n' > /etc/yum.repos.d/local-deps.repo \
	&& microdnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check nginx-agent-${AGENT_V3_VERSION}.* \
	&& agent.sh	\
    && rm -rf /etc/yum.repos.d/local-deps.repo \
	&& ubi-clean.sh


############################################# Intermediate image — NGINX Plus + App Protect WAF/DoS v4 on Red Hat UBI 10 #############################################
# Base:     ubi-minimal (Red Hat UBI 10 minimal)
# Installs: nginx-plus, app-protect (NAP WAF/DoS v4), app-protect-ip-intelligence, attack-signatures
# Extended: ubi-10-plus-nap (Agent v2)  •  ubi-10-plus-nap-agent (Agent v3)
FROM ubi-minimal AS ubi-10-plus-nap-base
ARG NAP_MODULES
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-10.repo,target=/etc/yum.repos.d/nginx-plus.repo \
	--mount=type=bind,from=nginx-files,src=app-protect-security-updates.key,target=/tmp/app-protect-security-updates.key \
	--mount=type=bind,from=nginx-files,src=app-protect-10.repo,target=/tmp/app-protect-10.repo \
	--mount=type=bind,from=nginx-files,src=app-protect-dos-10.repo,target=/tmp/app-protect-dos-10.repo \
	--mount=type=bind,from=nginx-files,src=ubi-setup.sh,target=/usr/local/bin/ubi-setup.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=nap-dos.sh,target=/usr/local/bin/nap-dos.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
    --mount=type=bind,from=ubi10-packages,src=/,target=/ubi-bin/ \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ubi-setup.sh \
	&& printf '[local-deps]\nname=Local UBI Deps\nbaseurl=file:///ubi-bin\nenabled=1\ngpgcheck=0\n' > /etc/yum.repos.d/local-deps.repo \
	&& microdnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-fips-check nginx-plus-module-otel \
	&& if [ -z "${NAP_MODULES##*waf*}" ]; then \
        rpm --import /tmp/app-protect-security-updates.key \
        && cp /tmp/app-protect-10.repo /etc/yum.repos.d/app-protect-10.repo \
        && microdnf --nodocs install -y \
            app-protect-${NAP_WAF_VERSION}* \
            app-protect-ip-intelligence \
            app-protect-attack-signatures \
            app-protect-threat-campaigns \
        && rm -f /etc/yum.repos.d/app-protect-10.repo \
        && nap-waf.sh; \
	fi \
	&& if [ -z "${NAP_MODULES##*dos*}" ]; then \
        cp /tmp/app-protect-dos-10.repo /etc/yum.repos.d/app-protect-dos-10.repo \
        && microdnf --nodocs install -y app-protect-dos \
        && rm -f /etc/yum.repos.d/app-protect-dos-10.repo \
        && nap-dos.sh; \
	fi \
	&& rm -f /etc/yum.repos.d/local-deps.repo \
	&& ubi-clean.sh


############################################# Intermediate image — NGINX Plus + App Protect WAF v5 on Red Hat UBI 10 #############################################
# Base:     ubi-minimal (Red Hat UBI 10 minimal)
# Installs: nginx-plus, app-protect-module-plus (NAP WAF v5)
# Extended: ubi-10-plus-nap-v5 (Agent v2)  •  ubi-10-plus-nap-v5-agent (Agent v3)
FROM ubi-minimal AS ubi-10-plus-nap-v5-base
ARG NGINX_PLUS_VERSION
ARG NAP_WAF_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-10.repo,target=/etc/yum.repos.d/nginx-plus.repo \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=app-protect-v5.repo,target=/etc/yum.repos.d/app-protect-v5.repo \
	--mount=type=bind,from=nginx-files,src=ubi-setup.sh,target=/usr/local/bin/ubi-setup.sh \
	--mount=type=bind,from=nginx-files,src=nap-waf.sh,target=/usr/local/bin/nap-waf.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
	--mount=type=bind,from=ubi10-packages,src=/,target=/ubi-bin/ \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ubi-setup.sh \
	&& microdnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-fips-check \
	&& rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm \
	&& rpm -Uvh /ubi-bin/c-ares-*.rpm \
	&& microdnf --nodocs install -y ca-certificates shadow-utils \
	&& microdnf --nodocs install -y nginx-plus-module-otel app-protect-module-plus-${NAP_WAF_VERSION}* \
	&& nap-waf.sh \
	&& ubi-clean.sh


############################################# NGINX Plus + App Protect WAF v5 + Agent v2 on Red Hat UBI 10 #############################################
# Base:     ubi-10-plus-nap-v5-base (NGINX Plus + NAP WAF v5)
# Adds:     nginx-agent v2
# Used as:  BUILD_OS=ubi-10-plus-nap-v5
FROM ubi-10-plus-nap-v5-base AS ubi-10-plus-nap-v5
ARG AGENT_V2_VERSION

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	microdnf --nodocs install -y nginx-agent-${AGENT_V2_VERSION}.* \
	&& microdnf clean all \
	&& agent.sh


############################################# NGINX Plus + App Protect WAF v5 + Agent v3 on Red Hat UBI 10 #############################################
# Base:     ubi-10-plus-nap-v5-base (NGINX Plus + NAP WAF v5)
# Adds:     nginx-agent v3
# Used as:  BUILD_OS=ubi-10-plus-nap-v5-agent
FROM ubi-10-plus-nap-v5-base AS ubi-10-plus-nap-v5-agent
ARG AGENT_V3_VERSION

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	microdnf --nodocs install -y nginx-agent-${AGENT_V3_VERSION}.* \
	&& microdnf clean all \
	&& agent.sh


############################################# NGINX Plus + Agent v3 on Red Hat UBI 10 #############################################
# Base:     ubi-minimal (Red Hat UBI 10 minimal)
# Adds:     nginx-plus, nginx-plus-module-njs/otel/fips-check, nginx-agent v3
# Used as:  BUILD_OS=ubi-10-plus-agent
FROM ubi-minimal AS ubi-10-plus-agent
ARG NGINX_PLUS_VERSION
ARG AGENT_V3_VERSION

ENV NGINX_VERSION=${NGINX_PLUS_VERSION}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx_signing.key,target=/tmp/nginx_signing.key \
	--mount=type=bind,from=nginx-files,src=nginx-plus-10.repo,target=/etc/yum.repos.d/nginx-plus.repo \
	--mount=type=bind,from=ubi10-packages,src=/,target=/ubi-bin/ \
	--mount=type=bind,from=nginx-files,src=ubi-setup.sh,target=/usr/local/bin/ubi-setup.sh \
	--mount=type=bind,from=nginx-files,src=ubi-clean.sh,target=/usr/local/bin/ubi-clean.sh \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	--mount=type=bind,from=nginx-files,src=tracking.info,target=/tmp/nginx/reporting/tracking.info \
	mkdir -p /etc/nginx/reporting/ && cp -av /tmp/nginx/reporting/tracking.info /etc/nginx/reporting/tracking.info \
	&& ubi-setup.sh \
	&& rpm -Uvh /ubi-bin/c-ares-*.rpm \
	&& microdnf --nodocs install -y nginx-plus nginx-plus-module-njs nginx-plus-module-otel nginx-plus-module-fips-check nginx-agent-${AGENT_V3_VERSION}.* \
	&& agent.sh	\
	&& ubi-clean.sh


############################################# NGINX Plus + App Protect WAF/DoS v4 + Agent v2 on Red Hat UBI 10 #############################################
# Base:     ubi-10-plus-nap-base (NGINX Plus + NAP WAF/DoS v4)
# Adds:     nginx-agent v2
# Used as:  BUILD_OS=ubi-10-plus-nap
FROM ubi-10-plus-nap-base AS ubi-10-plus-nap
ARG AGENT_V2_VERSION

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	microdnf --nodocs install -y nginx-agent-${AGENT_V2_VERSION}.* \
	&& microdnf clean all \
	&& agent.sh


############################################# NGINX Plus + App Protect WAF/DoS v4 + Agent v3 on Red Hat UBI 10 #############################################
# Base:     ubi-10-plus-nap-base (NGINX Plus + NAP WAF/DoS v4)
# Adds:     nginx-agent v3
# Used as:  BUILD_OS=ubi-10-plus-nap-agent
FROM ubi-10-plus-nap-base AS ubi-10-plus-nap-agent
ARG AGENT_V3_VERSION

RUN --mount=type=secret,id=nginx-repo.crt,dst=/etc/ssl/nginx/nginx-repo.crt,mode=0644 \
	--mount=type=secret,id=nginx-repo.key,dst=/etc/ssl/nginx/nginx-repo.key,mode=0644 \
	--mount=type=bind,from=nginx-files,src=nginx-agent.repo,target=/etc/yum.repos.d/nginx-agent.repo,rw \
	--mount=type=bind,from=nginx-files,src=agent.sh,target=/usr/local/bin/agent.sh \
	microdnf --nodocs install -y nginx-agent-${AGENT_V3_VERSION}.* \
	&& microdnf clean all \
	&& agent.sh


############################################# common — final shared configuration for all image variants #############################################
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


############################################# builder — compiles nginx-ingress for production #############################################
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


############################################# debug-builder — compiles nginx-ingress without optimisations and installs Delve #############################################
FROM golang-builder AS debug-builder
ARG TARGETARCH

WORKDIR /go/src/github.com/nginx/kubernetes-ingress/
RUN apk add --no-cache git
RUN --mount=type=bind,target=/go/src/github.com/nginx/kubernetes-ingress/ --mount=type=cache,target=/root/.cache/go-build \
	go mod download
RUN --mount=type=bind,target=/go/src/github.com/nginx/kubernetes-ingress/ --mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -gcflags "all=-N -l" -o /nginx-ingress github.com/nginx/kubernetes-ingress/cmd/nginx-ingress
RUN CGO_ENABLED=0 go install -ldflags "-s -w -extldflags '-static'" github.com/go-delve/delve/cmd/dlv@latest


############################################# container — binary from builder stage #############################################
FROM common AS container

LABEL org.nginx.kic.image.build.version="container"

COPY --link --from=builder --chown=101:0 /nginx-ingress /


############################################# local — host-compiled binary into common #############################################
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


############################################# debug — host binary + Delve, entrypoint /dlv #############################################
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


############################################# debug-container — Docker binary + Delve, entrypoint /dlv #############################################
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


############################################# local-prebuilt — host binary into pre-downloaded base image #############################################
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


############################################# goreleaser-setcap — sets cap_net_bind_service on GoReleaser binary #############################################
FROM common AS goreleaser-setcap
ARG TARGETARCH

COPY --link --chown=101:0 dist/kubernetes-ingress_linux_${TARGETARCH}*/nginx-ingress /
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


############################################# goreleaser — binary from GoReleaser dist/ #############################################
FROM common AS goreleaser
ARG TARGETARCH

LABEL org.nginx.kic.image.build.version="goreleaser"

COPY --link --chown=101:0 --from=goreleaser-setcap /nginx-ingress /


############################################# goreleaser-setcap-prebuilt — sets cap_net_bind_service on GoReleaser binary (prebuilt) #############################################
FROM ${PREBUILT_BASE_IMG} AS goreleaser-setcap-prebuilt
ARG TARGETARCH

COPY --link --chown=101:0 dist/kubernetes-ingress_linux_${TARGETARCH}*/nginx-ingress /
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


############################################# goreleaser-prebuilt — GoReleaser binary into pre-downloaded base image #############################################
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


############################################# aws-setcap — sets cap_net_bind_service on AWS binary #############################################
FROM common AS aws-setcap
ARG TARGETARCH
ARG NAP_MODULES_AWS

COPY --link --chown=101:0 dist/aws*${NAP_MODULES_AWS}_linux_${TARGETARCH}*/nginx-ingress /
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


############################################# aws — GoReleaser binary for AWS Marketplace #############################################
FROM common AS aws
ARG TARGETARCH
ARG NAP_MODULES_AWS

LABEL org.nginx.kic.image.build.version="aws"

COPY --link --chown=101:0 --from=aws-setcap /nginx-ingress /


############################################# aws-setcap-prebuilt — sets cap_net_bind_service on AWS binary (prebuilt) #############################################
FROM ${PREBUILT_BASE_IMG} AS aws-setcap-prebuilt
ARG TARGETARCH
ARG NAP_MODULES_AWS

COPY --link --chown=101:0 dist/aws*${NAP_MODULES_AWS}_linux_${TARGETARCH}*/nginx-ingress /
USER 0
RUN setcap 'cap_net_bind_service=+ep' /nginx-ingress && setcap -v 'cap_net_bind_service=+ep' /nginx-ingress


############################################# aws-prebuilt — AWS Marketplace binary into pre-downloaded base image #############################################
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


############################################# download — nginx-ingress binary from published image #############################################
FROM nginx/nginx-ingress:${DOWNLOAD_TAG} AS kic

FROM common AS download

LABEL org.nginx.kic.image.build.version="binaries"

COPY --link --from=kic --chown=101:0 /nginx-ingress /

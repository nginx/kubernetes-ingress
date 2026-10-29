# syntax=docker/dockerfile:1.28
FROM python:3.15-trixie@sha256:8268b5058c72832502a7eabc0c719892769c09389ed95fc213f3c308cbedc6dd
ARG ARCH=amd64
# renovate: datasource=github-releases depName=helm/helm
ARG HELM_VERSION=v4.3.1

ENV PYTHONUNBUFFERED=1
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

RUN --mount=type=secret,id=corp-ca,dst=/tmp/corp-ca,required=false \
	if [ -s /tmp/corp-ca ]; then \
		cp /tmp/corp-ca /usr/local/share/ca-certificates/corp-ca.crt; \
	fi \
	&& apt-get update \
	&& apt-get install -y curl git apache2-utils ca-certificates \
	&& update-ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/tests


COPY --link tests/requirements.txt /workspace/tests/
COPY --link deployments /workspace/deployments
COPY --link config /workspace/config
COPY --link tests /workspace/tests
COPY --link pyproject.toml /workspace/pyproject.toml

RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/${ARCH}/kubectl \
	&& install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl \
	&& install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
	&& printf "Types: deb\nURIs: https://download.docker.com/linux/debian\nSuites: %s\nComponents: stable\nSigned-By: /etc/apt/keyrings/docker.asc\n" "$( . /etc/os-release && echo "$VERSION_CODENAME" )" > /etc/apt/sources.list.d/docker.sources \
	&& apt update \
    && apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

RUN curl -fsSLO https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH}.tar.gz \
	&& curl -fsSL https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH}.tar.gz.sha256sum | sha256sum -c - \
	&& tar -xzf helm-${HELM_VERSION}-linux-${ARCH}.tar.gz linux-${ARCH}/helm \
	&& install -o root -g root -m 0755 linux-${ARCH}/helm /usr/local/bin/helm \
	&& rm -rf helm-${HELM_VERSION}-linux-${ARCH}.tar.gz linux-${ARCH}

RUN pip install --require-hashes -r requirements.txt --no-deps
RUN playwright install chromium
RUN playwright install-deps chromium

ENTRYPOINT ["python3", "-m", "pytest"]

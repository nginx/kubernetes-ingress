# syntax=docker/dockerfile:1.16
# this is here so we can grab the latest version of kind and have dependabot keep it up to date
FROM kindest/node:v1.33.2@sha256:c55080dc5be4f2cc242e6966fdf97bb62282e1cd818a28223cf536db8b0fddf4

# this is here so we can grab the latest version of skopeo and have dependabot keep it up to date
FROM quay.io/skopeo/stable:v1.19.0

FROM python:3.13-bookworm@sha256:aba8a0cd72f259c2737c8a47050652036c8bc8266a4f39291523a45cf8081960

RUN apt-get update \
	&& apt-get install -y curl git apache2-utils \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/tests


COPY --link tests/requirements.txt /workspace/tests/
COPY --link deployments /workspace/deployments
COPY --link config /workspace/config
COPY --link tests /workspace/tests
COPY --link pyproject.toml /workspace/pyproject.toml

RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl \
	&& install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl \
    && curl https://get.docker.com/builds/Linux/x86_64/docker-latest.tgz | tar xvz -C /tmp/ && mv /tmp/docker/docker /usr/bin/docker

RUN pip install --require-hashes -r requirements.txt --no-deps
RUN playwright install chromium
RUN playwright install-deps chromium

ENTRYPOINT ["python3", "-m", "pytest"]

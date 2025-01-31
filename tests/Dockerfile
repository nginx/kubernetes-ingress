# syntax=docker/dockerfile:1.5
# this is here so we can grab the latest version of kind and have dependabot keep it up to date
FROM kindest/node:v1.32.1@sha256:6afef2b7f69d627ea7bf27ee6696b6868d18e03bf98167c420df486da4662db6

# this is here so we can grab the latest version of skopeo and have dependabot keep it up to date
FROM quay.io/skopeo/stable:v1.17.0

FROM python:3.13@sha256:137ae4b9f85671bd912a82a19b6966e2655f73e13579b5d6ad4edbddaaf62a9c

RUN apt-get update \
	&& apt-get install -y curl git \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/tests

COPY --link tests/requirements.txt /workspace/tests/
RUN pip install --require-hashes -r requirements.txt --no-deps
RUN playwright install --with-deps chromium

COPY --link deployments /workspace/deployments
COPY --link config /workspace/config

RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl \
	&& install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl \
	&& apt-get update && apt-get install -y apache2-utils

RUN apt update -y \
	&& curl https://get.docker.com/builds/Linux/x86_64/docker-latest.tgz | tar xvz -C /tmp/ && mv /tmp/docker/docker /usr/bin/docker

COPY --link tests /workspace/tests

COPY --link pyproject.toml /workspace/

ENTRYPOINT ["python3", "-m", "pytest"]

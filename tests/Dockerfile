# syntax=docker/dockerfile:1.11
# this is here so we can grab the latest version of kind and have dependabot keep it up to date
FROM kindest/node:v1.32.3@sha256:b36e76b4ad37b88539ce5e07425f77b29f73a8eaaebf3f1a8bc9c764401d118c

# this is here so we can grab the latest version of skopeo and have dependabot keep it up to date
FROM quay.io/skopeo/stable:v1.18.0

FROM python:3.13@sha256:1f7ef1e8f35bc8629b05f4df943175f2851ba05f4a509f72304ebffde78178ee

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
RUN playwright install --with-deps chromium

ENTRYPOINT ["python3", "-m", "pytest"]

# syntax=docker/dockerfile:1.18
FROM python:3.13-bookworm@sha256:f64a1db27d5d0fdcb48a54c553e67b0ec920c8a1ef0b627e87b8d3d73dc003fb

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

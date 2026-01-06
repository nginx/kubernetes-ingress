SHELL                       = /bin/bash
ROOT_DIR                    = $(shell git rev-parse --show-toplevel)
CONTEXT                     =
PULL_POLICY                 ?= IfNotPresent
DEPLOYMENT_TYPE             = deployment
SERVICE                     = nodeport
NODE_IP                     =
TEST_PREFIX                 = test-runner
KUBE_CONFIG_FOLDER          = ${HOME}/.kube
KIND_KUBE_CONFIG_FOLDER     = $(KUBE_CONFIG_FOLDER)/kind
MINIKUBE_KUBE_CONFIG_FOLDER = $(KUBE_CONFIG_FOLDER)/minikube
DOCKERFILEPATH              := ${ROOT_DIR}/tests/Dockerfile
PYTHON                      ?= python3
IP_FAMILY                   = dual
IC_TYPE                     ?= nginx-ingress ## The Ingress Controller type to use, "nginx-ingress" or "nginx-plus-ingress".  Defaults to "nginx-ingress"
SHOW_IC_LOGS                ?= no ## Should the tests show the Ingress Controller logs on failure, "yes" or "no". Defaults to "no"
TEST_TAG                    ?= latest ## The Tag to use for the test image. e.g. commitsha
REGISTRY                    ?= docker.io ## The registry where the image is located. For example, docker.io
PREFIX                      ?= nginx/nginx-ingress ## The name of the image. For example, nginx/nginx-ingress
TAG                         ?= edge ## The tag of the image. For example, edge
K8S_CLUSTER_NAME            ?= local ## The name used when creating/using a Kind Kubernetes cluster
# renovate: datasource=docker depName=kindest/node
K8S_CLUSTER_VERSION         ?= v1.35.0
K8S_TIMEOUT                 ?= 75s ## The timeout used when creating a Kind Kubernetes cluster
PLUS_JWT                    ?=
PYTEST_ARGS                 ?=
ifeq (${REGISTRY},)
BUILD_IMAGE                 := $(strip $(PREFIX)):$(strip $(TAG))
else
BUILD_IMAGE                 := $(strip $(REGISTRY))/$(strip $(PREFIX)):$(strip $(TAG))
endif

.PHONY: help ## Show this help
help: ## Show available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "; printf "Usage:\n\n    make \033[36m<target>\033[0m [VARIABLE=value...]\n\nTargets:\n\n"}; {printf "    \033[36m%-30s\033[0m %s\n", $$1, $$2}'


.PHONY: build
build: ## Run build
	docker build -t $(TEST_PREFIX):$(TEST_TAG) -f $(DOCKERFILEPATH) $(ROOT_DIR)


$(KUBE_CONFIG_FOLDER):
	@mkdir -p $@


$(KIND_KUBE_CONFIG_FOLDER): $(KUBE_CONFIG_FOLDER)
	@mkdir -p $@


$(MINIKUBE_KUBE_CONFIG_FOLDER): $(KUBE_CONFIG_FOLDER)
	@mkdir -p $@


.PHONY: setup-venv
setup-venv:
	$(PYTHON) -m venv $(ROOT_DIR)/tests/venv;
	source $(ROOT_DIR)/tests/venv/bin/activate \
	&& pip install --require-hashes -r $(ROOT_DIR)/tests/requirements.txt --no-deps \
	&& playwright install --with-deps chromium


.PHONY: clean-venv
clean-venv:
	@rm -rf $(ROOT_DIR)/tests/venv


.PHONY: run-local-tests
run-local-tests: ## Run tests
	source $(ROOT_DIR)/tests/venv/bin/activate \
	&& pytest \
		--image=$(BUILD_IMAGE) \
		--image-pull-policy=$(PULL_POLICY) \
		--deployment-type=$(DEPLOYMENT_TYPE) \
		--ic-type=$(IC_TYPE) \
		--service=$(SERVICE) \
		--node-ip=$(NODE_IP) \
		--show-ic-logs=$(SHOW_IC_LOGS) \
		--plus-jwt=$(PLUS_JWT) \
		-sv \
		$(PYTEST_ARGS)


.PHONY: run-tests
run-tests: ## Run tests
	docker run --rm -v $(KUBE_CONFIG_FOLDER):/root/.kube \
		$(TEST_PREFIX):$(TEST_TAG) \
		--context=$(CONTEXT) \
		--image=$(BUILD_IMAGE) \
		--image-pull-policy=$(PULL_POLICY) \
		--deployment-type=$(DEPLOYMENT_TYPE) \
		--ic-type=$(IC_TYPE) \
		--service=$(SERVICE) \
		--node-ip=$(NODE_IP) \
		--show-ic-logs=$(SHOW_IC_LOGS) \
		--plus-jwt=$(PLUS_JWT) \
		$(PYTEST_ARGS)


.PHONY: run-tests-in-kind
run-tests-in-kind: ## Run tests in Kind
	docker run --network=kind --rm \
		-v $(KIND_KUBE_CONFIG_FOLDER):/root/.kube \
		-v $(ROOT_DIR)/tests:/workspace/tests \
		-v $(ROOT_DIR)/examples/common-secrets:/workspace/examples/common-secrets \
		-v $(ROOT_DIR)/deployments:/workspace/deployments \
		-v $(ROOT_DIR)/config:/workspace/config \
		-v $(ROOT_DIR)/pyproject.toml:/workspace/pyproject.toml \
		$(TEST_PREFIX):$(TEST_TAG) \
 		--context=kind-$(strip $(K8S_CLUSTER_NAME)) \
 		--image=$(BUILD_IMAGE) --image-pull-policy=$(PULL_POLICY) \
 		--deployment-type=$(DEPLOYMENT_TYPE) \
 		--ic-type=$(IC_TYPE) \
 		--service=nodeport \
 		--node-ip=$(strip $(K8S_CLUSTER_NAME))-control-plane \
 		--show-ic-logs=$(SHOW_IC_LOGS) \
		--plus-jwt=$(PLUS_JWT) \
 		$(PYTEST_ARGS)


.PHONY: create-kind-cluster
create-kind-cluster: $(KIND_KUBE_CONFIG_FOLDER) ## Create a Kind K8S cluster
	@kind create cluster \
		--name $(K8S_CLUSTER_NAME) \
		--image=kindest/node:$(K8S_CLUSTER_VERSION) \
		--config=<(sed 's/dual/${IP_FAMILY}/' $(ROOT_DIR)/tests/ci-files/ci-kind-config.yaml) \
		--wait $(K8S_TIMEOUT)
	@kind get kubeconfig --name $(K8S_CLUSTER_NAME) --internal > $(KIND_KUBE_CONFIG_FOLDER)/config


.PHONY: delete-kind-cluster
delete-kind-cluster: ## Delete a Kind K8S cluster
	@kind delete cluster --name $(K8S_CLUSTER_NAME)
	@rm -f $(KIND_KUBE_CONFIG_FOLDER)/config


.PHONY: image-load
image-load: ## Load the image into the Kind K8S cluster
	@kind load docker-image $(BUILD_IMAGE) --name $(K8S_CLUSTER_NAME)


.PHONY: run-tests-in-minikube
run-tests-in-minikube: ## Run tests in Minikube
	docker run --network=minikube --rm \
		-v $(MINIKUBE_KUBE_CONFIG_FOLDER):/root/.kube \
		-v $(ROOT_DIR)/tests:/workspace/tests \
		-v $$HOME/.minikube:$$HOME/.minikube \
		-v $(ROOT_DIR)/examples/common-secrets:/workspace/examples/common-secrets \
		-v $(ROOT_DIR)/deployments:/workspace/deployments \
		-v $(ROOT_DIR)/config:/workspace/config \
		-v $(ROOT_DIR)/pyproject.toml:/workspace/pyproject.toml \
		$(TEST_PREFIX):$(TEST_TAG) \
 		--context=minikube \
 		--image=$(BUILD_IMAGE) --image-pull-policy=$(PULL_POLICY) \
 		--deployment-type=$(DEPLOYMENT_TYPE) \
 		--ic-type=$(IC_TYPE) \
 		--service=nodeport \
 		--node-ip=minikube \
 		--show-ic-logs=$(SHOW_IC_LOGS) \
		--plus-jwt=$(PLUS_JWT) \
 		$(PYTEST_ARGS)


.PHONY: create-mini-cluster
create-mini-cluster: $(MINIKUBE_KUBE_CONFIG_FOLDER) ## Create a Minikube K8S cluster
	@minikube start --kubernetes-version=$(K8S_CLUSTER_VERSION) \
	&& KUBECONFIG=$(MINIKUBE_KUBE_CONFIG_FOLDER)/config minikube update-context \
	&& KUBECONFIG=$(MINIKUBE_KUBE_CONFIG_FOLDER)/config kubectl config set-cluster minikube --server=https://minikube:8443


.PHONY: delete-mini-cluster
delete-mini-cluster: ## Delete a Minikube K8S cluster
	@minikube delete
	@rm -f $(MINIKUBE_KUBE_CONFIG_FOLDER)/config


.PHONY: mini-image-load
mini-image-load: ## Load the image into the Minikube K8S cluster
	@minikube image load $(BUILD_IMAGE)


.PHONY: test-lint
test-lint: ## Run Python linting tools
	isort .
	black .


.PHONY: upgrade-resources
upgrade-resources:
## Create and delete resources for upgrade tests e.g. `make upgrade-resources PYTEST_ARGS="create OR delete"`
	pip install -r ../tests/requirements.txt --no-deps
	pytest -v -s -m $(PYTEST_ARGS)

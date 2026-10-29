SHELL                       = /bin/bash
ROOT_DIR                    = $(shell git rev-parse --show-toplevel)
CONTEXT                     =
PULL_POLICY                 ?= IfNotPresent
DEPLOYMENT_TYPE             = deployment
SERVICE                     ?= nodeport
NODE_IP                     =
LB_IP                       ?=
TEST_PREFIX                 = test-runner
KUBE_CONFIG_FOLDER          = ${HOME}/.kube
KIND_KUBE_CONFIG_FOLDER     = $(KUBE_CONFIG_FOLDER)/kind
MINIKUBE_KUBE_CONFIG_FOLDER = $(KUBE_CONFIG_FOLDER)/minikube
DOCKERFILEPATH              := ${ROOT_DIR}/tests/Dockerfile
PYTHON                      ?= python3
IP_FAMILY                   = dual
IC_TYPE                     ?= nginx-ingress ## The Ingress Controller type to use, "nginx-ingress" or "nginx-plus-ingress".  Defaults to "nginx-ingress"
SHOW_IC_LOGS                ?= no ## Should the tests show the Ingress Controller logs on failure, "yes" or "no". Defaults to "no"
TEST_TAG                    ?= latest ## The Tag to use for the test image. e.g. commitsha
REGISTRY                    ?= docker.io ## The registry where the image is located. For example, docker.io
PREFIX                      ?= nginx/nginx-ingress ## The name of the image. For example, nginx/nginx-ingress
TAG                         ?= edge ## The tag of the image. For example, edge
K8S_CLUSTER_NAME            ?= local ## The name used when creating/using a Kind Kubernetes cluster
# renovate: datasource=docker depName=kindest/node
K8S_CLUSTER_VERSION         ?= v1.37.0
K8S_TIMEOUT                 ?= 75s ## The timeout used when creating a Kind Kubernetes cluster
PLUS_JWT                    ?=
PYTEST_ARGS                 ?=
# Extra arguments for `minikube start`, e.g. --memory=4g --cpus=4
MINIKUBE_ARGS               ?=
# Go e2e parallel PoC (tests/e2e). Cluster access comes from .e2e/kubeconfig, see e2e-poc-cluster.
E2E_DIR                     = $(ROOT_DIR)/.e2e
E2E_KUBECONFIG              = $(E2E_DIR)/kubeconfig.local
# Where minikube's published ports are reachable: the Docker Desktop host from inside a container, else localhost
E2E_HOST                    ?= $(if $(wildcard /.dockerenv),host.docker.internal,127.0.0.1)
E2E_MINIKUBE_ARGS           ?= --memory=4g --cpus=4 --ports=30080:30080,30443:30443
E2E_IMAGE_REPO              ?= nginx/nginx-ingress
E2E_IMAGE_TAG               ?= edge
PROCS                       ?= 4
COPIES                      ?= 4
REPEAT                      ?= 0
# Extra ginkgo flags, e.g. GINKGO_ARGS="--focus-file=virtual_server_tls_test.go"
GINKGO_ARGS                 ?=
ifeq (${REGISTRY},)
BUILD_IMAGE                 := $(strip $(PREFIX)):$(strip $(TAG))
else
BUILD_IMAGE                 := $(strip $(REGISTRY))/$(strip $(PREFIX)):$(strip $(TAG))
endif
# Dynamically determine architecture
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),arm64)
    ARCH ?= arm64
else ifeq ($(UNAME_M),x86_64)
    ARCH ?= amd64
else
    ARCH ?= $(UNAME_M)
endif

.PHONY: help ## Show this help
help: ## Show available make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "; printf "Usage:\n\n    make \033[36m<target>\033[0m [VARIABLE=value...]\n\nTargets:\n\n"}; {printf "    \033[36m%-30s\033[0m %s\n", $$1, $$2}'


ifneq ($(strip $(CURL_CA_BUNDLE)),)
VALID_CA := $(shell if [ -f "$(CURL_CA_BUNDLE)" ] && { openssl x509 -in "$(CURL_CA_BUNDLE)" -noout >/dev/null 2>&1 || grep -q -- "-----BEGIN CERTIFICATE-----" "$(CURL_CA_BUNDLE)" 2>/dev/null; }; then echo "$(CURL_CA_BUNDLE)"; fi)
ifneq ($(VALID_CA),)
BUILD_SECRET_ARGS := --secret id=corp-ca,src=$(VALID_CA)
endif
endif

.PHONY: build
build: ## Run build
ifneq ($(strip $(CURL_CA_BUNDLE)),)
ifneq ($(VALID_CA),)
	@echo "Using custom CA bundle from CURL_CA_BUNDLE: $(VALID_CA)"
else
	@echo "WARNING: CURL_CA_BUNDLE is set ('$(CURL_CA_BUNDLE)') but is not a valid certificate bundle file; skipping secret mount."
endif
endif
	docker build $(BUILD_SECRET_ARGS) --build-arg ARCH=$(ARCH) -t $(TEST_PREFIX):$(TEST_TAG) -f $(DOCKERFILEPATH) $(ROOT_DIR)


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
run-local-tests: secrets ## Run tests
	source $(ROOT_DIR)/tests/venv/bin/activate \
	&& pytest \
		--image=$(BUILD_IMAGE) \
		--image-pull-policy=$(PULL_POLICY) \
		--deployment-type=$(DEPLOYMENT_TYPE) \
		--ic-type=$(IC_TYPE) \
		--service=$(SERVICE) \
		--node-ip=$(NODE_IP) \
		--lb-ip=$(LB_IP) \
		--show-ic-logs=$(SHOW_IC_LOGS) \
		--plus-jwt=$(PLUS_JWT) \
		-sv \
		$(PYTEST_ARGS)


.PHONY: run-tests
run-tests: secrets ## Run tests
	docker run --rm -v $(KUBE_CONFIG_FOLDER):/root/.kube \
		$(TEST_PREFIX):$(TEST_TAG) \
		--context=$(CONTEXT) \
		--image=$(BUILD_IMAGE) \
		--image-pull-policy=$(PULL_POLICY) \
		--deployment-type=$(DEPLOYMENT_TYPE) \
		--ic-type=$(IC_TYPE) \
		--service=$(SERVICE) \
		--node-ip=$(NODE_IP) \
		--lb-ip=$(LB_IP) \
		--show-ic-logs=$(SHOW_IC_LOGS) \
		--plus-jwt=$(PLUS_JWT) \
		$(PYTEST_ARGS)


.PHONY: run-tests-in-kind
run-tests-in-kind: secrets ## Run tests in Kind
	docker run --network=kind --rm \
		-v $(KIND_KUBE_CONFIG_FOLDER):/root/.kube \
		-v $(ROOT_DIR)/tests:/workspace/tests \
		-v $(ROOT_DIR)/common-secrets:/workspace/common-secrets \
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
create-kind-cluster: $(KIND_KUBE_CONFIG_FOLDER) ## Create a Kind K8S cluster
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
image-load: ## Load the image into the Kind K8S cluster
	@docker save $(BUILD_IMAGE) | \
		docker exec --privileged -i $(K8S_CLUSTER_NAME)-control-plane \
			ctr --namespace=k8s.io images import -


.PHONY: run-tests-in-minikube
run-tests-in-minikube: secrets ## Run tests in Minikube
	docker run --network=minikube --rm \
		-v $(MINIKUBE_KUBE_CONFIG_FOLDER):/root/.kube \
		-v $(ROOT_DIR)/tests:/workspace/tests \
		-v $$HOME/.minikube:$$HOME/.minikube \
		-v $(ROOT_DIR)/common-secrets:/workspace/common-secrets \
		-v $(ROOT_DIR)/charts:/workspace/charts \
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
create-mini-cluster: $(MINIKUBE_KUBE_CONFIG_FOLDER) ## Create a Minikube K8S cluster
	@minikube start $(MINIKUBE_ARGS) --kubernetes-version=$(K8S_CLUSTER_VERSION) \
	&& KUBECONFIG=$(MINIKUBE_KUBE_CONFIG_FOLDER)/config minikube update-context \
	&& KUBECONFIG=$(MINIKUBE_KUBE_CONFIG_FOLDER)/config kubectl config set-cluster minikube --server=https://minikube:8443


.PHONY: delete-mini-cluster
delete-mini-cluster: ## Delete a Minikube K8S cluster
	@minikube delete
	@rm -f $(MINIKUBE_KUBE_CONFIG_FOLDER)/config


.PHONY: mini-image-load
mini-image-load: ## Load the image into the Minikube K8S cluster
	@minikube image load $(BUILD_IMAGE)


.PHONY: e2e-poc-cluster
e2e-poc-cluster: ## Run on the host: recreate minikube with the e2e PoC NodePorts published and export .e2e/kubeconfig
	@$(MAKE) delete-mini-cluster
	@$(MAKE) create-mini-cluster MINIKUBE_ARGS="$(E2E_MINIKUBE_ARGS)"
	@$(MAKE) e2e-poc-kubeconfig
	@docker port minikube | grep -E '^30(080|443)/' || { echo "NodePorts 30080/30443 are not published by minikube"; exit 1; }


.PHONY: e2e-poc-kubeconfig
e2e-poc-kubeconfig: ## Run on the host after every `minikube start`: export .e2e/kubeconfig
	@mkdir -p $(E2E_DIR)
	@kubectl config view --context minikube --minify --flatten > $(E2E_DIR)/kubeconfig


$(E2E_DIR)/kubeconfig:
	@echo "Missing $@. On the host run: make -C tests e2e-poc-cluster (first time) or make -C tests e2e-poc-kubeconfig"; exit 1


# Same cluster, addressed via E2E_HOST. The API server cert does not cover E2E_HOST, so verify it as "minikube".
$(E2E_KUBECONFIG): $(E2E_DIR)/kubeconfig
	@cp $< $@
	@cluster=$$(kubectl --kubeconfig $@ config view -o jsonpath='{.clusters[0].name}'); \
	server=$$(kubectl --kubeconfig $@ config view -o jsonpath='{.clusters[0].cluster.server}'); \
	kubectl --kubeconfig $@ config set-cluster $$cluster --server=$${server/127.0.0.1/$(E2E_HOST)} --tls-server-name=minikube >/dev/null


.PHONY: e2e-poc-deploy
e2e-poc-deploy: $(E2E_KUBECONFIG) ## Install/upgrade the shared Ingress Controller used by the e2e PoC
	@kubectl --kubeconfig $(E2E_KUBECONFIG) get --raw /readyz >/dev/null || { \
		echo "Cannot reach the cluster at $(E2E_HOST). Is minikube running? On the host run: make -C tests e2e-poc-kubeconfig"; exit 1; }
	helm upgrade --install nic $(ROOT_DIR)/charts/nginx-ingress --kubeconfig $(E2E_KUBECONFIG) \
		--namespace nginx-ingress --create-namespace --wait --timeout 5m \
		--set controller.image.repository=$(E2E_IMAGE_REPO) --set controller.image.tag=$(E2E_IMAGE_TAG) \
		--set controller.service.type=NodePort \
		--set controller.service.httpPort.nodePort=30080 --set controller.service.httpsPort.nodePort=30443 \
		--set prometheus.create=true


.PHONY: e2e-poc
e2e-poc: e2e-poc-deploy secrets ## Run the Go e2e parallel PoC, e.g. make e2e-poc PROCS=4 COPIES=4 REPEAT=0
	cd $(ROOT_DIR) && KUBECONFIG=$(E2E_KUBECONFIG) E2E_HOST=$(E2E_HOST) E2E_COPIES=$(COPIES) E2E_ARTIFACTS=$(E2E_DIR)/artifacts \
		go tool ginkgo -tags e2e --procs=$(PROCS) --repeat=$(REPEAT) \
		--output-dir=$(E2E_DIR) --json-report=report-procs$(PROCS).json $(GINKGO_ARGS) ./tests/e2e/poc


.PHONY: test-lint
test-lint: ## Run Python linting tools
	isort .
	black .


.PHONY: upgrade-resources
upgrade-resources:
## Create and delete resources for upgrade tests e.g. `make upgrade-resources PYTEST_ARGS="create OR delete"`
	pip install -r ../tests/requirements.txt --no-deps
	pytest -v -s -m $(PYTEST_ARGS)

.PHONY: secrets-clean
secrets-clean: ## Clean just in time TLS certificates etc needed for tests
	@make -C $(ROOT_DIR) secrets-clean

.PHONY: secrets
secrets: ## Create just in time TLS certificates etc needed for tests
	@make -C $(ROOT_DIR) secrets

# variables that should not be overridden by the user
VER = $(shell grep IC_VERSION .github/data/version.txt | cut -d '=' -f 2)
GIT_TAG = $(shell git describe --exact-match --tags || echo untagged)
VERSION = $(VER)-SNAPSHOT
# renovate: datasource=docker depName=nginx/nginx
NGINX_OSS_VERSION             ?= 1.29.4
NGINX_PLUS_VERSION            ?= R36
NAP_WAF_VERSION               ?= 36+5.550
NAP_WAF_COMMON_VERSION        ?= 11.583
NAP_WAF_PLUGIN_VERSION        ?= 6.25.0
NAP_AGENT_VERSION             ?= 2
NGINX_AGENT_VERSION           ?= 3.6
PLUS_ARGS = --build-arg NGINX_PLUS_VERSION=$(NGINX_PLUS_VERSION) --secret id=nginx-repo.crt,src=nginx-repo.crt --secret id=nginx-repo.key,src=nginx-repo.key

# Variables that can be overridden
REGISTRY                      ?= ## The registry where the image is located.
PREFIX                        ?= nginx/nginx-ingress ## The name of the image. For example, nginx/nginx-ingress
TAG                           ?= $(VERSION:v%=%) ## The tag of the image. For example, 2.0.0
TARGET                        ?= local ## The target of the build. Possible values: local, container and download
PLUS_REPO                     ?= "pkgs.nginx.com" ## The package repo to install nginx-plus from
override DOCKER_BUILD_OPTIONS += --build-arg IC_VERSION=$(VERSION) --build-arg PACKAGE_REPO=$(PLUS_REPO) ## The options for the docker build command. For example, --pull
ARCH                          ?= amd64 ## The architecture of the image or binary. For example: amd64, arm64, ppc64le, s390x. Not all architectures are supported for all targets
GOOS                          ?= linux ## The OS of the binary. For example linux, darwin
TELEMETRY_ENDPOINT            ?= oss.edge.df.f5.com:443
# renovate: datasource=docker depName=golangci/golangci-lint
GOLANGCI_LINT_VERSION         ?= v2.7.2 ## The version of golangci-lint to use
# renovate: datasource=go depName=golang.org/x/tools
GOIMPORTS_VERSION             ?= v0.40.0 ## The version of goimports to use
# renovate: datasource=go depName=mvdan.cc/gofumpt
GOFUMPT_VERSION               ?= v0.9.2 ## The version of gofumpt to use

# Additional flags added here can be accessed in main.go.
# e.g. `main.version` maps to `var version` in main.go
GO_LINKER_FLAGS_VARS = -X main.version=${VERSION} -X main.telemetryEndpoint=${TELEMETRY_ENDPOINT}
GO_LINKER_FLAGS_OPTIONS = -s -w
GO_LINKER_FLAGS = $(GO_LINKER_FLAGS_OPTIONS) $(GO_LINKER_FLAGS_VARS)
DEBUG_GO_LINKER_FLAGS = $(GO_LINKER_FLAGS_VARS)
DEBUG_GO_GC_FLAGS = all=-N -l

ifeq (${REGISTRY},)
BUILD_IMAGE             := $(strip $(PREFIX)):$(strip $(TAG))
else
BUILD_IMAGE             := $(strip $(REGISTRY))/$(strip $(PREFIX)):$(strip $(TAG))
endif

# final docker build command
DOCKER_CMD = docker build --platform linux/$(strip $(ARCH)) $(strip $(DOCKER_BUILD_OPTIONS)) --target $(strip $(TARGET)) -f build/Dockerfile -t $(BUILD_IMAGE) .

export DOCKER_BUILDKIT = 1

.DEFAULT_GOAL:=help

.PHONY: help
help: Makefile ## Display this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "; printf "Usage:\n\n    make \033[36m<target>\033[0m [VARIABLE=value...]\n\nTargets:\n\n"}; {printf "    \033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@grep -E '^(override )?[a-zA-Z0-9_-]+ \??\+?= .*? ## .*$$' $< | sort | awk 'BEGIN {FS = " \\??\\+?= .*? ## "; printf "\nVariables:\n\n"}; {gsub(/override /, "", $$1); printf "    \033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: test lint verify-codegen update-crds debian-image

.PHONY: lint
lint: ## Run linter
	@git fetch
	docker run --pull always --rm -v $(shell pwd):/kubernetes-ingress -w /kubernetes-ingress -v $(shell go env GOCACHE):/cache/go -e GOCACHE=/cache/go -e GOLANGCI_LINT_CACHE=/cache/go -v $(shell go env GOPATH)/pkg:/go/pkg golangci/golangci-lint:$(GOLANGCI_LINT_VERSION) git diff -p origin/main > /tmp/diff.patch && golangci-lint --color always run -v --new-from-patch=/tmp/diff.patch

.PHONY: lint-python
lint-python: ## Run linter for python tests
	@isort -V || (code=$$?; printf "\033[0;31mError\033[0m: there was a problem with isort, use 'brew install isort' to install it\n"; exit $$code)
	@black --version || (code=$$?; printf "\033[0;31mError\033[0m: there was a problem with black, use 'brew install black' to install it\n"; exit $$code)
	@isort .
	@black .

.PHONY: format
format: ## Run goimports & gofmt
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)
	goimports -l -w .
	gofumpt -l -w .

.PHONY: staticcheck
staticcheck: ## Run staticcheck linter
	@staticcheck -version >/dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@2022.1.3;
	staticcheck ./...

.PHONY: test
test: ## Run GoLang tests
	go test -tags=aws,helmunit -shuffle=on ./...

.PHONY: test-update-snaps
test-update-snaps:
	UPDATE_SNAPS=true go test -tags=aws,helmunit -shuffle=on ./...

cover: ## Generate coverage report
	go test -tags=aws,helmunit -shuffle=on -race -coverprofile=coverage.txt -covermode=atomic ./...

cover-html: test ## Generate and show coverage report in HTML format
	go tool cover -html coverage.txt

.PHONY: verify-codegen
verify-codegen: ## Verify code generation
	./hack/verify-codegen.sh

.PHONY: update-codegen
update-codegen: ## Generate code
	./hack/update-codegen.sh

.PHONY: update-crds
update-crds: ## Update CRDs
	go run sigs.k8s.io/controller-tools/cmd/controller-gen crd paths=./pkg/apis/... output:crd:artifacts:config=config/crd/bases
	@kustomize version || (code=$$?; printf "\033[0;31mError\033[0m: there was a problem with kustomize, use 'brew install kustomize' to install it\n"; exit $$code)
	kustomize build config/crd >deploy/crds.yaml
	kustomize build config/crd/app-protect-dos --load-restrictor='LoadRestrictionsNone' >deploy/crds-nap-dos.yaml
	kustomize build config/crd/app-protect-waf --load-restrictor='LoadRestrictionsNone' >deploy/crds-nap-waf.yaml
	$(MAKE) update-crd-docs

.PHONY: telemetry-schema
telemetry-schema: ## Generate the telemetry Schema
	go generate internal/telemetry/exporter.go
	gofumpt -w internal/telemetry/*_generated.go

.PHONY: build
build: ## Build Ingress Controller binary
	@docker -v || (code=$$?; printf "\033[0;31mError\033[0m: there was a problem with Docker\n"; exit $$code)
ifeq ($(strip $(TARGET)),local)
	@go version || (code=$$?; printf "\033[0;31mError\033[0m: unable to build locally, try using the parameter TARGET=container or TARGET=download\n"; exit $$code)
	CGO_ENABLED=0 GOOS=$(strip $(GOOS)) GOARCH=$(strip $(ARCH)) go build -trimpath -ldflags "$(GO_LINKER_FLAGS)" -o nginx-ingress github.com/nginx/kubernetes-ingress/cmd/nginx-ingress
else ifeq ($(strip $(TARGET)),download)
	@$(MAKE) download-binary-docker
else ifeq ($(strip $(TARGET)),debug)
	@go version || (code=$$?; printf "\033[0;31mError\033[0m: unable to build locally, try using the parameter TARGET=container or TARGET=download\n"; exit $$code)
	CGO_ENABLED=0 GOOS=$(strip $(GOOS)) GOARCH=$(strip $(ARCH)) go build -ldflags "$(DEBUG_GO_LINKER_FLAGS)" -gcflags "$(DEBUG_GO_GC_FLAGS)" -o nginx-ingress github.com/nginx/kubernetes-ingress/cmd/nginx-ingress
endif

.PHONY: download-binary-docker
download-binary-docker: ## Download Docker image from which to extract Ingress Controller binary, TARGET=download is required
ifeq ($(strip $(TARGET)),download)
DOWNLOAD_TAG := $(shell ./hack/docker.sh $(GIT_TAG))
ifeq ($(DOWNLOAD_TAG),fail)
$(error unable to build with TARGET=download, this function is only available when building from a git tag or from the latest commit matching the edge image)
endif
override DOCKER_BUILD_OPTIONS += --build-arg DOWNLOAD_TAG=$(DOWNLOAD_TAG)
endif

.PHONY: build-goreleaser
build-goreleaser: ## Build Ingress Controller binary using GoReleaser
	@goreleaser -v || (code=$$?; printf "\033[0;31mError\033[0m: there was a problem with GoReleaser. Follow the docs to install it https://goreleaser.com/install\n"; exit $$code)
	GOOS=$(strip $(GOOS)) GOPATH=$(shell go env GOPATH) GOARCH=$(strip $(ARCH)) goreleaser build --clean --snapshot --id kubernetes-ingress --single-target

.PHONY: debian-image
debian-image: build ## Create Docker image for Ingress Controller (Debian)
	$(DOCKER_CMD) --build-arg BUILD_OS=debian --build-arg NGINX_OSS_VERSION=$(NGINX_OSS_VERSION) --build-arg NGINX_AGENT_VERSION=$(NGINX_AGENT_VERSION)

.PHONY: alpine-image
alpine-image: build ## Create Docker image for Ingress Controller (Alpine)
	$(DOCKER_CMD) --build-arg BUILD_OS=alpine --build-arg NGINX_OSS_VERSION=$(NGINX_OSS_VERSION) --build-arg NGINX_AGENT_VERSION=$(NGINX_AGENT_VERSION)

.PHONY: alpine-image-plus
alpine-image-plus: build ## Create Docker image for Ingress Controller (Alpine with NGINX Plus)
	$(DOCKER_CMD) $(PLUS_ARGS) --build-arg BUILD_OS=alpine-plus --build-arg NGINX_AGENT_VERSION=$(NGINX_AGENT_VERSION)

.PHONY: alpine-image-plus-fips
alpine-image-plus-fips: build ## Create Docker image for Ingress Controller (Alpine with NGINX Plus and FIPS)
	$(DOCKER_CMD) $(PLUS_ARGS) --build-arg BUILD_OS=alpine-plus-fips --build-arg NGINX_AGENT_VERSION=$(NGINX_AGENT_VERSION)

.PHONY: alpine-image-nap-plus-fips
alpine-image-nap-plus-fips: build ## Create Docker image for Ingress Controller (Alpine with NGINX Plus, NGINX App Protect WAF and FIPS)
	$(DOCKER_CMD) $(PLUS_ARGS) --build-arg BUILD_OS=alpine-plus-nap-fips --build-arg NAP_WAF_VERSION=$(NAP_WAF_VERSION) --build-arg NAP_AGENT_VERSION=$(NAP_AGENT_VERSION)

.PHONY: alpine-image-nap-v5-plus-fips
alpine-image-nap-v5-plus-fips: build ## Create Docker image for Ingress Controller (Alpine with NGINX Plus, NGINX App Protect WAFv5 and FIPS)
	$(DOCKER_CMD) $(PLUS_ARGS) \
	--build-arg BUILD_OS=alpine-plus-nap-v5-fips --build-arg NAP_WAF_VERSION=$(NAP_WAF_VERSION) --build-arg NAP_AGENT_VERSION=$(NAP_AGENT_VERSION)

.PHONY: debian-image-plus
debian-image-plus: build ## Create Docker image for Ingress Controller (Debian with NGINX Plus)
	$(DOCKER_CMD) $(PLUS_ARGS) --build-arg BUILD_OS=debian-plus --build-arg NGINX_AGENT_VERSION=$(NGINX_AGENT_VERSION)

.PHONY: debian-image-nap-plus
debian-image-nap-plus: build ## Create Docker image for Ingress Controller (Debian with NGINX Plus and NGINX App Protect WAF)
	$(DOCKER_CMD) $(PLUS_ARGS) --build-arg BUILD_OS=debian-plus-nap --build-arg NAP_MODULES=waf \
		--build-arg NAP_WAF_VERSION=$(NAP_WAF_VERSION) --build-arg NAP_WAF_PLUGIN_VERSION=$(NAP_WAF_PLUGIN_VERSION) \
		--build-arg NAP_WAF_COMMON_VERSION=$(NAP_WAF_COMMON_VERSION) --build-arg NAP_AGENT_VERSION=$(NAP_AGENT_VERSION)

.PHONY: debian-image-nap-v5-plus
debian-image-nap-v5-plus: build ## Create Docker image for Ingress Controller (Debian with NGINX Plus and NGINX App Protect WAFv5)
	$(DOCKER_CMD) $(PLUS_ARGS) --build-arg BUILD_OS=debian-plus-nap-v5 --build-arg NAP_WAF_VERSION=$(NAP_WAF_VERSION) \
		--build-arg NAP_WAF_PLUGIN_VERSION=$(NAP_WAF_PLUGIN_VERSION) --build-arg NAP_AGENT_VERSION=$(NAP_AGENT_VERSION)

.PHONY: debian-image-dos-plus
debian-image-dos-plus: build ## Create Docker image for Ingress Controller (Debian with NGINX Plus and NGINX App Protect DoS)
	$(DOCKER_CMD) $(PLUS_ARGS) --build-arg BUILD_OS=debian-plus-nap --build-arg NAP_MODULES=dos

.PHONY: debian-image-nap-dos-plus
debian-image-nap-dos-plus: build ## Create Docker image for Ingress Controller (Debian with NGINX Plus, NGINX App Protect WAF and DoS)
	$(DOCKER_CMD) $(PLUS_ARGS) --build-arg BUILD_OS=debian-plus-nap --build-arg NAP_MODULES=waf,dos \
		--build-arg NAP_WAF_VERSION=$(NAP_WAF_VERSION) --build-arg NAP_WAF_PLUGIN_VERSION=$(NAP_WAF_PLUGIN_VERSION) \
		--build-arg NAP_WAF_COMMON_VERSION=$(NAP_WAF_COMMON_VERSION) --build-arg NAP_AGENT_VERSION=$(NAP_AGENT_VERSION)

.PHONY: ubi-image
ubi-image: build ## Create Docker image for Ingress Controller (UBI)
	$(DOCKER_CMD) --build-arg BUILD_OS=ubi --build-arg NGINX_OSS_VERSION=$(NGINX_OSS_VERSION) --build-arg NGINX_AGENT_VERSION=$(NGINX_AGENT_VERSION)

.PHONY: ubi-image-plus
ubi-image-plus: build ## Create Docker image for Ingress Controller (UBI with NGINX Plus)
	$(DOCKER_CMD) $(PLUS_ARGS) --build-arg BUILD_OS=ubi-9-plus --build-arg NGINX_AGENT_VERSION=$(NGINX_AGENT_VERSION)

.PHONY: ubi-image-nap-plus
ubi-image-nap-plus: build ## Create Docker image for Ingress Controller (UBI with NGINX Plus and NGINX App Protect WAF)
	$(DOCKER_CMD) $(PLUS_ARGS) --secret id=rhel_license,src=rhel_license --build-arg BUILD_OS=ubi-9-plus-nap \
		--build-arg NAP_MODULES=waf --build-arg NAP_WAF_VERSION=$(NAP_WAF_VERSION) --build-arg NAP_AGENT_VERSION=$(NAP_AGENT_VERSION)

.PHONY: ubi8-image-nap-plus
ubi8-image-nap-plus: build ## Create Docker image for Ingress Controller (UBI with NGINX Plus and NGINX App Protect WAF)
	$(DOCKER_CMD) $(PLUS_ARGS) --secret id=rhel_license,src=rhel_license --build-arg BUILD_OS=ubi-8-plus-nap \
		--build-arg NAP_MODULES=waf --build-arg NAP_WAF_VERSION=$(NAP_WAF_VERSION) --build-arg NAP_AGENT_VERSION=$(NAP_AGENT_VERSION)

.PHONY: ubi-image-nap-v5-plus
ubi-image-nap-v5-plus: build ## Create Docker image for Ingress Controller (UBI with NGINX Plus and NGINX App Protect WAFv5)
	$(DOCKER_CMD) $(PLUS_ARGS) --secret id=rhel_license,src=rhel_license \
	--build-arg BUILD_OS=ubi-9-plus-nap-v5 --build-arg NAP_WAF_VERSION=$(NAP_WAF_VERSION) --build-arg NAP_AGENT_VERSION=$(NAP_AGENT_VERSION)

.PHONY: ubi8-image-nap-v5-plus
ubi8-image-nap-v5-plus: build ## Create Docker image for Ingress Controller (UBI with NGINX Plus and NGINX App Protect WAFv5)
	$(DOCKER_CMD) $(PLUS_ARGS) --secret id=rhel_license,src=rhel_license \
	--build-arg BUILD_OS=ubi-8-plus-nap-v5 --build-arg NAP_WAF_VERSION=$(NAP_WAF_VERSION) --build-arg NAP_AGENT_VERSION=$(NAP_AGENT_VERSION)

.PHONY: ubi-image-dos-plus
ubi-image-dos-plus: build ## Create Docker image for Ingress Controller (UBI with NGINX Plus and NGINX App Protect DoS)
	$(DOCKER_CMD) $(PLUS_ARGS) --secret id=rhel_license,src=rhel_license --build-arg BUILD_OS=ubi-9-plus-nap \
		--build-arg NAP_MODULES=dos

.PHONY: ubi-image-nap-dos-plus
ubi-image-nap-dos-plus: build ## Create Docker image for Ingress Controller (UBI with NGINX Plus, NGINX App Protect WAF and DoS)
	$(DOCKER_CMD) $(PLUS_ARGS) --secret id=rhel_license,src=rhel_license --build-arg BUILD_OS=ubi-9-plus-nap \
		--build-arg NAP_MODULES=waf,dos --build-arg NAP_WAF_VERSION=$(NAP_WAF_VERSION) --build-arg NAP_AGENT_VERSION=$(NAP_AGENT_VERSION)

.PHONY: all-images ## Create all the Docker images for Ingress Controller
all-images: alpine-image alpine-image-plus alpine-image-plus-fips alpine-image-nap-plus-fips debian-image debian-image-plus debian-image-nap-plus debian-image-dos-plus debian-image-nap-dos-plus ubi-image ubi-image-plus ubi-image-nap-plus ubi-image-dos-plus ubi-image-nap-dos-plus

.PHONY: patch-os
patch-os: ## Patch supplied image
	$(DOCKER_CMD) --build-arg IMAGE_NAME=$(IMAGE)

.PHONY: push
push: ## Docker push to PREFIX and TAG
	docker push $(strip $(PREFIX)):$(strip $(TAG))

.PHONY: clean
clean:  ## Remove nginx-ingress binary
	-rm -f nginx-ingress
	-rm -rf dist

.PHONY: deps
deps: ## Add missing and remove unused modules, verify deps and download them to local cache
	@go mod tidy && go mod verify && go mod download

.PHONY: clean-cache
clean-cache: ## Clean go cache
	@go clean -modcache

.PHONY: rebuild-test-img ## Rebuild the python e2e test image
rebuild-test-img:
	cd tests && \
	make build

.PHONY: update-crd-docs
update-crd-docs: ## Update CRD markdown documentation from YAML definitions
	@echo "Generating CRD documentation..."
	@go run hack/generate-crd-docs.go -crd-dir config/crd/bases -output-dir docs/crd
	@echo "CRD documentation updated successfully!"

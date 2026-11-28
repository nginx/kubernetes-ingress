# variables that should not be overridden by the user
VER = $(shell grep IC_VERSION .github/data/version.txt | cut -d '=' -f 2)
GIT_TAG = $(shell git describe --exact-match --tags || echo untagged)
BINARY_NAME = nginx-ingress
VERSION = $(VER)-SNAPSHOT

# variables that can be overridden by the user
PLUS_REPO					  ?= "pkgs.nginx.com" ## The package repo to install nginx-plus from
# Local build through the F5 Artifactory mirror:
#   F5_REPO_USER=<user> F5_REPO_TOKEN=<token> F5_REPO_HOST=<host> make debian-image
# Check that no credentials or mirror URLs reached the image:
#   docker run --rm --user 0 --entrypoint sh <image> -c 'grep -rl "$0" /etc; test $? -eq 1' <host>
F5_REPO_USER                  ?= ## The user for the F5 package repository.
F5_REPO_TOKEN                 ?= ## The token for the F5 package repository.
F5_REPO_HOST                  ?= ## The host of the F5 package mirror (Artifactory).
F5_DEBIAN_REPO                ?= debian-remote ## The Artifactory repository mirroring deb.debian.org/debian.
F5_DEBIAN_SECURITY_REPO       ?= debian-security-remote ## The Artifactory repository mirroring deb.debian.org/debian-security.

# renovate: datasource=docker depName=nginx/nginx
NGINX_OSS_VERSION             ?= 1.31.0
NGINX_PLUS_VERSION            ?= R37.0
NAP_WAF_VERSION               ?= 37.0+5.635
NAP_WAF_COMMON_VERSION        ?= 11.665
NAP_WAF_PLUGIN_VERSION        ?= 6.29
NAP_AGENT_VERSION             ?= 2
NGINX_AGENT_VERSION           ?= 3

# variables that can be overridden by the user, but are required for plus/staging builds
NGX_CRT 					  ?= nginx-repo.crt
NGX_KEY 					  ?= nginx-repo.key

DOCKER_AUTH = --secret id=$(NGX_CRT),src=$(NGX_CRT) --secret id=$(NGX_KEY),src=$(NGX_KEY)

REGISTRY                      ?= ## The registry where the image is located.
GHCR_REGISTRY                 ?= ghcr.io ## The GitHub Container Registry to use for images.
DOCKER_REGISTRY               ?= docker.io ## The Docker registry to use for images.
PLUS_ARGS ?=  $(DOCKER_AUTH) --build-arg NGINX_PLUS_VERSION=$(NGINX_PLUS_VERSION) --build-arg PLUS_PACKAGE_REPO=$(PLUS_REPO)

# Variables that can be overridden

# renovate: datasource=github-releases depName=dominikh/go-tools
STATICCHECK_VERSION ?= 452d5bb86b45416c35891262f6a11dbd6a970117

# renovate: datasource=github-tags depName=golang/vuln
GOVULNCHECK_VERSION ?= v1.10.0

GO_DOCKER_IMAGE_NAME    ?= $(strip $(DOCKER_REGISTRY))/library/golang
# renovate: datasource=docker depName=golang versioning=docker
GO_DOCKER_IMAGE_VERSION ?= 1.27.4-trixie
GO_DOCKER_IMAGE         ?= $(GO_DOCKER_IMAGE_NAME):$(GO_DOCKER_IMAGE_VERSION)

PREFIX                        ?= nginx/nginx-ingress ## The name of the image. For example, nginx/nginx-ingress
TAG                           ?= $(VERSION:v%=%) ## The tag of the image. For example, 2.0.0
TARGET                        ?= local ## The target of the build. Possible values: local, container, download, goreleaser, and debug
override DOCKER_BUILD_OPTIONS += --build-arg DOCKER_REGISTRY=$(DOCKER_REGISTRY) --build-arg GHCR_REGISTRY=$(GHCR_REGISTRY) --build-arg IC_VERSION=$(VERSION) --build-arg PLUS_PACKAGE_REPO=$(PLUS_REPO) ## The options for the docker build command. For example, --pull
ifneq ($(F5_REPO_USER),)
ifeq ($(strip $(F5_REPO_HOST)),)
$(error F5_REPO_HOST must be set when F5_REPO_USER is set)
endif
override DOCKER_BUILD_OPTIONS += --secret id=f5-repo-user,env=F5_REPO_USER \
--secret id=f5-repo-token,env=F5_REPO_TOKEN \
--build-arg F5_REPO_HOST=$(F5_REPO_HOST) \
--build-arg F5_DEBIAN_REPO=$(F5_DEBIAN_REPO) \
--build-arg F5_DEBIAN_SECURITY_REPO=$(F5_DEBIAN_SECURITY_REPO)
endif
ARCH                          ?= amd64 ## The architecture of the image or binary. For example: amd64, arm64, ppc64le, s390x. Not all architectures are supported for all targets
GOOS                          ?= linux ## The OS of the binary. For example linux, darwin
TELEMETRY_ENDPOINT            ?= oss.edge.df.f5.com:443
# renovate: datasource=docker depName=golangci/golangci-lint
GOLANGCI_LINT_VERSION         ?= v2.15.0 ## The version of golangci-lint to use
# renovate: datasource=go depName=golang.org/x/tools
GOIMPORTS_VERSION             ?= v0.53.0 ## The version of goimports to use
# renovate: datasource=go depName=mvdan.cc/gofumpt
GOFUMPT_VERSION               ?= v0.12.0 ## The version of gofumpt to use

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

# Note: only tracks committed/staged files. Run `git add` on new .go files for incremental rebuild.
GO_SRCS := $(shell git ls-files '*.go' go.mod go.sum .github/data/version.txt | grep -v '_test\.go$$')

.DEFAULT_GOAL:=help

.PHONY: help
help: Makefile ## Display this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "; printf "Usage:\n\n    make \033[36m<target>\033[0m [VARIABLE=value...]\n\nTargets:\n\n"}; {printf "    \033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@grep -E '^(override )?[a-zA-Z0-9_-]+ \??\+?= .*? ## .*$$' $< | sort | awk 'BEGIN {FS = " \\??\\+?= .*? ## "; printf "\nVariables:\n\n"}; {gsub(/override /, "", $$1); printf "    \033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: test lint verify-codegen update-crds debian-image-plus

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
	@staticcheck -version >/dev/null 2>&1 || go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION};
	staticcheck ./...

.PHONY: govulncheck
govulncheck: ## Run govulncheck linter
	@govulncheck -version >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION};
	govulncheck ./...

.PHONY: test
test: ## Run GoLang tests
	go test -tags=aws,helmunit -shuffle=on ./...

.PHONY: test-update-snaps
test-update-snaps:
	UPDATE_SNAPS=always go test -tags=aws,helmunit -shuffle=on ./...

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
	$(MAKE) update-crd-docs

.PHONY: telemetry-schema
telemetry-schema: ## Generate the telemetry Schema
	go generate internal/telemetry/exporter.go
	gofumpt -w internal/telemetry/*_generated.go

.PHONY: build-local
build-local: $(BINARY_NAME)-$(ARCH) ## Build Ingress Controller binary (local, incremental)

$(BINARY_NAME)-$(ARCH): $(GO_SRCS)
	@go version || (code=$$?; printf "\033[0;31mError\033[0m: unable to build locally, try using the parameter TARGET=container or TARGET=download\n"; exit $$code)
	CGO_ENABLED=0 GOOS=$(strip $(GOOS)) GOARCH=$(strip $(ARCH)) go build -trimpath -ldflags "$(GO_LINKER_FLAGS)" -o $(BINARY_NAME)-$(ARCH) github.com/nginx/kubernetes-ingress/cmd/nginx-ingress
	@cp $(BINARY_NAME)-$(ARCH) $(BINARY_NAME)

.PHONY: build
build: ## Build Ingress Controller binary
ifeq ($(strip $(TARGET)),local)
	@$(MAKE) $(BINARY_NAME)-$(ARCH)
else ifeq ($(strip $(TARGET)),download)
	@docker -v || (code=$$?; printf "\033[0;31mError\033[0m: there was a problem with Docker\n"; exit $$code)
	@$(MAKE) download-binary-docker
else ifeq ($(strip $(TARGET)),debug)
# Debug builds run unconditionally (no incremental file target) since they are infrequent.
	@go version || (code=$$?; printf "\033[0;31mError\033[0m: unable to build locally, try using the parameter TARGET=container or TARGET=download\n"; exit $$code)
	CGO_ENABLED=0 GOOS=$(strip $(GOOS)) GOARCH=$(strip $(ARCH)) go build -ldflags "$(DEBUG_GO_LINKER_FLAGS)" -gcflags "$(DEBUG_GO_GC_FLAGS)" -o $(BINARY_NAME)-$(ARCH) github.com/nginx/kubernetes-ingress/cmd/nginx-ingress
	@cp $(BINARY_NAME)-$(ARCH) $(BINARY_NAME)
else ifeq ($(strip $(TARGET)),container)
# Binary is built inside Docker as part of the image build; nothing to do here.
else ifeq ($(strip $(TARGET)),goreleaser)
# Binary is built using GoReleaser; nothing to do here.
else
	$(error Unknown TARGET "$(TARGET)". Valid values: local, container, download, goreleaser, debug)
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

.PHONY: debian-image-plus
debian-image-plus: build ## Create Docker image for Ingress Controller (Debian with NGINX Plus)
	$(DOCKER_CMD) $(PLUS_ARGS) --build-arg BUILD_OS=debian-plus --build-arg NGINX_AGENT_VERSION=$(NGINX_AGENT_VERSION)

.PHONY: all-images ## Create all the Docker images for Ingress Controller
all-images:
	docker builder prune -af; \
	images="debian-image-plus"; \
	for img in $$images; do \
		TAG="$(strip $(TAG))-$$img" make $$img; \
	done

.PHONY: patch-os
patch-os: ## Patch supplied image
	$(DOCKER_CMD) --build-arg IMAGE_NAME=$(IMAGE)

.PHONY: push
push: ## Docker push to PREFIX and TAG
	docker push $(strip $(PREFIX)):$(strip $(TAG))

.PHONY: clean
clean:  ## Remove nginx-ingress binaries and dist
	-rm -f $(BINARY_NAME) $(foreach a,amd64 arm64 ppc64le s390x,$(BINARY_NAME)-$(a))
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

.PHONY: secrets
secrets: ## Create just in time TLS certificates etc needed for tests and examples
ifeq (, $(shell command -v go))
	@docker run --rm -v .:/workspace/kubernetes-ingress -w /workspace/kubernetes-ingress ${GO_DOCKER_IMAGE} make secrets
else
	@make -C hack/secrets-gen ignore
endif

.PHONY: secrets-clean
secrets-clean: ## Clean just in time TLS certificates etc. needed for tests and examples
ifeq (, $(shell command -v go))
	@docker run --rm -v .:/workspace/kubernetes-ingress -w /workspace/kubernetes-ingress ${GO_DOCKER_IMAGE} make secrets-clean
else
	@make -C hack/secrets-gen clean
endif

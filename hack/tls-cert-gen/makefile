SECRETS ?= ../secrets.json
DEBUG ?= false

OPTIONS :=
ifeq ($(DEBUG),true)
OPTIONS += -debug
endif

.PHONY: run
run: ## Create just in time TLS certificates needed for tests and examples
	@go run ./... $(OPTIONS) -secrets-path  $(SECRETS)

.PHONY: clean
clean: ## Clean just in time TLS certificates needed for tests and examples
	@go run ./... $(OPTIONS) -clean -secrets-path $(SECRETS)

.PHONY: ignore
ignore:
	@go run ./... $(OPTIONS) -gitignore -secrets-path $(SECRETS)

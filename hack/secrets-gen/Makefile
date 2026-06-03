SECRETS ?= ../secrets.json
DEBUG ?= false
SECRETS_GEN_BIN ?=

OPTIONS :=
ifeq ($(DEBUG),true)
OPTIONS += -debug
endif

ifeq ($(SECRETS_GEN_BIN),)
RUN_CMD := go run ./...
else
RUN_CMD := $(SECRETS_GEN_BIN)
endif

.PHONY: run
run: ## Create just in time TLS certificates needed for tests and examples
	@$(RUN_CMD) $(OPTIONS) -secrets-path  $(SECRETS)

.PHONY: clean
clean: ## Clean just in time TLS certificates needed for tests and examples
	@$(RUN_CMD) $(OPTIONS) -clean -secrets-path $(SECRETS)

.PHONY: ignore
ignore:
	@$(RUN_CMD) $(OPTIONS) -gitignore -secrets-path $(SECRETS)

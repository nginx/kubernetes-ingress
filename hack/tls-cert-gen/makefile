SECRETS := ../secrets.json

.PHONY: run
run: ## Create just in time TLS certificates needed for tests and examples
	go run ./... -secrets-path $(SECRETS)

.PHONY: clean
clean: ## Clean just in time TLS certificates needed for tests and examples
	go run ./... -clean -secrets-path $(SECRETS)

.PHONY: ignore
ignore:
	go run ./... -gitignore -secrets-path $(SECRETS)

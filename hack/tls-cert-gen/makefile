.PHONY: run
run:
	go run tls-cert-gen.go

.PHONY: extract
extract:
	@if [ -z "$@" ]; then \
		echo "Usage: make extract <file>"; \
		exit 1; \
	fi

	@echo "dollar at is"
	@echo $@
	@echo "this was dollar"

	@# Extract the TLS certificate from the Kubernetes secret
	cat $@ | yq eval '.data["tls.crt"]' - | base64 -d | openssl x509 -text -noout

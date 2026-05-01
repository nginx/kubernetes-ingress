# Agent Instructions

NGINX Kubernetes Ingress Controller -- watches Ingress, VirtualServer/VirtualServerRoute, TransportServer, and Policy CRDs, generates NGINX configuration, and reloads NGINX. Uses raw client-go (SharedInformerFactory + work queue), not controller-runtime.

## References

| Topic | Link |
| ------- | ------ |
| NIC docs | <https://docs.nginx.com/nginx-ingress-controller/> |
| NGINX directives | <https://nginx.org/en/docs/> |
| K8s API conventions | <https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md> |
| client-go | <https://pkg.go.dev/k8s.io/client-go> |
| Kubebuilder markers | <https://book.kubebuilder.io/reference/markers> |
| CRD docs | <https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/> |
| K8s validation (CEL) | <https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation-rules> |

## Custom API Groups

| API Group | Version | Key Types |
| ----------- | --------- | ----------- |
| `k8s.nginx.org` | `v1` | VirtualServer, VirtualServerRoute, TransportServer, Policy, GlobalConfiguration |
| `appprotectdos.f5.com` | `v1beta1` | DosProtectedResource |
| `externaldns.nginx.org` | `v1` | DNSEndpoint |

The controller also watches `networking.k8s.io` Ingress/IngressClass, `appprotect.f5.com` WAF resources (via dynamic client), and optionally `cert-manager.io` Certificates.

Use the codebase as the authoritative reference for patterns and style. Plan before implementing. Read files before modifying them.

---

## Build, Test, Validate

| Command | Purpose |
| --------- | --------- |
| `make test` | Run all Go tests via `go test -tags=aws,helmunit -shuffle=on ./...` |
| `make test-update-snaps` | Regenerate snapshot golden files via `UPDATE_SNAPS=always go test -tags=aws,helmunit -shuffle=on ./...` |
| `make lint` | golangci-lint via Docker against `origin/main` |
| `make format` | goimports + gofumpt |
| `make build` | Build `nginx-ingress` binary |
| `make update-codegen` | Regenerate DeepCopy + typed clients |
| `make update-crds` | Regenerate CRD YAML from kubebuilder markers |

Always use `make test` over raw `go test`. Run `make test-update-snaps` when template output changes.
After changing `types.go`, always run `make update-codegen` then `make update-crds`.

---

## Project Layout

| Path | Purpose |
| ------ | --------- |
| `pkg/apis/configuration/v1/types.go` | CRD struct definitions (source of truth) |
| `pkg/apis/configuration/validation/` | CRD validation |
| `internal/k8s/` | Controller loop, sync handlers, event dispatching |
| `internal/configs/` | Config generation: virtualserver, ingress, policy, annotations |
| `internal/configs/version1/` | Ingress template structs + `.tmpl` files |
| `internal/configs/version2/` | VirtualServer/TransportServer template structs + `.tmpl` files |
| `internal/nginx/` | NGINX process management and reload |
| `charts/nginx-ingress/` | Helm chart (values.yaml, schema, templates) |
| `tests/suite/` | Python integration tests (pytest) |
| `build/Dockerfile` | Multi-stage Dockerfile for all image variants |
| `.github/workflows/` | CI/CD pipelines (reusable workflow pattern) |

---

## Skills

| Skill | When to load |
| ------- | -------------- |
| `nic-structure` | Exploring the codebase, tracing data flow, debugging config generation |
| `nic-add-feature` | Adding Ingress annotations, VirtualServer/VSR fields, or Helm values |
| `nic-add-policy` | Adding or extending a Policy CRD type |
| `nic-ci-pipelines` | Working on CI workflows, build matrices, or release pipeline |
| `nic-docker-images` | Building container images, modifying Dockerfile, adding image variants |
| `nic-testing` | Writing unit, snapshot, Helm, or Python integration tests |

---

## Key Invariants

- **NGINX config security**: Run `containsDangerousChars()` on every user-provided string that reaches NGINX config (dangerous: `;`, `{`, `}`, `\n`, `\r`, `$`, backtick). Use `ValidateEscapedString()` for escape validation.
- **Codegen**: Never edit `zz_generated.deepcopy.go` manually. After changing `types.go`, always run `make update-codegen` then `make update-crds`.
- **Templates**: OSS and Plus template variants are separate files -- always update both. When adding a VirtualServer (v2) feature, check whether Ingress (v1) also needs it.
- **Credentials**: Plus credentials use `--secret` mounts in Docker builds, never `COPY`. CI secrets via Azure Key Vault OIDC, never GitHub repository secrets.
- **New CRD fields**: Every new field requires kubebuilder markers, validation, template struct, template rendering, and tests.

---

## Code Review Checklist

Comment only at >80% confidence. Be concise and actionable.

### Security

- Raw NGINX config injection via unsanitized user strings (missing `containsDangerousChars()`)
- Command injection in shell commands or NGINX directives
- Credential exposure or hardcoded secrets
- Docker secrets leaked into image layers

### Correctness

- Logic errors causing panics or incorrect behavior
- Race conditions in concurrent code
- `*bool` used where plain `bool` (default false) suffices
- Missing error context in `fmt.Errorf` wrapping
- Template directives without `{{- if }}` / `{{- with }}` guards

### Architecture

- Missing validation for new CRD fields
- Missing template rendering for new config struct fields
- Missing tests for new functionality
- Helm values changes without schema updates
- OSS template updated but Plus template missed (or vice versa)
- Version 1 (Ingress) support forgotten when adding Version 2 (VS) features

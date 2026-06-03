---
name: nic-debugging
description: 'Debugging and troubleshooting patterns for NIC. Use when diagnosing failures, tracing issues, investigating NGINX reload errors, config generation bugs, or controller sync problems.'
---

# Debugging and Troubleshooting

## Common Failure Modes

### NGINX Reload Failure

**Symptom:** Controller logs show "reload failed" or NGINX returns error status.

**Diagnosis:**
1. Check controller logs for the generated config that failed
2. Look for `nginx -t` output in logs — shows exact syntax error and line number
3. Common causes:
   - Unsanitized user string injected into config (missing `containsDangerousChars()` check)
   - Template guard missing (`{{- if }}` / `{{- with }}`) for optional field
   - Duplicate directive from conflicting policies
   - Invalid upstream when no endpoints available

**Fix pattern:**
- Find the template or config generation code that produced the bad directive
- Add validation to reject the input earlier, OR fix the template guard
- Verify with `make test` — snapshot tests catch most template output issues

### CRD Not Taking Effect

**Symptom:** User applies VirtualServer/Policy but NGINX config doesn't change.

**Diagnosis:**
1. Check CRD status: `kubectl get vs <name> -o yaml` — look at `.status.message`
2. Check controller logs for sync errors on that resource
3. Common causes:
   - Validation rejecting the resource (check `status.state: Invalid`)
   - Missing secret reference (TLS, JWT, OIDC secrets)
   - Policy referenced but not found in namespace
   - Resource conflicts (duplicate host/path)

### Controller Crash / Panic

**Symptom:** Pod restarts, panic in logs.

**Diagnosis:**
1. Check logs for the panic stack trace
2. Common causes:
   - Nil pointer on optional CRD field (forgot `*bool`/`*int` check)
   - Map access without nil check on `.Spec.X` field
   - Race condition in concurrent secret/config access
3. Look for the file:line in the stack trace → usually in `internal/configs/` or `internal/k8s/`

### Snapshot Test Failure

**Symptom:** `make test` fails with snapshot mismatch.

**Diagnosis:**
1. This means template output changed — could be intentional or regression
2. Review the diff shown in test output
3. If change is intentional: `make test-update-snaps` to regenerate
4. If change is unintentional: your template edit had side effects — fix the template

## Log Locations

| Context | Location | What to look for |
| --- | --- | --- |
| Controller logs | Pod stdout/stderr | Sync errors, reload status, validation failures |
| NGINX error log | `/var/log/nginx/error.log` in container | Config syntax errors, upstream failures |
| NGINX access log | `/var/log/nginx/access.log` in container | Request routing verification |

## Validation and Diagnostic Tools

| Tool | Command | Purpose |
| --- | --- | --- |
| Config test | `nginx -t` (inside container) | Validate NGINX config syntax |
| CRD status | `kubectl get vs,vsr,ts,pol -A` | Check resource state |
| Controller logs | `kubectl logs <pod> -n nginx-ingress` | Runtime errors |
| Describe events | `kubectl describe vs <name>` | Kubernetes events for the resource |
| Generated config | `kubectl exec <pod> -- cat /etc/nginx/conf.d/<file>` | Inspect actual generated NGINX config |

## Debugging Workflow

1. **Reproduce** — Get the exact error. Is it a reload failure? Wrong routing? Crash?
2. **Assess security impact** — Before diving into the fix, ask:
   - Is this bug exploitable? (Can external input trigger it?)
   - Does the failure expose sensitive data in logs or error messages?
   - Could an attacker craft input to reach this code path?
   - If exploitable: flag for security review BEFORE fixing
3. **Locate the layer** — Use logs and status to determine:
   - Validation layer? → `status.state: Invalid` with reason
   - Config generation? → Generated config has wrong directives
   - Template? → Snapshot test shows the issue
   - Controller? → Sync error in logs, resource not processed
4. **Isolate** — Find minimum CRD/annotation that triggers the issue
5. **Fix** — Make the change in the correct layer (don't fix templates for validation bugs)
6. **Verify** — `make test` passes, snapshot output is correct
7. **Prevent** — Add a test case that would catch this regression (include negative/malicious input tests if the bug was in a validation path)

## Config Generation Debugging

When the generated NGINX config is wrong:

1. **Find the template struct** — Which struct feeds the template? Check `internal/configs/version2/http.go` (VS) or `internal/configs/version1/config.go` (Ingress)
2. **Find the config generator** — Where is the struct populated? Check `internal/configs/virtualserver.go` or `internal/configs/ingress.go`
3. **Find the template** — Which `.tmpl` file renders it? Check `internal/configs/version2/nginx-plus.virtualserver.tmpl` or the OSS variant
4. **Add a snapshot test** — Create a test case in the appropriate `_test.go` file with the input that triggers the bug, run `make test-update-snaps` to capture current (wrong) output, then fix and regenerate

## Common Gotchas When Debugging

- NGINX config errors show line numbers in the GENERATED file, not your template — map back manually
- Secret-related failures often show as "file not found" in NGINX logs (secret not written to filesystem yet)
- Policy ordering matters — first matching policy wins, check `generatePolicies()` logic
- Plus-only features will work in Plus template but silently produce invalid config in OSS template
- `containsDangerousChars()` failures are validation errors and typically result in `status.state: Invalid` — check the CRD status message and controller logs

## Security-Sensitive Debugging

When debugging an issue that involves user-provided input reaching NGINX config:

1. **Trace the input path** — From CRD field / annotation → validation → config struct → template → NGINX config file. Identify every point where sanitization SHOULD happen.
2. **Check for injection** — Can crafted input inject NGINX directives? Look for `;`, `{`, `}`, `$`, newlines, backticks in the user-controlled value.
3. **Verify the guard** — Does `containsDangerousChars()` or `ValidateEscapedString()` cover this path? If not, the bug is a security vulnerability.
4. **Never log secrets** — When debugging TLS/JWT/OIDC issues, mask credential values. Log key names and paths, not contents.
5. **Check RBAC** — If the issue involves unauthorized access, verify ServiceAccount permissions and RBAC role bindings before looking at code.

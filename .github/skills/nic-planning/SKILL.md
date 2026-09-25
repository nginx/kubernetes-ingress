---
name: nic-planning
description: 'Task planning and approach strategy for NIC. Use when starting any non-trivial task, reading issues or specs, planning before implementing, or when asked to create a plan for a change.'
---

# Planning and Task Approach

## Before Writing Code

1. **Read the requirement** — Understand what's being asked. Check linked issues, specs, or PRs for full context.
2. **Write acceptance criteria** — Before implementing, state what "done" looks like in testable terms. What should work? What should be rejected? What must NOT break?
3. **Identify security impact** — Does this change:
   - Accept new external/untrusted input? → Requires input validation at the trust boundary
   - Touch credential or secret paths? → Requires human review
   - Generate config from user data? → Must pass through `containsDangerousChars()`
   - Change RBAC or access control? → Requires security review
4. **Identify affected layers** — Determine which architectural layers are touched:
   - Data Model (`pkg/apis/configuration/v1/types.go`)
   - Validation (`pkg/apis/configuration/validation/`)
   - Controller (`internal/k8s/`)
   - Config Generation (`internal/configs/`)
   - Templates (`internal/configs/version1/` or `version2/`)
   - Process Management (`internal/nginx/`)
   - Helm Chart (`charts/nginx-ingress/`)
5. **Check invariants** — Review the Key Invariants section in AGENTS.md:
   - Security: `containsDangerousChars()` on user strings reaching NGINX config
   - Codegen: Never edit `zz_generated.deepcopy.go` manually
   - Templates: Update BOTH OSS and Plus variants for shared directives; Plus-only directives go in the Plus template only
   - CRD fields: Every new field needs kubebuilder markers + validation + template + tests
6. **Identify test surface** — What tests need adding or updating?
   - Unit tests for validation logic
   - Negative tests for input rejection (security)
   - Snapshot tests for template output
   - Helm tests if chart changes
   - Integration tests if behaviour changes
7. **Produce a plan** — State your approach before coding. List files to change in order. Include what this change must NOT break.

## Layer Impact Checklist

For any change, ask:

- [ ] Does it accept new external input? → Add validation with `containsDangerousChars()` or appropriate sanitizer
- [ ] Does it touch `types.go`? → Run `make update-codegen` then `make update-crds`
- [ ] Does it add a template directive? → Update BOTH `nginx.ingress.tmpl` AND `nginx-plus.ingress.tmpl` (or v2 equivalents) if the directive is shared; Plus-only directives go in the Plus template alone
- [ ] Does it add a CRD field? → Add kubebuilder markers, validation, template struct, rendering, tests
- [ ] Does it touch Helm values? → Update `values.yaml`, `values.schema.json`, and helmunit tests
- [ ] Does it affect config generation? → Add a snapshot fixture that exercises the change, then run `make test-update-snaps`
- [ ] Does it change telemetry data types? → Run `make telemetry-schema`
- [ ] Does user-controlled data reach NGINX config? → Verify sanitization path exists and is tested

## Definition of Done

Do not report a task as complete until every applicable box is ticked. These are the steps most often skipped.

| Condition | Required action | Verification |
| --- | --- | --- |
| Edited any `.tmpl` | Snapshot fixture added **and** regenerated | `git diff -- '**/__snapshots__/**'` is non-empty and shows the new directive |
| Edited a template struct (`version1/config.go`, `version2/http.go`, `version2/stream.go`) | Fixture populates the field, snapshots regenerated | Same as above |
| Edited `pkg/apis/**/types.go` | `make update-codegen && make update-crds` | `git status` shows regenerated `pkg/**`, `config/crd/bases`, `deploy/crds*.yaml`, `docs/crd/` |
| Edited telemetry `Data` / `NICResourceCounts` | `make telemetry-schema` | No diff on re-run |
| Added/changed imports | `go mod tidy` | `go.mod` / `go.sum` clean |
| Edited chart templates or values | testdata + helmunit case | `charts/tests/__snapshots__/` diff is non-empty |
| Added a pytest marker | Registered in `pyproject.toml` | Suite runs under `--strict-markers` |
| Any of the above | `make test` then `make lint` | Both pass |

**Snapshot rule:** regenerating without adding a fixture produces an empty diff, which is a *silent failure*, not a success. If `make test-update-snaps` changes nothing after a template edit, you have not tested the feature.

## Scope Assessment

| Scope | Indicators | Action |
| --- | --- | --- |
| Trivial | Typo, docs, comment fix | Fix directly, no plan needed |
| Small | Single layer, <50 lines, no API change | Brief plan → implement → test |
| Medium | 2-3 layers, new field or annotation | Detailed plan → implement layer by layer → test each |
| Large | New subsystem, new policy type, cross-cutting | Write plan document → get approval → implement in stages |

## Common Planning Mistakes

- Starting implementation before understanding the full scope of affected files
- Forgetting to update BOTH OSS and Plus templates for a shared directive -- or the inverse, leaking a Plus-only directive into the OSS template
- Changing `types.go` without running codegen
- Adding a VirtualServer feature without checking if Ingress (v1) also needs it
- Adding Helm values without updating the JSON schema
- Not checking if the feature already exists as an annotation when adding a CRD field
- Skipping snapshot regeneration after template changes -- or regenerating without adding a fixture, which silently produces no diff
- Forgetting `make telemetry-schema` after touching telemetry data types
- Assuming a directive exists or behaves a certain way without checking <https://nginx.org/en/docs/> -- verify NGINX semantics before wiring a template
- Not identifying where untrusted input enters — a new CRD field IS user input that reaches NGINX config
- Skipping negative tests — only testing the happy path leaves injection vectors undiscovered

## Ordering Rules for Multi-Layer Changes

When a change spans multiple layers, implement in this order:

1. **Data model** — Define types/fields in `types.go`
2. **Codegen** — `make update-codegen && make update-crds`
3. **Validation** — Add validation rules in `pkg/apis/configuration/validation/`
4. **Config structs** — Add fields to template structs in `version1/` or `version2/`
5. **Config generation** — Wire the new field into config builders in `internal/configs/`
6. **Templates** — Add NGINX directives to `.tmpl` files (OSS + Plus)
7. **Controller** — Wire into sync handlers if needed
8. **Helm** — Update chart values, schema, templates
9. **Tests** — Unit, negative, snapshot (fixture + regenerate), helm, integration
10. **Regenerate** — `make update-codegen`, `make update-crds`, `make telemetry-schema`, `make test-update-snaps`, then `make test` and `make lint`

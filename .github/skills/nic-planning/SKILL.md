---
name: nic-planning
description: 'Task planning and approach strategy for NIC. Use when starting any non-trivial task, reading issues or specs, planning before implementing, or when asked to create a plan for a change.'
---

# Planning and Task Approach

## Before Writing Code

1. **Read the requirement** — Understand what's being asked. Check linked issues, specs, or PRs for full context.
2. **Identify affected layers** — Determine which architectural layers are touched:
   - Data Model (`pkg/apis/configuration/v1/types.go`)
   - Validation (`pkg/apis/configuration/validation/`)
   - Controller (`internal/k8s/`)
   - Config Generation (`internal/configs/`)
   - Templates (`internal/configs/version1/` or `version2/`)
   - Process Management (`internal/nginx/`)
   - Helm Chart (`charts/nginx-ingress/`)
3. **Check invariants** — Review the Key Invariants section in AGENTS.md:
   - Security: `containsDangerousChars()` on user strings reaching NGINX config
   - Codegen: Never edit `zz_generated.deepcopy.go` manually
   - Templates: Always update BOTH OSS and Plus variants
   - CRD fields: Every new field needs kubebuilder markers + validation + template + tests
4. **Identify test surface** — What tests need adding or updating?
   - Unit tests for validation logic
   - Snapshot tests for template output
   - Helm tests if chart changes
   - Integration tests if behaviour changes
5. **Produce a plan** — State your approach before coding. List files to change in order.

## Layer Impact Checklist

For any change, ask:

- [ ] Does it touch `types.go`? → Run `make update-codegen` then `make update-crds`
- [ ] Does it add a template directive? → Update BOTH `nginx.ingress.tmpl` AND `nginx-plus.ingress.tmpl` (or v2 equivalents)
- [ ] Does it add a CRD field? → Add kubebuilder markers, validation, template struct, rendering, tests
- [ ] Does it touch Helm values? → Update `values.yaml`, `values.schema.json`, and helmunit tests
- [ ] Does it affect config generation? → Run `make test-update-snaps` after implementation

## Scope Assessment

| Scope | Indicators | Action |
| --- | --- | --- |
| Trivial | Typo, docs, comment fix | Fix directly, no plan needed |
| Small | Single layer, <50 lines, no API change | Brief plan → implement → test |
| Medium | 2-3 layers, new field or annotation | Detailed plan → implement layer by layer → test each |
| Large | New subsystem, new policy type, cross-cutting | Write plan document → get approval → implement in stages |

## Common Planning Mistakes

- Starting implementation before understanding the full scope of affected files
- Forgetting to update BOTH OSS and Plus templates
- Changing `types.go` without running codegen
- Adding a VirtualServer feature without checking if Ingress (v1) also needs it
- Adding Helm values without updating the JSON schema
- Not checking if the feature already exists as an annotation when adding a CRD field
- Skipping snapshot regeneration after template changes

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
9. **Tests** — Unit, snapshot, helm, integration

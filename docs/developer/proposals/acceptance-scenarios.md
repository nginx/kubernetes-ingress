# Proposal: Acceptance Scenarios as the Contract for AI-Written Code

> Status: Proposed
> Author: Discussion from team AI-workflow review, Nov 2026
> Related: [#11061 Migrate Python tests to Go](https://github.com/nginx/kubernetes-ingress/issues/11061), `docs/developer/e2e-golang-poc-findings.md`, `docs/developer/parallel-e2e-plan.md`

## TL;DR

AI agents now write a large share of our code and tests, and that output is outgrowing
what we can review line by line. Today we verify **how** things are built very well:
snapshots, codegen checks, lint. We barely record **what** a change should do before it
is built. The proposal is to write short, numbered **given/when/then scenarios** before
the code, link each one to a test, and treat those tests as a contract that agents cannot
quietly weaken. The planned Go/Ginkgo e2e migration is the natural place to make those
scenarios executable.

---

## Problem

### We have no behaviour specs

No design doc, test, skill or issue template in this repo contains given/when/then
scenarios. Design docs describe intent in prose and list test *categories* after the work
is done.

The `opaque-secrets-high-level-design.md` doc is a good example of where we are. Its
"User Contract" table says which data keys each Secret role requires. That's the expected
outcome. It has no scenarios: no starting state, no action, no observable result. You
would have to derive a scenario like this one from it:

> Given an `Opaque` Secret with `ca.crt` and a VirtualServer's `ingressMTLS` policy
> referencing it, when the VirtualServer is applied, then client certificates signed by
> that CA are accepted and others get a 400.

The tests for this behaviour exist. They are just not connected to the doc.

### Our skills tell agents to write tests last

`nic-planning` orders implementation steps as: types → codegen → validation →
config structs → config generation → templates → controller → Helm → **tests (step 9)**
→ regenerate. `nic-add-feature` adds the snapshot case at step 7 or 9, after the
implementation is in place.

An agent following these steps produces code first, then writes tests to describe what
it built. Those tests can only confirm that the code does what it already does.

### Our strongest gate records what the code already does

`make test-update-snaps` writes whatever the templates currently produce into the golden
files. Only a human reading the diff checks that it was *meant* to look like that. An
empty diff after a template edit means nothing exercises the new branch, which the skills
correctly call a silent failure. But there is no equivalent check at the intent level:
was this directive the right one to add?

### An agent has already silently dropped an assertion

In the Ginkgo PoC's AI porting sample (see `docs/developer/e2e-golang-poc-findings.md`,
"AI-assisted porting sample"), the API-key test dropped its `/no-auth` assertion when
ported. The result compiled, `go vet` was clean, and nothing went red. The finding
document records it as "coverage loss found". Nothing in our skills or review rules would
catch that class of failure.

This is not a one-off risk. The PoC estimates 15–20k lines of AI-written Go for the full
suite. The document names "review effort for AI output" as "the real constraint". Reviewing
a list of scenarios before a port is far cheaper than discovering a gap in a code review
after one.

### Why this matters more with AI tooling

A manually written test is usually written by the person who understands the feature. Its
existence is evidence that the author thought about the scenario. An AI-ported test is
evidence that the agent found a matching code shape. These are different things.

---

## Proposal

Three parts, each independently mergeable.

### Part A: Design docs and agent skills (main branch, docs only)

| # | File | Change |
|---|---|---|
| A1 | `docs/developer/README.md` | Document the design-doc convention. Add the two docs missing from the index. |
| A2 | `docs/developer/opaque-secrets-high-level-design.md` | Backfill acceptance scenarios as the worked example of the convention. |
| A3 | `.github/skills/nic-planning/SKILL.md` | Reorder: types → codegen → **failing tests (watch them fail)** → implementation. Step 2 becomes "write acceptance scenarios; a human approves them". |
| A4 | `.github/skills/nic-add-feature/SKILL.md` and `nic-add-policy/SKILL.md` | Move test and snapshot steps before implementation. |
| A5 | `.github/skills/nic-testing/SKILL.md` | Snapshots are characterisation tests. New behaviour also needs an intent assertion. Add the scenario-docstring convention for new or changed Python tests. |
| A6 | `.github/skills/nic-code-review/SKILL.md` | Blocking rule: deleted or skipped tests, loosened assertions, or snapshot re-records outside the PR's scope need a human's written justification. Check scenario-to-test links when a design doc with scenarios exists. |
| A7 | `AGENTS.md` and `.github/copilot-instructions.md` | New invariant: **Acceptance tests are the contract**. These files are currently identical; both need the same edit. |

`.claude/skills` is a symlink to `.github/skills`, so each skill needs one edit.

#### The design-doc convention (for A1)

Every design doc whose status is "Implemented" or "Proposed" should include an
**Acceptance scenarios** section with this structure:

```markdown
## Acceptance scenarios

| ID | Scenario | Test |
|----|----------|------|
| S1 | **Given** … **when** … **then** … | `TestFoo`, `test_bar.py` |
| S2 | **Given** … **when** … **then** … | `TestBaz` |
| S3 | **Given** … **when** … **then** … | *no test yet* |
```

Rules:
- Scenarios are written and approved by a human before implementation starts.
- A doc reaches `Status: Implemented` only when every scenario has a linked test.
- A scenario with no test is marked "*no test yet*" rather than omitted. That gap is
  the point.
- Linked test names must exist in the codebase. A reviewer can grep for them.

#### Backfilled scenarios for `opaque-secrets-high-level-design.md` (for A2)

| ID | Scenario | Test |
|----|----------|------|
| S1 | **Given** an `Opaque` Secret with `ca.crt`, **when** an IngressMTLS policy references it, **then** client certificates signed by that CA are accepted | `TestValidateSecretForRole` (CA case), `test_ingress_mtls_ingress.py` |
| S2 | **Given** a Secret of any type with the required keys for a role, **when** NIC resolves it, **then** the type field is not checked and the Secret is accepted | `TestValidateSecretForRole` (arbitrary-type cases) |
| S3 | **Given** a Secret missing a required key for its role, **when** NIC resolves it, **then** a warning is published and the previous safe behaviour is preserved | `TestValidateSecretForRoleMissingRequiredKey` |
| S4 | **Given** an `Opaque` Secret containing both a TLS keypair and a CA cert, **when** a VirtualServer references it as its TLS certificate and an IngressMTLS policy references it as the trusted CA, **then** both roles work and two separate role files are written | `TestGetSecretTwoRoles`, `TestValidateSpecialSecretMultiRole` |
| S5 | **Given** a Secret that is not referenced by any NIC resource, **when** it is created or updated, **then** it is not retained, materialised or reloaded | `TestSyncSecretUnreferencedDoesNotMaterializeOrReload` |
| S6 | **Given** a Secret resolved in two roles where one role's data becomes invalid, **when** the Secret is updated, **then** only that role is pruned and the other role continues to work | `TestSecretUpdatePrunesOnlyInvalidRole` |
| S7 | **Given** a Secret materialised in multiple roles, **when** the Secret is deleted, **then** every role's file is removed | `TestDeleteSecretRemovesEveryResolvedRole` |
| S8 | **Given** an API-key Secret whose every data key is a reserved name, **when** NIC resolves it, **then** the Secret is rejected as a misreference | `TestReservedKeysCoversAllRoles`, `TestValidateValidateAPIKeyFails` |
| S9 | **Given** an API-key Secret containing a data key with dangerous characters, **when** NIC resolves it, **then** the Secret is rejected before its data reaches NGINX config | `TestValidateAPIKeySecretRejectsDangerousClientIDs` |
| S10 | **Given** an existing TLS or typed-NIC Secret (pre-migration), **when** NIC starts with the new code, **then** the Secret continues to be accepted without any changes to the Secret itself | `TestValidateSecretForRole` (legacy-type cases) |

### Part B: Python test convention (main branch, new or changed tests only)

No backfill of the existing 154 test files; they are being migrated.

For any **new or modified** Python test, the class or method docstring should state the
scenario:

```python
def test_auth_basic_policy_credentials(self, ...):
    """
    Given a VirtualServer with a basic-auth policy attached,
    when a request arrives without credentials,
    then the response is 401.

    When valid credentials are supplied,
    then the response is 200 and is served from a pod in this namespace.

    When wrong credentials are supplied,
    then the response is 401.
    """
```

This convention applies immediately for new tests. The porting rule in Part C enforces it
for every file migrated to Go.

### Part C: Go/Ginkgo e2e migration (`tests/ginkgo-poc` branch)

These changes go into `docs/developer/e2e-golang-migration-plan.md` and the PoC specs.
They are part of the existing 1–2 day spike, not additional work.

#### Spec conventions

| Ginkgo construct | Role | Equivalent |
|---|---|---|
| `Describe("capability")` | What the system does | Feature or component name |
| `Context("given … / when …")` | State and action | Given + When |
| `It("then …")` | Observable outcome in domain language | Then |
| `By("step")` | Narrative for multi-step flows only | Steps within a scenario |
| `Label("scenario:<doc>/<id>")` | Links spec to design-doc scenario | Traceability |

The outcome in `It` should be in domain language: what a user or operator would observe.
No HTTP method names, no pod counts, no Kubernetes resource kinds unless that *is* the
user-visible thing.

Add DSL verbs (`GivenApp`, `GivenBasicAuthPolicy`, `AttachPolicy`) only when a second
spec needs them. The existing `Sandbox` helpers (`EventuallyStatus`, `ExpectServedHere`)
are already the protocol-driver layer; keep spec-level code above them.

#### Reference example: basic-auth spec rewritten

The existing PoC spec (`tests/e2e/poc/policy_basic_auth_test.go`) in the new style:

```go
var _ = Describe("Basic auth policy", Label("policies"), func() {
    for i := range copies {
        Context(fmt.Sprintf("given a VirtualServer with a basic-auth policy attached #%d", i), func() {
            It("then rejects requests without credentials", Label("scenario:basic-auth/S1"), func(ctx SpecContext) {
                s := f.NewSandbox(ctx)
                s.Apply(ctx, "auth-basic-policy/secret/htpasswd-secret-valid.yaml")
                s.Apply(ctx, "auth-basic-policy/policies/auth-basic-policy-valid.yaml")
                s.Apply(ctx, "common/app/simple/app.yaml")
                s.Apply(ctx, "auth-basic-policy/spec/virtual-server-policy-single.yaml")

                url := "http://" + s.Host("virtual-server.example.com") + "/backend1"
                s.EventuallyStatus(ctx, url, 401)
                s.ExpectServedHere(ctx, s.EventuallyStatus(ctx, url, 200, framework.BasicAuth("foo", "bar")))
                s.EventuallyStatus(ctx, url, 401, framework.BasicAuth("foo", "wrong"))
            })
        })

        Context(fmt.Sprintf("when the basic-auth policy is detached #%d", i), func() {
            It("then serves requests without credentials", Label("scenario:basic-auth/S2"), func(ctx SpecContext) {
                s := f.NewSandbox(ctx)
                s.Apply(ctx, "auth-basic-policy/secret/htpasswd-secret-valid.yaml")
                s.Apply(ctx, "auth-basic-policy/policies/auth-basic-policy-valid.yaml")
                s.Apply(ctx, "common/app/simple/app.yaml")
                s.Apply(ctx, "auth-basic-policy/spec/virtual-server-policy-single.yaml")
                s.Apply(ctx, "virtual-server/standard/virtual-server.yaml")

                url := "http://" + s.Host("virtual-server.example.com") + "/backend1"
                s.EventuallyStatus(ctx, url, 200)
            })
        })
    }
})
```

`ginkgo --dry-run -v` on this prints the full scenario tree as human-readable
documentation with no extra tooling.

#### Porting rule

Before an agent ports a Python file:

1. List every assertion in the Python file as a scenario (given/when/then, one per `assert`
   or response-code check).
2. A human reviews and approves the list in the PR or issue.
3. The Go port must cover every scenario on the approved list.
4. During code review, the reviewer checks the list against the spec, not just the diff.

This rule would have caught the `/no-auth` assertion that the AI porting sample silently
dropped. The drop was not a bug in the agent; it was a gap in the process.

#### Living documentation

```bash
# Print the full scenario tree
ginkgo --dry-run -v ./tests/e2e/...

# Filter to one domain
ginkgo --dry-run -v --label-filter="policies" ./tests/e2e/...
```

No extra tooling needed.

---

## What we are not doing

- **No Gherkin / `.feature` files or `godog`.** Ginkgo's `Describe`/`Context`/`It`
  structure already gives us this. Adding another framework layer would increase
  complexity with no gain.
- **No backfill of the 154 Python test files.** The suite is being migrated.
- **No automated scenario-to-label checker.** Labels make one feasible later; we do not
  need it to start. Manual review of the scenario list is the gate.
- **No mutation testing.** A candidate package (validation logic) exists, but this
  proposal does not add it. Worth revisiting after the convention settles.
- **No new CI gates.** The proposal changes process and guidance, not pipeline
  structure.

---

## What changes day to day

**When planning a feature:**
Write 3–10 scenarios in the design doc or issue before writing any code. A human approves
them. The agent implements against the failing tests that prove those scenarios, not
against a description in Markdown.

**When reviewing a PR:**
Check that every scenario has a test, and that the test actually asserts the scenario's
outcome. Reading the implementation code is a choice you make when the risk warrants it,
not a line-by-line obligation.

**When an agent wants to change a test:**
It must state which scenario the change affects and why the scenario itself changed. A
test deletion with no scenario justification is blocking.

**When porting a Python test to Go:**
Write the scenario list first. Port second.

---

## Decisions needed from the team

1. **Agree on the design-doc convention** (Acceptance scenarios section, ID format,
   "no test yet" policy).
2. **Agree on the review rule** (deleted/weakened tests are blocking without written
   justification).
3. **Choose the pilot design doc.** The *next* design doc written — not a backfill —
   uses scenarios from the start. The opaque-secrets backfill demonstrates the convention
   on existing work; the pilot proves it on new work.
4. **Confirm the porting rule** goes into the spike acceptance criteria alongside the
   existing Go/no-go criteria in `e2e-golang-poc-findings.md`.

---

## Relationship to the existing parallel e2e plan

The `parallel-e2e-plan.md` already has an acceptance-criteria table with a "How we verify
it" column. That is the closest thing in the repo to what this proposal formalises. The
plan's criteria are at the CI and infrastructure level (bleed, order-independence, wall
time). This proposal extends the same thinking down to individual feature behaviour.

The two plans are complementary. `parallel-e2e-plan.md` makes the test suite faster and
more reliable. This proposal makes what the suite *asserts* traceable to documented intent.

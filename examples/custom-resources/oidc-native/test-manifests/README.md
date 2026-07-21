# OIDCNative Manual Test Scenarios

Manual test manifests for exercising OIDCNative policy placement, coexistence
with the NJS OIDC policy, and error handling. These are meant for hand-driven
verification, not CI.

## Prerequisites

Complete the base walkthrough in [../README.md](../README.md) first — Keycloak,
webapp, the `oidcnative-policy`, `client-secret`, `tls-secret`, and `nginx-config`
must all be applied and working end-to-end.

Before running any test, export the same hostname variables from Step 1 of the
base README plus the two extras used by the multi-VS scenarios:

```shell
export WEBAPP_HOST=webapp.${LB_IP}.nip.io
export KEYCLOAK_HOST=keycloak.${LB_IP}.nip.io
export APP1_HOST=app1.${LB_IP}.nip.io    # tests 6, 7, 9 only
export APP2_HOST=app2.${LB_IP}.nip.io    # tests 6, 7, 9 only
```

`run-test.sh` substitutes the `example.com` placeholders in each manifest with
these values on the fly. If any variable is unset, the placeholder is used as-is.

Register the extra hostnames (`app1.<LB_IP>.nip.io`, `app2.<LB_IP>.nip.io`) as
valid redirect URIs in the Keycloak `nginx-plus` client (`https://app1.<...>/*`
and `https://app2.<...>/*`) before running tests 6, 7 or 9.

## Usage

Each scenario is a single manifest. Apply through the wrapper (recommended —
it does the hostname substitution and prints the per-test verify steps):

```shell
./run-test.sh 1                 # apply test-1-*.yaml
./run-test.sh 1 check           # apply + dump generated NGINX config
./run-test.sh list              # list all scenarios
./run-test.sh clean             # tear down all test resources
```

## Scenarios

| # | File | What it exercises |
| - | ---- | ----------------- |
| 1 | test-1-vs-spec.yaml | Policy on VS spec (server-level). All routes protected. |
| 2 | test-2-vs-route.yaml | Policy on a single route (location-level). |
| 3 | test-3-vsr-subroute.yaml | Policy on a VSR subroute. |
| 4 | test-4-two-policies-vs.yaml | Different policies on VS spec vs a route. |
| 5 | test-5-vs-and-vsr.yaml | Different policies on VS spec vs a VSR subroute. |
| 6 | test-6-multi-vs-different-policies.yaml | Two VS with different policies. |
| 7 | test-7-same-policy-multi-vs.yaml | Same policy referenced by two VS. |
| 8a | test-8a-njs-and-native.yaml | NJS OIDC on spec + Native on route (same VS). |
| 8b | test-8b-conflict.yaml | Both NJS and Native on same route (expected: VS Warning). |
| 9 | test-9-njs-vs-native.yaml | NJS on VS1, Native on VS2 (independent). |
| 10 | test-10-lifecycle-delete.yaml | Delete the policy afterward, watch VS go to Warning, re-apply to recover. |
| 13 | test-13-invalid.yaml | Invalid policies rejected at API-server admission. |
| 14 | test-14-no-tls.yaml | VS without TLS (config renders; browser flow won't work). |
| 15 | test-15-mixed-routes.yaml | Some routes protected, some open. |
| 16 | test-16-cross-namespace.yaml | Policy in a different namespace than the VS. |
| 17 | test-17-missing-secret.yaml | Client secret doesn't exist (expected: VS Warning). |
| 18 | test-18-wrong-secret-type.yaml | Secret is `kubernetes.io/tls` (expected: VS Warning). |
| 19 | test-19-missing-ca.yaml | `trustedCertSecret` doesn't exist (expected: VS Warning). |
| 20 | test-20-wrong-ca-type.yaml | CA secret has wrong type (expected: VS Warning). |
| 21 | test-21-wrong-key.yaml | Secret uses a key other than `client-secret` (Keycloak rejects at auth). |
| 22 | test-22-both-oidc.yaml | Both `oidc` and `oidcNative` set on one policy (rejected at admission). |

Tests 11 (secret rotation) and 12 (policy update) are not shipped as manifests —
they use `kubectl patch` / `kubectl create ... --dry-run=client | kubectl apply`
against the base resources; see the base README.

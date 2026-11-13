package k8s

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	schemacel "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	apiextvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
)

// crdSchemaGate applies the CRD's own OpenAPI schema and CEL rules to an object,
// which is what the API server does before the controller ever sees it.
//
// The injection tests need this to be able to say anything useful. A custom
// resource passes three gates on its way to configuration:
//
//  1. the CRD schema enforced by the API server, from config/crd/bases
//  2. the Go validation in pkg/apis/configuration/validation
//  3. the templates, which quote or escape what reaches them
//
// A test that only knows the last two will report a value as reachable when the
// API server would in fact have refused it, and a field whose only protection is
// the schema then looks like a hole. Loading the shipped CRD keeps the verdict
// honest, and reads the same artifact users install rather than a copy of the
// kubebuilder markers.
type crdSchemaGate struct {
	structural *apiextschema.Structural
	validator  apiextvalidation.SchemaValidator
	cel        *schemacel.Validator
}

func newCRDSchemaGate(t *testing.T, path string) *crdSchemaGate {
	t.Helper()

	raw, err := os.ReadFile(path) //nolint:gosec // G304: reads a fixed in-repo CRD artifact in a test
	if err != nil {
		t.Fatalf("cannot read the CRD: %v", err)
	}
	var crd apiextv1.CustomResourceDefinition
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatalf("cannot parse the CRD: %v", err)
	}
	if len(crd.Spec.Versions) != 1 {
		// Every NIC CRD is single-version today. If that changes, the gate has to
		// be told which version to apply rather than guessing.
		t.Fatalf("the CRD declares %d versions, so the gate cannot pick one", len(crd.Spec.Versions))
	}

	var internal apiextensions.JSONSchemaProps
	if err := apiextv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
		crd.Spec.Versions[0].Schema.OpenAPIV3Schema, &internal, nil); err != nil {
		t.Fatalf("cannot convert the CRD schema: %v", err)
	}

	validator, _, err := apiextvalidation.NewSchemaValidator(&internal)
	if err != nil {
		t.Fatalf("cannot build a schema validator: %v", err)
	}
	structural, err := apiextschema.NewStructural(&internal)
	if err != nil {
		t.Fatalf("cannot build a structural schema: %v", err)
	}

	return &crdSchemaGate{
		structural: structural,
		validator:  validator,
		cel:        schemacel.NewValidator(structural, true, celconfig.PerCallLimit),
	}
}

// admits reports the error the API server would return for this object, or nil
// if it would accept it. Both the OpenAPI schema and the CEL rules are applied,
// because NIC uses XValidation for constraints that cannot be written as a
// pattern, and a gate that skipped them would understate what the API server
// catches.
func (g *crdSchemaGate) admits(obj runtime.Object) error {
	unstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return err
	}
	pruneUnset(unstructured)

	errs := apiextvalidation.ValidateCustomResource(nil, unstructured, g.validator)
	if g.cel != nil {
		celErrs, _ := g.cel.Validate(context.Background(), nil, g.structural, unstructured, nil,
			celconfig.RuntimeCELCostBudget)
		errs = append(errs, celErrs...)
	}
	return errs.ToAggregate()
}

// pruneUnset deletes the keys that a Go struct produces for fields the user
// never set, so the object matches the YAML someone would actually apply.
//
// Converting a typed object to unstructured writes every field, and the CRD
// structs do not all carry omitempty, so a nil pointer arrives as an explicit
// null and an unset string as "". The API server rejects both against a typed or
// pattern-constrained property, which would make the gate refuse fixtures a real
// user could apply. A nil pointer and an unset string mean an absent key here,
// and neither can carry an injection, so dropping them costs the test nothing.
func pruneUnset(value map[string]any) {
	for key, child := range value {
		switch typed := child.(type) {
		case nil:
			delete(value, key)
		case string:
			if typed == "" {
				delete(value, key)
			}
		case map[string]any:
			pruneUnset(typed)
			if len(typed) == 0 {
				delete(value, key)
			}
		case []any:
			for _, element := range typed {
				if nested, ok := element.(map[string]any); ok {
					pruneUnset(nested)
				}
			}
			if len(typed) == 0 {
				delete(value, key)
			}
		}
	}
}

// TestCRDSchemaGate checks the gate against the shipped Policy CRD: a value that
// satisfies a pattern is admitted and one that violates it is refused. The
// injection tests rely on this behavior to decide whether the API server, not
// the Go validation, is what would reject a payload.
func TestCRDSchemaGate(t *testing.T) {
	t.Parallel()

	gate := newCRDSchemaGate(t, "../../config/crd/bases/k8s.nginx.org_policies.yaml")

	// cacheZoneSize carries the pattern ^[0-9]+[kmgKMG]$ in the CRD.
	valid := &conf_v1.Policy{
		Spec: conf_v1.PolicySpec{
			Cache: &conf_v1.Cache{CacheZoneName: "zone", CacheZoneSize: "10m"},
		},
	}
	if err := gate.admits(valid); err != nil {
		t.Errorf("the CRD schema rejected a valid Policy: %v", err)
	}

	invalid := &conf_v1.Policy{
		Spec: conf_v1.PolicySpec{
			Cache: &conf_v1.Cache{CacheZoneName: "zone", CacheZoneSize: "not-a-size"},
		},
	}
	if err := gate.admits(invalid); err == nil {
		t.Error("the CRD schema admitted a Policy whose cacheZoneSize violates its pattern")
	}

	// cacheKey has no pattern, only a CEL rule rejecting ';' and other command
	// patterns, so this rejection can only come from the CEL validator.
	celValid := &conf_v1.Policy{
		Spec: conf_v1.PolicySpec{
			Cache: &conf_v1.Cache{CacheZoneName: "zone", CacheZoneSize: "10m", CacheKey: "$scheme$host$request_uri"},
		},
	}
	if err := gate.admits(celValid); err != nil {
		t.Errorf("the CRD schema rejected a valid cacheKey: %v", err)
	}

	celInvalid := &conf_v1.Policy{
		Spec: conf_v1.PolicySpec{
			Cache: &conf_v1.Cache{CacheZoneName: "zone", CacheZoneSize: "10m", CacheKey: "$host; return 500"},
		},
	}
	err := gate.admits(celInvalid)
	if err == nil {
		t.Fatal("the CRD schema admitted a cacheKey that violates its CEL rule, so CEL rules are not applied")
	}
	if !strings.Contains(err.Error(), "command execution patterns") {
		t.Errorf("want the cacheKey CEL rule message, got: %v", err)
	}
}

// TestCRDSchemaGateJWTClaimValues covers the claim value rules that are mirrored in CEL as defense in depth
// for the controller's own validation: the value limits and the character rules per match type.
func TestCRDSchemaGateJWTClaimValues(t *testing.T) {
	t.Parallel()

	gate := newCRDSchemaGate(t, "../../config/crd/bases/k8s.nginx.org_policies.yaml")

	policy := func(match conf_v1.JWTClaimMatchType, values ...string) *conf_v1.Policy {
		return &conf_v1.Policy{Spec: conf_v1.PolicySpec{JWTAuth: &conf_v1.JWTAuth{
			Realm:  "realm",
			Secret: "jwk",
			Authorization: &conf_v1.JWTAuthorization{Rules: []conf_v1.JWTAuthorizationRule{
				{Claims: []conf_v1.JWTClaim{{Name: "c", Match: &match, Values: values}}},
			}},
		}}}
	}
	many := func(n int) []string {
		values := make([]string, n)
		for i := range values {
			values[i] = "v"
		}
		return values
	}

	tests := []struct {
		name   string
		policy *conf_v1.Policy
		admit  bool
	}{
		{"exact plain", policy(conf_v1.JWTClaimMatchExact, "a b", `a"b`, `c\d`), true},
		{"exact semicolon", policy(conf_v1.JWTClaimMatchExact, "a;b"), false},
		{"exact brace", policy(conf_v1.JWTClaimMatchExact, "a{b"), false},
		{"exact dollar", policy(conf_v1.JWTClaimMatchExact, "a$b"), false},
		{"exact backtick", policy(conf_v1.JWTClaimMatchExact, "a`b"), false},
		{"exact newline", policy(conf_v1.JWTClaimMatchExact, "a\nb"), false},
		{"exact carriage return", policy(conf_v1.JWTClaimMatchExact, "a\rb"), false},
		{"contains plain", policy(conf_v1.JWTClaimMatchContains, "orders:read"), true},
		{"contains dollar", policy(conf_v1.JWTClaimMatchContains, "a$b"), false},
		{"contains space", policy(conf_v1.JWTClaimMatchContains, "a b"), false},
		{"regex anchors and braces", policy(conf_v1.JWTClaimMatchRegex, `^[a-z0-9]{3,12}$`, `^[^@]+@example\.com$`), true},
		{"regex numbered capture", policy(conf_v1.JWTClaimMatchRegex, `^(a|b)$`, `^(?:a|b)$`), true},
		{"regex lookbehind", policy(conf_v1.JWTClaimMatchRegex, `(?<=a+)b`), false},
		{"regex negative lookbehind", policy(conf_v1.JWTClaimMatchRegex, `(?<!a)b`), false},
		{"regex named capture angle", policy(conf_v1.JWTClaimMatchRegex, `^(?<host>.*)$`), false},
		{"regex named capture P", policy(conf_v1.JWTClaimMatchRegex, `^(?P<host>.*)$`), false},
		{"regex named capture quote", policy(conf_v1.JWTClaimMatchRegex, `^(?'host'.*)$`), false},
		{"regex escaped named capture", policy(conf_v1.JWTClaimMatchRegex, `^\(?<n>x\)$`), false},
		{"regex bracketed named capture", policy(conf_v1.JWTClaimMatchRegex, `^[(?<n>]x$`), false},
		{"32 values", policy(conf_v1.JWTClaimMatchExact, many(32)...), true},
		{"33 values", policy(conf_v1.JWTClaimMatchExact, many(33)...), false},
		{"256 character value", policy(conf_v1.JWTClaimMatchExact, strings.Repeat("a", 256)), true},
		{"257 character value", policy(conf_v1.JWTClaimMatchExact, strings.Repeat("a", 257)), false},
		{"256 multibyte character value", policy(conf_v1.JWTClaimMatchExact, strings.Repeat("é", 256)), true},
		{"257 multibyte character value", policy(conf_v1.JWTClaimMatchExact, strings.Repeat("é", 257)), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := gate.admits(tc.policy)
			if tc.admit && err != nil {
				t.Errorf("the CRD rejected a valid policy: %v", err)
			}
			if !tc.admit && err == nil {
				t.Error("the CRD admitted a policy that must be rejected")
			}
		})
	}
}

// TestCRDSchemaGateAuthResponseHeaders covers the scenario "Invalid lists are
// rejected" of the ExternalAuth response headers design at the API server: the
// shipped CRD admits valid lists, and rejects invalid ones naming the rule that
// each breaks.
func TestCRDSchemaGateAuthResponseHeaders(t *testing.T) {
	t.Parallel()

	gate := newCRDSchemaGate(t, "../../config/crd/bases/k8s.nginx.org_policies.yaml")
	longest := "X-" + strings.Repeat("a", 44)
	distinct := func(count, length int) []string {
		names := make([]string, count)
		for i := range names {
			prefix := fmt.Sprintf("X-%02d-", i)
			names[i] = prefix + strings.Repeat("a", length-len(prefix))
		}
		return names
	}

	tests := []struct {
		name    string
		headers []string
		// want is part of the expected error, or empty when the CRD admits the list.
		want string
	}{
		{name: "names that other configuration also sets", headers: []string{"Tenant-UUID", "Authorization"}},
		{name: "one 46-character name", headers: []string{longest}},
		{name: "32 distinct 46-character names", headers: distinct(32, 46)},
		{name: "Invalid lists are rejected: a name with _", headers: []string{"X_User"}, want: "should match"},
		{name: "Invalid lists are rejected: an empty name", headers: []string{""}, want: "should match"},
		{name: "Invalid lists are rejected: a 47-character name", headers: []string{longest + "a"}, want: "Too long"},
		{name: "Invalid lists are rejected: 33 names", headers: distinct(33, 10), want: "Too many"},
		{name: "Invalid lists are rejected: names that differ only in case", headers: []string{"X-User", "x-user"}, want: "must be unique, ignoring case"},
		{name: "Invalid lists are rejected: reserved name host", headers: []string{"host"}, want: "managed by NGINX"},
		{name: "Invalid lists are rejected: reserved name CONTENT-LENGTH", headers: []string{"CONTENT-LENGTH"}, want: "managed by NGINX"},
		{name: "Invalid lists are rejected: reserved name X-Forwarded-For", headers: []string{"X-Forwarded-For"}, want: "managed by NGINX"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := &conf_v1.Policy{
				Spec: conf_v1.PolicySpec{
					ExternalAuth: &conf_v1.ExternalAuth{AuthURI: "/auth", AuthServiceName: "auth-svc", AuthResponseHeaders: tc.headers},
				},
			}
			err := gate.admits(policy)
			if tc.want == "" {
				if err != nil {
					t.Errorf("the CRD rejected %q: %v", tc.headers, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("the CRD admitted %q, want an error containing %q", tc.headers, tc.want)
			}
			if !strings.Contains(err.Error(), "authResponseHeaders") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the CRD rejected %q with %q, want an error on authResponseHeaders containing %q", tc.headers, err, tc.want)
			}
		})
	}
}

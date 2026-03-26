package version1

import (
	"bytes"
	"testing"
	"text/template"

	"github.com/nginx/kubernetes-ingress/internal/configs/commonhelpers"
)

func TestMakeLocationPath_WithRegexCaseSensitiveModifier(t *testing.T) {
	t.Parallel()

	want := "~ \"^/coffee/[A-Z0-9]{3}\""
	got := makeLocationPath(
		&Location{Path: "/coffee/[A-Z0-9]{3}"},
		map[string]string{"nginx.org/path-regex": "case_sensitive"},
	)
	if got != want {
		t.Errorf("got: %s, want: %s", got, want)
	}
}

func TestMakeLocationPath_WithRegexCaseInsensitiveModifier(t *testing.T) {
	t.Parallel()

	want := "~* \"^/coffee/[A-Z0-9]{3}\""
	got := makeLocationPath(
		&Location{Path: "/coffee/[A-Z0-9]{3}"},
		map[string]string{"nginx.org/path-regex": "case_insensitive"},
	)
	if got != want {
		t.Errorf("got: %s, want: %s", got, want)
	}
}

func TestMakeLocationPath_WithRegexExactModifier(t *testing.T) {
	t.Parallel()

	want := "= \"/coffee\""
	got := makeLocationPath(
		&Location{Path: "/coffee"},
		map[string]string{"nginx.org/path-regex": "exact"},
	)
	if got != want {
		t.Errorf("got: %s, want: %s", got, want)
	}
}

func TestMakeLocationPath_WithBogusRegexModifier(t *testing.T) {
	t.Parallel()

	want := "/coffee"
	got := makeLocationPath(
		&Location{Path: "/coffee"},
		map[string]string{"nginx.org/path-regex": "bogus"},
	)
	if got != want {
		t.Errorf("got: %s, want: %s", got, want)
	}
}

func TestMakeLocationPath_WithEmptyRegexModifier(t *testing.T) {
	t.Parallel()

	want := "/coffee"
	got := makeLocationPath(
		&Location{Path: "/coffee"},
		map[string]string{"nginx.org/path-regex": ""},
	)
	if got != want {
		t.Errorf("got: %s, want: %s", got, want)
	}
}

func TestMakeLocationPath_WithBogusAnnotationName(t *testing.T) {
	t.Parallel()

	want := "/coffee"
	got := makeLocationPath(
		&Location{Path: "/coffee"},
		map[string]string{"nginx.org/bogus-annotation": ""},
	)
	if got != want {
		t.Errorf("got: %s, want: %s", got, want)
	}
}

func TestMakeLocationPath_ForIngressWithoutPathRegex(t *testing.T) {
	t.Parallel()

	want := "/coffee"
	got := makeLocationPath(
		&Location{Path: "/coffee"},
		map[string]string{},
	)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMakeLocationPath_ForIngressWithPathRegexCaseSensitive(t *testing.T) {
	t.Parallel()

	want := "~ \"^/coffee\""
	got := makeLocationPath(
		&Location{Path: "/coffee"},
		map[string]string{
			"nginx.org/path-regex": "case_sensitive",
		},
	)
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMakeLocationPath_ForIngressWithPathRegexSetOnMinion(t *testing.T) {
	t.Parallel()

	want := "~ \"^/coffee\""
	got := makeLocationPath(
		&Location{
			Path: "/coffee",
			MinionIngress: &Ingress{
				Name:      "cafe-ingress-coffee-minion",
				Namespace: "default",
				Annotations: map[string]string{
					"nginx.org/mergeable-ingress-type": "minion",
					"nginx.org/path-regex":             "case_sensitive",
				},
			},
		},
		map[string]string{
			"nginx.org/mergeable-ingress-type": "master",
		},
	)

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMakeLocationPath_ForIngressWithPathRegexSetOnMaster(t *testing.T) {
	t.Parallel()

	want := "~ \"^/coffee\""
	got := makeLocationPath(
		&Location{
			Path: "/coffee",
			MinionIngress: &Ingress{
				Name:      "cafe-ingress-coffee-minion",
				Namespace: "default",
			},
		},
		map[string]string{
			"nginx.org/mergeable-ingress-type": "master",
			"nginx.org/path-regex":             "case_sensitive",
		},
	)

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMakeLocationPath_SetOnMinionTakesPrecedenceOverMaster(t *testing.T) {
	t.Parallel()

	want := "= \"/coffee\""
	got := makeLocationPath(
		&Location{
			Path: "/coffee",
			MinionIngress: &Ingress{
				Name:      "cafe-ingress-coffee-minion",
				Namespace: "default",
				Annotations: map[string]string{
					"nginx.org/mergeable-ingress-type": "minion",
					"nginx.org/path-regex":             "exact",
				},
			},
		},
		map[string]string{
			"nginx.org/mergeable-ingress-type": "master",
			"nginx.org/path-regex":             "case_sensitive",
		},
	)

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMakeLocationPath_PathRegexSetOnMasterDoesNotModifyMinionWithoutPathRegexAnnotation(t *testing.T) {
	t.Parallel()

	want := "/coffee"
	got := makeLocationPath(
		&Location{
			Path: "/coffee",
			MinionIngress: &Ingress{
				Name:      "cafe-ingress-coffee-minion",
				Namespace: "default",
				Annotations: map[string]string{
					"nginx.org/mergeable-ingress-type": "minion",
				},
			},
		},
		map[string]string{
			"nginx.org/mergeable-ingress-type": "master",
			"nginx.org/path-regex":             "exact",
		},
	)

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMakeLocationPath_ForIngress(t *testing.T) {
	t.Parallel()

	want := "~ \"^/coffee\""
	got := makeLocationPath(
		&Location{
			Path: "/coffee",
		},
		map[string]string{
			"nginx.org/path-regex": "case_sensitive",
		},
	)

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSplitInputString(t *testing.T) {
	t.Parallel()

	tmpl := newSplitTemplate(t)
	var buf bytes.Buffer

	input := "foo,bar"
	expected := "foo bar "

	err := tmpl.Execute(&buf, input)
	if err != nil {
		t.Fatalf("Failed to execute the template %v", err)
	}
	if buf.String() != expected {
		t.Errorf("Template generated wrong config, got %v but expected %v.", buf.String(), expected)
	}
}

func TestTrimWhiteSpaceFromInputString(t *testing.T) {
	t.Parallel()

	tmpl := newTrimTemplate(t)
	inputs := []string{
		"  foobar     ",
		"foobar   ",
		"   foobar",
		"foobar",
	}
	expected := "foobar"

	for _, i := range inputs {
		var buf bytes.Buffer
		err := tmpl.Execute(&buf, i)
		if err != nil {
			t.Fatalf("Failed to execute the template %v", err)
		}
		if buf.String() != expected {
			t.Errorf("Template generated wrong config, got %v but expected %v.", buf.String(), expected)
		}
	}
}

func TestReplaceAll(t *testing.T) {
	t.Parallel()

	tmpl := newReplaceAll(t)
	testCases := []struct {
		InputString  string
		OldSubstring string
		NewSubstring string
		expected     string
	}{
		{InputString: "foobarfoo", OldSubstring: "bar", NewSubstring: "foo", expected: "foofoofoo"},
		{InputString: "footest", OldSubstring: "test", NewSubstring: "bar", expected: "foobar"},
		{InputString: "barfoo", OldSubstring: "bar", NewSubstring: "test", expected: "testfoo"},
		{InputString: "foofoofoo", OldSubstring: "foo", NewSubstring: "bar", expected: "barbarbar"},
	}

	for _, tc := range testCases {
		var buf bytes.Buffer
		err := tmpl.Execute(&buf, tc)
		if err != nil {
			t.Fatalf("Failed to execute the template %v", err)
		}
		if buf.String() != tc.expected {
			t.Errorf("Template generated wrong config, got %v but expected %v.", buf.String(), tc.expected)
		}
	}
}

func TestContainsSubstring(t *testing.T) {
	t.Parallel()

	tmpl := newContainsTemplate(t)
	testCases := []struct {
		InputString string
		Substring   string
		expected    string
	}{
		{InputString: "foo", Substring: "foo", expected: "true"},
		{InputString: "foobar", Substring: "foo", expected: "true"},
		{InputString: "foo", Substring: "", expected: "true"},
		{InputString: "foo", Substring: "bar", expected: "false"},
		{InputString: "foo", Substring: "foobar", expected: "false"},
		{InputString: "", Substring: "foo", expected: "false"},
	}

	for _, tc := range testCases {
		var buf bytes.Buffer
		err := tmpl.Execute(&buf, tc)
		if err != nil {
			t.Fatalf("Failed to execute the template %v", err)
		}
		if buf.String() != tc.expected {
			t.Errorf("Template generated wrong config, got %v but expected %v.", buf.String(), tc.expected)
		}
	}
}

func TestHasPrefix(t *testing.T) {
	t.Parallel()

	tmpl := newHasPrefixTemplate(t)
	testCases := []struct {
		InputString string
		Prefix      string
		expected    string
	}{
		{InputString: "foo", Prefix: "foo", expected: "true"},
		{InputString: "foo", Prefix: "f", expected: "true"},
		{InputString: "foo", Prefix: "", expected: "true"},
		{InputString: "foo", Prefix: "oo", expected: "false"},
		{InputString: "foo", Prefix: "bar", expected: "false"},
		{InputString: "foo", Prefix: "foobar", expected: "false"},
	}

	for _, tc := range testCases {
		var buf bytes.Buffer
		err := tmpl.Execute(&buf, tc)
		if err != nil {
			t.Fatalf("Failed to execute the template %v", err)
		}
		if buf.String() != tc.expected {
			t.Errorf("Template generated wrong config, got %v but expected %v.", buf.String(), tc.expected)
		}
	}
}

func TestHasSuffix(t *testing.T) {
	t.Parallel()

	tmpl := newHasSuffixTemplate(t)
	testCases := []struct {
		InputString string
		Suffix      string
		expected    string
	}{
		{InputString: "bar", Suffix: "bar", expected: "true"},
		{InputString: "bar", Suffix: "r", expected: "true"},
		{InputString: "bar", Suffix: "", expected: "true"},
		{InputString: "bar", Suffix: "ba", expected: "false"},
		{InputString: "bar", Suffix: "foo", expected: "false"},
		{InputString: "bar", Suffix: "foobar", expected: "false"},
	}

	for _, tc := range testCases {
		var buf bytes.Buffer
		err := tmpl.Execute(&buf, tc)
		if err != nil {
			t.Fatalf("Failed to execute the template %v", err)
		}
		if buf.String() != tc.expected {
			t.Errorf("Template generated wrong config, got %v but expected %v.", buf.String(), tc.expected)
		}
	}
}

func TestToLowerInputString(t *testing.T) {
	t.Parallel()

	tmpl := newToLowerTemplate(t)
	testCases := []struct {
		InputString string
		expected    string
	}{
		{InputString: "foobar", expected: "foobar"},
		{InputString: "FOOBAR", expected: "foobar"},
		{InputString: "fOoBaR", expected: "foobar"},
		{InputString: "", expected: ""},
	}

	for _, tc := range testCases {
		var buf bytes.Buffer
		err := tmpl.Execute(&buf, tc)
		if err != nil {
			t.Fatalf("Failed to execute the template %v", err)
		}
		if buf.String() != tc.expected {
			t.Errorf("Template generated wrong config, got %v but expected %v.", buf.String(), tc.expected)
		}
	}
}

func TestToUpperInputString(t *testing.T) {
	t.Parallel()

	tmpl := newToUpperTemplate(t)
	testCases := []struct {
		InputString string
		expected    string
	}{
		{InputString: "foobar", expected: "FOOBAR"},
		{InputString: "FOOBAR", expected: "FOOBAR"},
		{InputString: "fOoBaR", expected: "FOOBAR"},
		{InputString: "", expected: ""},
	}

	for _, tc := range testCases {
		var buf bytes.Buffer
		err := tmpl.Execute(&buf, tc)
		if err != nil {
			t.Fatalf("Failed to execute the template %v", err)
		}
		if buf.String() != tc.expected {
			t.Errorf("Template generated wrong config, got %v but expected %v.", buf.String(), tc.expected)
		}
	}
}

func newSplitTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("testTemplate").Funcs(helperFunctions).Parse(`{{range $n := split . ","}}{{$n}} {{end}}`)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}
	return tmpl
}

func newTrimTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("testTemplate").Funcs(helperFunctions).Parse(`{{trim .}}`)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}
	return tmpl
}

func newContainsTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("testTemplate").Funcs(helperFunctions).Parse(`{{contains .InputString .Substring}}`)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}
	return tmpl
}

func newHasPrefixTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("testTemplate").Funcs(helperFunctions).Parse(`{{hasPrefix .InputString .Prefix}}`)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}
	return tmpl
}

func newHasSuffixTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("testTemplate").Funcs(helperFunctions).Parse(`{{hasSuffix .InputString .Suffix}}`)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}
	return tmpl
}

func newToLowerTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("testTemplate").Funcs(helperFunctions).Parse(`{{toLower .InputString}}`)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}
	return tmpl
}

func newToUpperTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("testTemplate").Funcs(helperFunctions).Parse(`{{toUpper .InputString}}`)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}
	return tmpl
}

func newReplaceAll(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("testTemplate").Funcs(helperFunctions).Parse(`{{replaceAll .InputString .OldSubstring .NewSubstring}}`)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}
	return tmpl
}

func TestMakeResolver(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		resolverAddresses []string
		resolverValid     string
		resolverIPV6      *bool
		expected          string
	}{
		{
			name:              "No addresses",
			resolverAddresses: []string{},
			resolverValid:     "",
			resolverIPV6:      commonhelpers.BoolToPointerBool(true),
			expected:          "",
		},
		{
			name:              "Single address, default options",
			resolverAddresses: []string{"8.8.8.8"},
			resolverValid:     "",
			resolverIPV6:      commonhelpers.BoolToPointerBool(true),
			expected:          "resolver 8.8.8.8;",
		},
		{
			name:              "Multiple addresses, valid time, ipv6 on",
			resolverAddresses: []string{"8.8.8.8", "8.8.4.4"},
			resolverValid:     "30s",
			resolverIPV6:      commonhelpers.BoolToPointerBool(true),
			expected:          "resolver 8.8.8.8 8.8.4.4 valid=30s;",
		},
		{
			name:              "Single address, ipv6 off",
			resolverAddresses: []string{"8.8.8.8"},
			resolverValid:     "",
			resolverIPV6:      commonhelpers.BoolToPointerBool(false),
			expected:          "resolver 8.8.8.8 ipv6=off;",
		},
		{
			name:              "Multiple addresses, valid time, ipv6 off",
			resolverAddresses: []string{"8.8.8.8", "8.8.4.4"},
			resolverValid:     "30s",
			resolverIPV6:      commonhelpers.BoolToPointerBool(false),
			expected:          "resolver 8.8.8.8 8.8.4.4 valid=30s ipv6=off;",
		},
		{
			name:              "No valid time, ipv6 off",
			resolverAddresses: []string{"8.8.8.8"},
			resolverValid:     "",
			resolverIPV6:      commonhelpers.BoolToPointerBool(false),
			expected:          "resolver 8.8.8.8 ipv6=off;",
		},
		{
			name:              "Valid time only",
			resolverAddresses: []string{"8.8.8.8"},
			resolverValid:     "10s",
			resolverIPV6:      commonhelpers.BoolToPointerBool(true),
			expected:          "resolver 8.8.8.8 valid=10s;",
		},
		{
			name:              "IPv6 only",
			resolverAddresses: []string{"8.8.8.8"},
			resolverValid:     "",
			resolverIPV6:      commonhelpers.BoolToPointerBool(false),
			expected:          "resolver 8.8.8.8 ipv6=off;",
		},
		{
			name:              "All options",
			resolverAddresses: []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"},
			resolverValid:     "60s",
			resolverIPV6:      commonhelpers.BoolToPointerBool(false),
			expected:          "resolver 8.8.8.8 8.8.4.4 1.1.1.1 valid=60s ipv6=off;",
		},
		{
			name:              "All options, ipv6 nil",
			resolverAddresses: []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"},
			resolverValid:     "60s",
			resolverIPV6:      nil,
			expected:          "resolver 8.8.8.8 8.8.4.4 1.1.1.1 valid=60s;",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := makeResolver(tc.resolverAddresses, tc.resolverValid, tc.resolverIPV6)
			if got != tc.expected {
				t.Errorf("makeResolver(%v, %q, %v) = %q; want %q", tc.resolverAddresses, tc.resolverValid, tc.resolverIPV6, got, tc.expected)
			}
		})
	}
}

func TestMakeRewritePattern_WithRegexCaseSensitiveModifier(t *testing.T) {
	t.Parallel()

	want := "^/(hello|hi)"
	got := makeRewritePattern(
		&Location{Path: "/(hello|hi)"},
		map[string]string{"nginx.org/path-regex": "case_sensitive"},
	)
	if got != want {
		t.Errorf("makeRewritePattern() = %q; want %q", got, want)
	}
}

func TestMakeRewritePattern_WithRegexCaseInsensitiveModifier(t *testing.T) {
	t.Parallel()

	want := "(?i)^/(hello|hi)"
	got := makeRewritePattern(
		&Location{Path: "/(hello|hi)"},
		map[string]string{"nginx.org/path-regex": "case_insensitive"},
	)
	if got != want {
		t.Errorf("makeRewritePattern() = %q; want %q", got, want)
	}
}

func TestMakeRewritePattern_WithRegexExactModifier(t *testing.T) {
	t.Parallel()

	want := "/coffee"
	got := makeRewritePattern(
		&Location{Path: "/coffee"},
		map[string]string{"nginx.org/path-regex": "exact"},
	)
	if got != want {
		t.Errorf("makeRewritePattern() = %q; want %q", got, want)
	}
}

func TestMakeRewritePattern_WithBogusRegexModifier(t *testing.T) {
	t.Parallel()

	want := "/(hello|hi)"
	got := makeRewritePattern(
		&Location{Path: "/(hello|hi)"},
		map[string]string{"nginx.org/path-regex": "bogus"},
	)
	if got != want {
		t.Errorf("makeRewritePattern() = %q; want %q", got, want)
	}
}

func TestMakeRewritePattern_WithoutRegexModifier(t *testing.T) {
	t.Parallel()

	want := "/coffee"
	got := makeRewritePattern(
		&Location{Path: "/coffee"},
		map[string]string{},
	)
	if got != want {
		t.Errorf("makeRewritePattern() = %q; want %q", got, want)
	}
}

func TestMakeRewritePattern_WithMergableIngress(t *testing.T) {
	t.Parallel()

	// Test with minion ingress having path-regex annotation
	want := "^/coffee/[A-Z0-9]{3}"
	got := makeRewritePattern(
		&Location{
			Path: "/coffee/[A-Z0-9]{3}",
			MinionIngress: &Ingress{
				Annotations: map[string]string{
					"nginx.org/mergeable-ingress-type": "minion",
					"nginx.org/path-regex":             "case_sensitive",
				},
			},
		},
		map[string]string{"nginx.org/path-regex": "case_insensitive"}, // Should be ignored
	)
	if got != want {
		t.Errorf("makeRewritePattern() = %q; want %q", got, want)
	}
}

func TestMakeRewritePattern_WithComplexPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		path      string
		pathRegex string
		expected  string
	}{
		{
			name:      "Simple path with case sensitive regex",
			path:      "/api/(v1|v2)",
			pathRegex: "case_sensitive",
			expected:  "^/api/(v1|v2)",
		},
		{
			name:      "Complex regex pattern with case insensitive",
			path:      "/user/([0-9]+)/(profile|settings)",
			pathRegex: "case_insensitive",
			expected:  "(?i)^/user/([0-9]+)/(profile|settings)",
		},
		{
			name:      "Exact match pattern",
			path:      "/health",
			pathRegex: "exact",
			expected:  "/health",
		},
		{
			name:      "Pattern with special characters",
			path:      "/api/v1/([a-zA-Z0-9_-]+)/data",
			pathRegex: "case_sensitive",
			expected:  "^/api/v1/([a-zA-Z0-9_-]+)/data",
		},
		{
			name:      "Path with no regex annotation",
			path:      "/static/assets",
			pathRegex: "",
			expected:  "/static/assets",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			annotations := map[string]string{}
			if tt.pathRegex != "" {
				annotations["nginx.org/path-regex"] = tt.pathRegex
			}

			got := makeRewritePattern(
				&Location{Path: tt.path},
				annotations,
			)
			if got != tt.expected {
				t.Errorf("Test %q: makeRewritePattern() = %q; want %q", tt.name, got, tt.expected)
			}
		})
	}
}

package nginx

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNginxVersionParsing(t *testing.T) {
	t.Parallel()
	type testCase struct {
		input    string
		expected Version
	}
	testCases := []testCase{
		{
			input: "nginx version: nginx/1.25.1 (nginx-plus-r30-p1)",
			expected: Version{
				Raw:    "nginx version: nginx/1.25.1 (nginx-plus-r30-p1)",
				OSS:    "1.25.1",
				IsPlus: true,
				Plus:   "nginx-plus-r30-p1",
			},
		},
		{
			input: "nginx version: nginx/1.25.3 (nginx-plus-r31)",
			expected: Version{
				Raw:    "nginx version: nginx/1.25.3 (nginx-plus-r31)",
				OSS:    "1.25.3",
				IsPlus: true,
				Plus:   "nginx-plus-r31",
			},
		},
		{
			input: "nginx version: nginx/1.25.0",
			expected: Version{
				Raw:    "nginx version: nginx/1.25.0",
				OSS:    "1.25.0",
				IsPlus: false,
				Plus:   "",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			actual := NewVersion(tc.input)
			if actual != tc.expected {
				t.Errorf("expected %v but got %v", tc.expected, actual)
			}
		})
	}
}

func TestNginxVersionFormat(t *testing.T) {
	t.Parallel()

	tt := []struct {
		input string
		want  string
	}{
		{
			input: "nginx version: nginx/1.25.1 (nginx-plus-r30-p1)",
			want:  "1.25.1-nginx-plus-r30-p1",
		},
		{
			input: "nginx version: nginx/1.25.3 (nginx-plus-r31)",
			want:  "1.25.3-nginx-plus-r31",
		},
		{
			input: "nginx version: nginx/1.25.0",
			want:  "1.25.0",
		},
	}
	for _, tc := range tt {
		t.Run(tc.input, func(t *testing.T) {
			v := NewVersion(tc.input)
			got := v.Format()
			if got != tc.want {
				t.Errorf("want %q but got %q", tc.want, got)
			}
		})
	}
}

func TestNginxVersionPlusGreaterThanOrEqualTo(t *testing.T) {
	t.Parallel()
	type testCase struct {
		version  Version
		input    string
		expected bool
	}
	testCases := []testCase{
		{
			version:  NewVersion("nginx version: nginx/1.25.1 (nginx-plus-r30-p1)"),
			input:    "nginx-plus-r30-p1",
			expected: true,
		},
		{
			version:  NewVersion("nginx version: nginx/1.25.1 (nginx-plus-r30)"),
			input:    "nginx-plus-r30",
			expected: true,
		},
		{
			version:  NewVersion("nginx version: nginx/1.25.1 (nginx-plus-r30-p1)"),
			input:    "nginx-plus-r30",
			expected: true,
		},
		{
			version:  NewVersion("nginx version: nginx/1.25.1 (nginx-plus-r30)"),
			input:    "nginx-plus-r30-p1",
			expected: false,
		},
		{
			version:  NewVersion("nginx version: nginx/1.25.1"),
			input:    "nginx-plus-r30-p1",
			expected: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			actual, _ := tc.version.PlusGreaterThanOrEqualTo(tc.input)
			if actual != tc.expected {
				t.Errorf("expected %v but got %v", tc.expected, actual)
			}
		})
	}
}

func TestNginxVersionPlusGreaterThanOrEqualToFailsOnInalidInput(t *testing.T) {
	t.Parallel()

	tt := []struct {
		version Version
		input   string
	}{
		{
			version: NewVersion("nginx version: nginx/1.25.1 (nginx-plus-r30-p1)"),
			input:   "nginx-plus",
		},
		{
			version: NewVersion("nginx version: nginx/1.25.1 (nginx-plus-r30)"),
			input:   "nginxr30",
		},
		{
			version: NewVersion("nginx version: nginx/1.25.1 (nginx-plus-r30-p1)"),
			input:   "",
		},
		{
			version: NewVersion("nginx version: nginx/1.25.1 (nginx-plus-r30)"),
			input:   "30",
		},
		{
			version: NewVersion("nginx version: nginx/1.25.1"),
			input:   "-3",
		},
		{
			version: NewVersion("nginx version: nginx/1.25.1 (nginx-plus-r30-p1)"),
			input:   "nginx-plus-rA",
		},
	}
	for _, tc := range tt {
		t.Run(tc.input, func(t *testing.T) {
			_, err := tc.version.PlusGreaterThanOrEqualTo(tc.input)
			if err == nil {
				t.Errorf("want error, got nil")
			}
		})
	}
}

func TestNginxNewVersionHandlesRawString(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name  string
		input string
		want  Version
	}{
		{
			name:  "empty string",
			input: "",
			want:  Version{Raw: ""},
		},
		{
			name:  "invalid nginx string",
			input: "nginx",
			want:  Version{Raw: "nginx"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := NewVersion(tc.input)
			if !cmp.Equal(tc.want, got) {
				t.Error(cmp.Diff(tc.want, got))
			}
		})
	}
}

func TestExtractAgentVersionValues(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name  string
		input string
		major int
		minor int
		patch int
		err   bool
	}{
		{
			name:  "empty string",
			input: "",
			major: 0,
			minor: 0,
			patch: 0,
			err:   true,
		},
		{
			name:  "v2 semver",
			input: "v2.3.0",
			major: 2,
			minor: 3,
			patch: 0,
			err:   false,
		},
		{
			name:  "v2 semver",
			input: "v2.40.15",
			major: 2,
			minor: 40,
			patch: 15,
			err:   false,
		},
		{
			name:  "v3 semver",
			input: "v3.0.0-hash",
			major: 3,
			minor: 0,
			patch: 0,
			err:   false,
		},
		{
			name:  "v3 major only",
			input: "v3",
			major: 3,
			minor: 0,
			patch: 0,
			err:   true,
		},
		{
			name:  "v3 major & minor only",
			input: "v3.2",
			major: 3,
			minor: 2,
			patch: 0,
			err:   true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			major, minor, patch, err := extractAgentVersionValues(tc.input)
			if err != nil && !tc.err {
				t.Errorf("unexpected error: %v", err)
			}
			if !cmp.Equal(tc.major, major) {
				t.Errorf("wanted %d, got %d", tc.major, major)
			}
			if !cmp.Equal(tc.minor, minor) {
				t.Errorf("wanted %d, got %d", tc.minor, minor)
			}
			if !cmp.Equal(tc.patch, patch) {
				t.Errorf("wanted %d, got %d", tc.patch, patch)
			}
		})
	}
}

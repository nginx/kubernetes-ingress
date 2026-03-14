package nsutils

import "testing"

func TestHasNamespace(t *testing.T) {
	tests := []struct {
		resource      string
		withNamespace bool
		description   string
	}{
		{
			resource:      "my-resource",
			withNamespace: false,
			description:   "resource name without namespace",
		},
		{
			resource:      "custom/my-resource",
			withNamespace: true,
			description:   "resource name with namespace",
		},
		{
			resource:      "default/my-resource",
			withNamespace: true,
			description:   "resource name with default namespace",
		},
		{
			resource:      "",
			withNamespace: false,
			description:   "empty resource name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			if r := HasNamespace(tt.resource); r != tt.withNamespace {
				t.Errorf("HasNamespace() = %v, want %v", r, tt.withNamespace)
			}
		})
	}
}

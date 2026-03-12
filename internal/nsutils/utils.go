package nsutils

import (
	"strings"
)

// HasNamespace checks if the given string is a resource reference with a namespace (i.e., has a '/' character).
func HasNamespace(s string) bool {
	return strings.Contains(s, "/")
}

// FormatResourceReference formats a resource reference by concatenating the namespace and name with a '/' character.
func FormatResourceReference(namespace, name string) string {
	return namespace + "/" + name
}

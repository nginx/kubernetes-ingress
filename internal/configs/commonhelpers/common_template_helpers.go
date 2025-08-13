// Package commonhelpers contains template helpers used in v1 and v2
package commonhelpers

import (
	"strings"
)

// MakeSecretPath will return the path to the secret with the base secrets
// path replaced with the given variable
func MakeSecretPath(path, defaultPath, variable string, useVariable bool) string {
	if useVariable {
		return strings.Replace(path, defaultPath, variable, 1)
	}
	return path
}

// MakeOnOffFromBool will return a string on | off from a boolean pointer
func MakeOnOffFromBool(b *bool) string {
	if b == nil || !*b {
		return "off"
	}

	return "on"
}

// BoolToPointerBool turns a bool into a pointer bool
func BoolToPointerBool(b bool) *bool {
	return &b
}

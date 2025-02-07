// Package commonhelpers contains template helpers used in v1 and v2
package commonhelpers

import (
	"strings"

	"golang.org/x/exp/rand"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"

// RandStringBytes generates a pseudo-random string of length `n`.
func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

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

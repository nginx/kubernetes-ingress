package configs

import "strings"

// escapeNginxString safely escapes string values for nginx configuration.
func escapeNginxString(value string) string {
	// Escape quotes and backslashes for nginx string safety.
	result := strings.ReplaceAll(value, "\\", "\\\\")
	result = strings.ReplaceAll(result, "\"", "\\\"")
	return result
}

// Package commonhelpers contains template helpers used in v1 and v2
package commonhelpers

import (
	"fmt"
	"strconv"
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

// MakeProxyBuffers generates nginx proxy buffer configuration with safety validations
func MakeProxyBuffers(proxyBuffers, proxyBufferSize, proxyBusyBufferSize string) string {
	var parts []string

	if proxyBufferSize != "" && proxyBuffers == "" {
		count := 4
		if proxyBusyBufferSize != "" {
			if minBuffers := int((ParseSize(proxyBusyBufferSize) + ParseSize(proxyBufferSize)) / ParseSize(proxyBufferSize)); minBuffers > count {
				count = minBuffers
			}
		}
		proxyBuffers = fmt.Sprintf("%d %s", count, proxyBufferSize)
		parts = append(parts, fmt.Sprintf("proxy_buffer_size %s", proxyBufferSize), fmt.Sprintf("proxy_buffers %s", proxyBuffers))
	} else if proxyBuffers != "" {
		originalProxyBuffers := proxyBuffers
		proxyBuffers, proxyBufferSize = applySafetyCorrections(proxyBuffers, proxyBufferSize)
		parts = append(parts, fmt.Sprintf("proxy_buffers %s", proxyBuffers))
		if proxyBufferSize != "" {
			parts = append(parts, fmt.Sprintf("proxy_buffer_size %s", proxyBufferSize))
		}

		// If proxy_buffers was corrected and no explicit busy buffer size is set,
		// we need to set a safe default to prevent nginx conflicts
		if proxyBusyBufferSize == "" && originalProxyBuffers != proxyBuffers {
			proxyBusyBufferSize = calculateSafeBusyBufferSize(proxyBuffers)
		}
	}

	// Add busy buffers with validation
	// proxy_busy_buffers_size must be equal to or greater than the maximum of the value of proxy_buffer_size and one of the poxy_buffers
	if proxyBusyBufferSize != "" {
		validatedSize := proxyBusyBufferSize
		if len(parts) > 0 && proxyBuffers != "" && proxyBufferSize != "" {
			validatedSize = validateBusyBufferSize(proxyBuffers, proxyBufferSize, proxyBusyBufferSize)
		}
		parts = append(parts, fmt.Sprintf("proxy_busy_buffers_size %s", validatedSize))
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ";\n\t\t") + ";"
}

// calculateSafeBusyBufferSize calculates a safe default busy buffer size when proxy_buffers was corrected
func calculateSafeBusyBufferSize(proxyBuffers string) string {
	fields := strings.Fields(proxyBuffers)
	if len(fields) >= 2 {
		count, _ := strconv.Atoi(fields[0])
		individualSize := ParseSize(fields[1])
		// Set busy buffer size to a safe value: max allowed is (count * size - size)
		safeSize := int64(count-1) * individualSize
		if safeSize > 0 {
			return FormatSize(safeSize)
		}
	}
	return ""
}

// applySafetyCorrections applies safety corrections to proxy buffer configuration
func applySafetyCorrections(proxyBuffers, proxyBufferSize string) (string, string) {
	fields := strings.Fields(strings.TrimSpace(proxyBuffers))
	if len(fields) < 2 {
		return proxyBuffers, proxyBufferSize
	}

	count, _ := strconv.Atoi(fields[0])
	if count < 2 {
		count = 2
		proxyBuffers = fmt.Sprintf("2 %s", fields[1])
	}
	if proxyBufferSize == "" {
		proxyBufferSize = fields[1]
	} else if ParseSize(proxyBufferSize) > ParseSize(fields[1]) {
		proxyBuffers = fmt.Sprintf("%d %s", count, proxyBufferSize)
	}

	return proxyBuffers, proxyBufferSize
}

// validateBusyBufferSize ensures proxy_busy_buffers_size meets nginx requirements
func validateBusyBufferSize(proxyBuffers, proxyBufferSize, proxyBusyBufferSize string) string {
	if proxyBusyBufferSize == "" {
		return ""
	}

	fields := strings.Fields(proxyBuffers)
	if len(fields) < 2 {
		return proxyBusyBufferSize
	}

	count, _ := strconv.Atoi(fields[0])
	busySize, bufferSize, individualSize := ParseSize(proxyBusyBufferSize), ParseSize(proxyBufferSize), ParseSize(fields[1])

	minSize := max(bufferSize, individualSize)
	maxSize := int64(count)*individualSize - individualSize

	if busySize < minSize {
		return FormatSize(minSize)
	}
	if maxSize > 0 && busySize >= maxSize {
		return FormatSize(maxSize)
	}
	return proxyBusyBufferSize
}

// ParseSize converts size strings to bytes
func ParseSize(sizeStr string) int64 {
	sizeStr = strings.ToLower(strings.TrimSpace(sizeStr))
	if sizeStr == "" {
		return 0
	}

	// Handle plain numbers
	if num, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
		return num
	}

	// Parse with units
	if len(sizeStr) < 2 {
		return 0
	}

	unit := sizeStr[len(sizeStr)-1]
	if num, err := strconv.ParseInt(sizeStr[:len(sizeStr)-1], 10, 64); err == nil {
		switch unit {
		case 'k':
			return num << 10
		case 'm':
			return num << 20
		case 'g':
			return num << 30
		}
	}
	return 0
}

// FormatSize converts bytes to appropriate size string
func FormatSize(bytes int64) string {
	for _, unit := range []struct {
		size   int64
		suffix string
	}{{1 << 30, "g"}, {1 << 20, "m"}, {1 << 10, "k"}} {
		if bytes >= unit.size {
			return fmt.Sprintf("%d%s", bytes/unit.size, unit.suffix)
		}
	}
	return fmt.Sprintf("%d", bytes)
}

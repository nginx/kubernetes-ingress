// Package commonhelpers contains template helpers used in v1 and v2
package commonhelpers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nginx/kubernetes-ingress/internal/validation"
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
func MakeProxyBuffers(proxyBuffers, proxyBufferSize, proxyBusyBuffersSize string) string {
	var parts []string

	// Validate and normalize size inputs to prevent invalid nginx configs
	proxyBufferSize = validation.NormalizeSize(proxyBufferSize)
	proxyBusyBuffersSize = validation.NormalizeSize(proxyBusyBuffersSize)

	if proxyBufferSize != "" && proxyBuffers == "" {
		count := 4
		if proxyBusyBuffersSize != "" {
			bufferSizeBytes := validation.ParseSize(proxyBufferSize)
			if bufferSizeBytes > 0 { // Prevent division by zero
				if minBuffers := int((validation.ParseSize(proxyBusyBuffersSize) + bufferSizeBytes) / bufferSizeBytes); minBuffers > count {
					count = minBuffers
				}
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
		if proxyBusyBuffersSize == "" && originalProxyBuffers != proxyBuffers {
			proxyBusyBuffersSize = calculateSafeBusyBufferSize(proxyBuffers)
		}
	}

	// Add busy buffers with validation
	if proxyBusyBuffersSize != "" {
		validatedSize := proxyBusyBuffersSize
		if len(parts) > 0 && proxyBuffers != "" && proxyBufferSize != "" {
			validatedSize = validateBusyBufferSize(proxyBuffers, proxyBufferSize, proxyBusyBuffersSize)
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
		individualSize := validation.ParseSize(fields[1])
		// Set busy buffer size to a safe value: max allowed is (count * size - size)
		safeSize := int64(count-1) * individualSize
		if safeSize > 0 {
			return validation.FormatSize(safeSize)
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
	} else if validation.ParseSize(proxyBufferSize) > validation.ParseSize(fields[1]) {
		// Don't allow individual buffers larger than 1m to prevent nginx issues
		bufferSizeBytes := validation.ParseSize(proxyBufferSize)
		if bufferSizeBytes > (1 << 20) { // 1MB limit
			return proxyBuffers, proxyBufferSize
		}
		proxyBuffers = fmt.Sprintf("%d %s", count, proxyBufferSize)
	}

	return proxyBuffers, proxyBufferSize
}

// validateBusyBufferSize ensures proxy_busy_buffers_size meets nginx requirements
// and gives precedence to proxy_buffer_size when determining the minimum
func validateBusyBufferSize(proxyBuffers, proxyBufferSize, proxyBusyBuffersSize string) string {
	if proxyBusyBuffersSize == "" {
		return ""
	}

	fields := strings.Fields(proxyBuffers)
	if len(fields) < 2 {
		return proxyBusyBuffersSize
	}

	count, _ := strconv.Atoi(fields[0])
	busySize, bufferSize, individualSize := validation.ParseSize(proxyBusyBuffersSize), validation.ParseSize(proxyBufferSize), validation.ParseSize(fields[1])

	// Give precedence to proxy_buffer_size - if it's larger, use it as the minimum
	minSize := max(bufferSize, individualSize)
	maxSize := int64(count)*individualSize - individualSize

	// If proxy_buffer_size is significantly larger, prefer to align busy buffer with it
	if bufferSize > individualSize && busySize < bufferSize && bufferSize <= maxSize {
		return validation.FormatSize(bufferSize)
	}
	if busySize < minSize {
		return validation.FormatSize(minSize)
	}
	if maxSize > 0 && busySize >= maxSize {
		return validation.FormatSize(maxSize)
	}
	return proxyBusyBuffersSize
}

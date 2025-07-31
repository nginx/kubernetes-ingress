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

// MakeProxyBuffers generates nginx proxy buffer configuration with validation
func MakeProxyBuffers(proxyBuffers, proxyBufferSize, proxyBusyBuffersSize string) string {
	var parts []string

	proxyBufferSize = validation.NormalizeBufferSize(proxyBufferSize)
	proxyBusyBuffersSize = validation.NormalizeBufferSize(proxyBusyBuffersSize)

	proxyBufferSize, _ = capBufferLimits(proxyBufferSize, 0)

	if proxyBufferSize != "" && proxyBuffers == "" {
		count := 4
		if proxyBusyBuffersSize != "" {
			bufferSizeBytes := validation.ParseSize(proxyBufferSize)
			if bufferSizeBytes > 0 {
				minBuffers := int((validation.ParseSize(proxyBusyBuffersSize) + bufferSizeBytes) / bufferSizeBytes)
				if minBuffers > count {
					count = minBuffers
				}
			}
		}
		proxyBuffers = fmt.Sprintf("%d %s", count, proxyBufferSize)
		parts = append(parts, fmt.Sprintf("proxy_buffer_size %s", proxyBufferSize), fmt.Sprintf("proxy_buffers %s", proxyBuffers))
	} else if proxyBuffers != "" {
		originalBuffers := proxyBuffers
		proxyBuffers, proxyBufferSize = correctBufferConfig(proxyBuffers, proxyBufferSize)
		parts = append(parts, fmt.Sprintf("proxy_buffers %s", proxyBuffers))
		if proxyBufferSize != "" {
			parts = append(parts, fmt.Sprintf("proxy_buffer_size %s", proxyBufferSize))
		}

		if proxyBusyBuffersSize == "" && originalBuffers != proxyBuffers {
			proxyBusyBuffersSize = defaultBusyBufferSize(proxyBuffers)
		}
	}

	parts = addBusyBufferSizeConfig(parts, proxyBuffers, proxyBufferSize, proxyBusyBuffersSize)

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ";\n\t\t") + ";"
}

func defaultBusyBufferSize(proxyBuffers string) string {
	fields := strings.Fields(proxyBuffers)
	if len(fields) >= 2 {
		// Return the individual buffer size as the default busy buffer size
		return fields[1]
	}
	return ""
}

// correctBufferConfig applies corrections to proxy buffer configuration
func correctBufferConfig(proxyBuffers, proxyBufferSize string) (string, string) {
	fields := strings.Fields(strings.TrimSpace(proxyBuffers))
	if len(fields) < 2 {
		return proxyBuffers, proxyBufferSize
	}

	count, _ := strconv.Atoi(fields[0])

	// Capping buffer count and individual buffer size
	fields[1], count = capBufferLimits(fields[1], count)
	proxyBuffers = fmt.Sprintf("%d %s", count, fields[1])

	if proxyBufferSize == "" {
		proxyBufferSize = fields[1]
	} else if validation.ParseSize(proxyBufferSize) > validation.ParseSize(fields[1]) {
		bufferSizeBytes := validation.ParseSize(proxyBufferSize)
		individualSizeBytes := validation.ParseSize(fields[1])

		maxPossibleBusySize := int64(count)*individualSizeBytes - individualSizeBytes
		if bufferSizeBytes >= maxPossibleBusySize {
			cappedSize := maxPossibleBusySize / 2
			if cappedSize < individualSizeBytes {
				cappedSize = individualSizeBytes
			}
			proxyBufferSize = validation.FormatSize(cappedSize)
		} else if bufferSizeBytes <= (1 << 20) { // 1MB limit for changing buffer sizes
			proxyBuffers = fmt.Sprintf("%d %s", count, proxyBufferSize)
		}
	}

	return proxyBuffers, proxyBufferSize
}

// capBufferLimits applies limits to buffer configurations to prevent issues
func capBufferLimits(bufferSize string, bufferCount int) (string, int) {
	const maxReasonableBufferSize = 1000 * 1024 * 1024 // 1000MB in bytes
	const maxReasonableBufferCount = 1024
	const minReasonableBufferCount = 2

	cappedSize := bufferSize
	cappedCount := bufferCount

	// Cap buffer size
	if bufferSize != "" {
		bufferSizeBytes := validation.ParseSize(bufferSize)
		if bufferSizeBytes > maxReasonableBufferSize {
			cappedSize = validation.FormatSize(maxReasonableBufferSize)
		}
	}

	// Cap buffer count
	if bufferCount > maxReasonableBufferCount {
		cappedCount = maxReasonableBufferCount
	} else if bufferCount < minReasonableBufferCount {
		cappedCount = minReasonableBufferCount
	}

	return cappedSize, cappedCount
}

// addBusyBufferSizeConfig manages busy buffer size configuration and adds it to the parts slice
func addBusyBufferSizeConfig(parts []string, proxyBuffers, proxyBufferSize, proxyBusyBuffersSize string) []string {
	// Always ensure we have a valid busy buffer size when we have any buffer configuration
	if len(parts) > 0 && proxyBuffers != "" {
		if proxyBusyBuffersSize == "" {
			proxyBusyBuffersSize = processBusyBufferSize(proxyBuffers, proxyBufferSize, "")
		} else {
			proxyBusyBuffersSize = processBusyBufferSize(proxyBuffers, proxyBufferSize, proxyBusyBuffersSize)
		}

		if proxyBusyBuffersSize != "" {
			parts = append(parts, fmt.Sprintf("proxy_busy_buffers_size %s", proxyBusyBuffersSize))
		}
	} else if proxyBusyBuffersSize != "" {
		// Handle case where only busy buffer size is provided without buffer configuration
		parts = append(parts, fmt.Sprintf("proxy_busy_buffers_size %s", proxyBusyBuffersSize))
	}

	return parts
}

// If proxyBusyBuffersSize is empty, it calculates a safe value
// If proxyBusyBuffersSize is provided, it validates and corrects it
func processBusyBufferSize(proxyBuffers, proxyBufferSize, proxyBusyBuffersSize string) string {
	fields := strings.Fields(proxyBuffers)
	if len(fields) < 2 {
		if proxyBusyBuffersSize == "" {
			return ""
		}
		return proxyBusyBuffersSize
	}

	count, _ := strconv.Atoi(fields[0])
	individualSize := validation.ParseSize(fields[1])

	if proxyBusyBuffersSize == "" {
		proxyBufferSize, _ = capBufferLimits(proxyBufferSize, 0)
	}
	bufferSize := validation.ParseSize(proxyBufferSize)

	maxSize := int64(count)*individualSize - individualSize
	minSize := individualSize
	if bufferSize > minSize {
		minSize = bufferSize
	}

	if maxSize <= 0 || minSize >= maxSize {
		safeSize := individualSize
		if maxSize > individualSize {
			safeSize = maxSize - 1024 // Leave 1k margin for safety
			if safeSize < individualSize {
				safeSize = individualSize
			}
		}
		return validation.FormatSize(safeSize)
	}

	// If no busy buffer size provided, calculate a safe one
	if proxyBusyBuffersSize == "" {
		// proxy_buffer_size + (2 * individual_buffer_size)
		recommendedSize := minSize + 2*individualSize
		if recommendedSize >= maxSize {
			return validation.FormatSize(minSize)
		}
		return validation.FormatSize(recommendedSize)
	}

	busySize := validation.ParseSize(proxyBusyBuffersSize)

	if busySize >= maxSize {
		return validation.FormatSize(maxSize)
	}

	if busySize < minSize {
		return validation.FormatSize(minSize)
	}

	return proxyBusyBuffersSize
}

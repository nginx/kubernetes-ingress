package validation

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

var (
	maxNGINXBufferCount = uint64(1024)
	minNGINXBufferCount = uint64(2)
)

// SizeUnit moves validation and normalisation of incoming string into a custom
// type so we can pass that one around. Source for the size unit is from nginx
// documentation. @see https://nginx.org/en/docs/syntax.html
//
// This is also used for offsets like buffer sizes with badUnit.
type SizeUnit uint64

// SizeUnit represents the size unit used in NGINX configuration. It can be
// one of KB, MB, GB, or BadUnit for invalid sizes.
const (
	BadUnit SizeUnit = 1 << (10 * iota)
	SizeKB
	SizeMB
	SizeGB
)

// String returns the string representation of the SizeUnit in lowercase.
func (s SizeUnit) String() string {
	switch s {
	case SizeKB:
		return "k"
	case SizeMB:
		return "m"
	case SizeGB:
		return "g"
	default:
		return ""
	}
}

// NewSizeWithUnit creates a normalized string from a string representation.
// If normalize is false, returns the original string after basic validation.
func NewSizeWithUnit(sizeStr string, normalize bool) (string, error) {
	sizeStr = strings.ToLower(strings.TrimSpace(sizeStr))
	if sizeStr == "" {
		return "", nil
	}

	var unit SizeUnit
	var numStr string
	lastChar := sizeStr[len(sizeStr)-1]

	switch lastChar {
	case 'k':
		unit = SizeKB
		numStr = sizeStr[:len(sizeStr)-1]
	case 'm':
		unit = SizeMB
		numStr = sizeStr[:len(sizeStr)-1]
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		unit = SizeMB    // Default to MB if no unit is specified
		numStr = sizeStr // If the last character is a digit, treat the whole string as a number
	default:
		// Invalid units like 'g', 'x' should be replaced with 'm'
		unit = SizeMB
		numStr = sizeStr[:len(sizeStr)-1]
	}

	num, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil || num < 1 {
		return "", fmt.Errorf("invalid size value, must be an integer larger than 0: %s", sizeStr)
	}

	// If normalize is false, return the original string after validation
	if !normalize {
		return sizeStr, nil
	}

	// Return the normalized string representation
	return fmt.Sprintf("%d%s", num, unit), nil
}

// newNumberSizeConfig creates a normalized string from a string representation.
// If normalize is false, returns the original string after basic validation.
func newNumberSizeConfig(sizeStr string, normalize bool) (string, error) {
	sizeStr = strings.ToLower(strings.TrimSpace(sizeStr))
	if sizeStr == "" {
		return "", nil
	}

	parts := strings.Fields(sizeStr)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid size format, expected '<number> <size>', got: %s", sizeStr)
	}

	num, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid number value, could not parse into unsigned integer: %s", parts[0])
	}

	sizeStr2, err := NewSizeWithUnit(parts[1], normalize)
	if err != nil {
		return "", fmt.Errorf("could not parse size with unit: %s", parts[1])
	}

	// If normalize is false, return the original string after validation
	if !normalize {
		return sizeStr, nil
	}

	return fmt.Sprintf("%d %s", num, sizeStr2), nil
}

// Helper function to parse size string to bytes for comparison
func parseSizeToBytes(sizeStr string) uint64 {
	if sizeStr == "" {
		return 0
	}
	sizeStr = strings.ToLower(strings.TrimSpace(sizeStr))
	if len(sizeStr) == 0 {
		return 0
	}

	lastChar := sizeStr[len(sizeStr)-1]
	numStr := sizeStr
	multiplier := uint64(1024 * 1024) // Default to MB

	switch lastChar {
	case 'k':
		multiplier = 1024
		numStr = sizeStr[:len(sizeStr)-1]
	case 'm':
		multiplier = 1024 * 1024
		numStr = sizeStr[:len(sizeStr)-1]
	case 'g':
		multiplier = 1024 * 1024 * 1024
		numStr = sizeStr[:len(sizeStr)-1]
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		multiplier = 1024 * 1024 // Default to MB if no unit
	}

	if num, err := strconv.ParseUint(numStr, 10, 64); err == nil {
		return num * multiplier
	}
	return 0
}

// Helper function to convert bytes back to size string
func bytesToSizeString(bytes uint64) string {
	if bytes == 0 {
		return "0k"
	}
	if bytes%(1024*1024*1024) == 0 {
		return fmt.Sprintf("%dg", bytes/(1024*1024*1024))
	}
	if bytes%(1024*1024) == 0 {
		return fmt.Sprintf("%dm", bytes/(1024*1024))
	}
	if bytes%1024 == 0 {
		return fmt.Sprintf("%dk", bytes/1024)
	}
	return fmt.Sprintf("%dk", (bytes+1023)/1024) // Round up to nearest KB
}

// parseProxyBuffers extracts buffer number and size from proxy_buffers string
func parseProxyBuffers(proxyBuffers string) (uint64, uint64) {
	bufferNumber := uint64(8)           // default
	bufferSizeBytes := uint64(4 * 1024) // default 4k

	if proxyBuffers != "" {
		parts := strings.Fields(strings.TrimSpace(proxyBuffers))
		if len(parts) == 2 {
			if num, err := strconv.ParseUint(parts[0], 10, 64); err == nil {
				bufferNumber = num
				bufferSizeBytes = parseSizeToBytes(parts[1])
			}
		}
	}

	return bufferNumber, bufferSizeBytes
}

// validateBufferConstraints ensures buffer number is within valid range
func validateBufferConstraints(bufferNumber uint64) (uint64, []string) {
	var modifications []string

	if bufferNumber < minNGINXBufferCount {
		modifications = append(modifications, fmt.Sprintf("adjusted proxy_buffers number from %d to %d", bufferNumber, minNGINXBufferCount))
		bufferNumber = minNGINXBufferCount
	}
	if bufferNumber > maxNGINXBufferCount {
		modifications = append(modifications, fmt.Sprintf("adjusted proxy_buffers number from %d to %d", bufferNumber, maxNGINXBufferCount))
		bufferNumber = maxNGINXBufferCount
	}

	return bufferNumber, modifications
}

// parseBufferSizes extracts and validates buffer sizes from input strings
func parseBufferSizes(proxyBufferSize, proxyBusyBuffers string, defaultSize uint64) (uint64, uint64) {
	var proxyBufferSizeBytes, proxyBusyBuffersBytes uint64

	if proxyBufferSize != "" {
		proxyBufferSizeBytes = parseSizeToBytes(proxyBufferSize)
	} else {
		proxyBufferSizeBytes = defaultSize
	}

	if proxyBusyBuffers != "" {
		proxyBusyBuffersBytes = parseSizeToBytes(proxyBusyBuffers)
	} else {
		proxyBusyBuffersBytes = defaultSize
	}

	return proxyBufferSizeBytes, proxyBusyBuffersBytes
}

// applyBufferSizeConstraints applies NGINX rules for buffer size relationships
func applyBufferSizeConstraints(proxyBufferSizeBytes, proxyBusyBuffersBytes, bufferSizeBytes, maxAllowedSize uint64) (uint64, uint64, []string) {
	var modifications []string

	// Apply rule 4: proxy_buffer_size must be <= (total_buffers - 1_buffer)
	if proxyBufferSizeBytes > maxAllowedSize {
		modifications = append(modifications, "adjusted proxy_buffer_size because it was too large for proxy_buffers")
		proxyBufferSizeBytes = maxAllowedSize
	}

	// Apply rule 3: proxy_busy_buffers_size must be <= (total_buffers - 1_buffer)
	if proxyBusyBuffersBytes > maxAllowedSize {
		modifications = append(modifications, "adjusted proxy_busy_buffers_size because it was too large")
		proxyBusyBuffersBytes = maxAllowedSize
	}

	// Apply rule 2: proxy_busy_buffers_size must be >= max(proxy_buffer_size, buffer_size)
	minBusySize := bufferSizeBytes
	if proxyBufferSizeBytes > bufferSizeBytes {
		minBusySize = proxyBufferSizeBytes
	}

	if proxyBusyBuffersBytes < minBusySize {
		proxyBusyBuffersBytes = minBusySize
	}

	return proxyBufferSizeBytes, proxyBusyBuffersBytes, modifications
}

// BalanceProxyValues normalises and validates the values for the proxy buffer
// configuration options and their defaults:
// * proxy_buffers           8 4k|8k (one memory page size)
// * proxy_buffer_size         4k|8k (one memory page size)
// * proxy_busy_buffers_size   8k|16k (two memory page sizes)
//
// These requirements are based on the NGINX source code. The rules and their
// priorities are:
//
//  1. there must be at least 2 proxy buffers
//  2. proxy_busy_buffers_size must be equal to or greater than the max of
//     proxy_buffer_size and one of proxy_buffers
//  3. proxy_busy_buffers_size must be less than or equal to the size of all
//     proxy_buffers minus one proxy_buffer
//
// The above also means that:
//  4. proxy_buffer_size must be less than or equal to the size of all
//     proxy_buffers minus one proxy_buffer
//
// This function now works with string inputs and returns string outputs.
// Proxy buffer format is always "number size" separated by a space.
func BalanceProxyValues(proxyBuffers, proxyBufferSize, proxyBusyBuffers string, autoadjust bool) (string, string, string, []string, error) {
	if !autoadjust {
		return proxyBuffers, proxyBufferSize, proxyBusyBuffers, []string{"auto adjust is turned off, no changes have been made to the proxy values"}, nil
	}

	modifications := make([]string, 0)

	if proxyBuffers == "" && proxyBufferSize == "" && proxyBusyBuffers == "" {
		return proxyBuffers, proxyBufferSize, proxyBusyBuffers, modifications, nil
	}

	// Parse proxy buffers or use defaults
	bufferNumber, bufferSizeBytes := parseProxyBuffers(proxyBuffers)

	// Handle special case where proxy_buffers is not set
	if proxyBuffers == "" && (proxyBufferSize != "" || proxyBusyBuffers != "") {
		bufferNumber = minNGINXBufferCount
		bufferSizeBytes = 4 * 1024 // default 4k
	}

	// Validate buffer number constraints
	bufferNumber, bufferConstraintMods := validateBufferConstraints(bufferNumber)
	modifications = append(modifications, bufferConstraintMods...)

	// Parse buffer sizes
	proxyBufferSizeBytes, proxyBusyBuffersBytes := parseBufferSizes(proxyBufferSize, proxyBusyBuffers, bufferSizeBytes)

	// Calculate constraints and apply rules
	totalBufferSize := bufferSizeBytes * bufferNumber
	maxAllowedSize := totalBufferSize - bufferSizeBytes

	proxyBufferSizeBytes, proxyBusyBuffersBytes, constraintMods := applyBufferSizeConstraints(
		proxyBufferSizeBytes, proxyBusyBuffersBytes, bufferSizeBytes, maxAllowedSize)
	modifications = append(modifications, constraintMods...)

	// Convert results back to strings
	bufferSizeStr := bytesToSizeString(bufferSizeBytes)
	proxyBufferSizeStr := bytesToSizeString(proxyBufferSizeBytes)
	proxyBusyBuffersStr := bytesToSizeString(proxyBusyBuffersBytes)

	resultProxyBuffers := fmt.Sprintf("%d %s", bufferNumber, bufferSizeStr)
	return resultProxyBuffers, proxyBufferSizeStr, proxyBusyBuffersStr, modifications, nil
}

// BalanceProxiesForUpstreams balances the proxy buffer settings for an Upstream
// struct. The only reason for this function is to convert between the data type
// in the Upstream struct and the data types used in the balancing logic and
// back.
func BalanceProxiesForUpstreams(in *conf_v1.Upstream, autoadjust bool) error {
	if in.ProxyBuffers == nil {
		return nil
	}

	// When autoadjust is disabled, don't change anything - leave it broken!
	if !autoadjust {
		return nil
	}

	pb, err := newNumberSizeConfig(fmt.Sprintf("%d %s", in.ProxyBuffers.Number, in.ProxyBuffers.Size), autoadjust)
	if err != nil {
		// if there's an error, set it to default `8 4k`
		pb = "8 4k"
	}

	pbs, err := NewSizeWithUnit(in.ProxyBufferSize, autoadjust)
	if err != nil {
		// if there's an error, set it to default `4k`
		pbs = "4k"
	}

	pbbs, err := NewSizeWithUnit(in.ProxyBusyBuffersSize, autoadjust)
	if err != nil {
		// if there's an error, set it to default `4k`
		pbbs = "4k"
	}

	balancedPB, balancedPBS, balancedPBBS, _, err := BalanceProxyValues(pb, pbs, pbbs, autoadjust)
	if err != nil {
		return fmt.Errorf("error balancing proxy values: %w", err)
	}

	// Parse the balanced proxy buffers string back to struct
	if balancedPB != "" {
		parts := strings.Fields(balancedPB)
		if len(parts) == 2 {
			if num, err := strconv.Atoi(parts[0]); err == nil {
				if num > math.MaxInt32 {
					num = math.MaxInt32
				}
				in.ProxyBuffers.Number = num
				in.ProxyBuffers.Size = parts[1]
			}
		}
	}

	in.ProxyBufferSize = balancedPBS
	in.ProxyBusyBuffersSize = balancedPBBS

	return nil
}

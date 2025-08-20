package validation

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
)

const (
	// DefaultPageSize is one page size to be used for default values in NGINX.
	// 4k page size is fairly
	DefaultPageSize = "4k"
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

// SizeWithUnit represents a size value with a unit. It's used for handling any
// NGINX configuration values that have a size type. All the size values need to
// be non-negative, hence the use of uint64 for the size.
//
// Example: "4k" represents 4 kilobytes.
type SizeWithUnit struct {
	Size uint64
	Unit SizeUnit
}

func (s SizeWithUnit) String() string {
	if s.Size == 0 {
		return ""
	}

	return fmt.Sprintf("%d%s", s.Size, s.Unit)
}

// SizeBytes returns the size in bytes based on the size and unit to make it
// easier to compare sizes and use them in calculations.
func (s SizeWithUnit) SizeBytes() uint64 {
	return s.Size * uint64(s.Unit)
}

// NewSizeWithUnit creates a SizeWithUnit from a string representation.
func NewSizeWithUnit(sizeStr string) (SizeWithUnit, error) {
	sizeStr = strings.ToLower(strings.TrimSpace(sizeStr))
	if sizeStr == "" {
		return SizeWithUnit{}, nil
	}

	var unit SizeUnit
	lastChar := sizeStr[len(sizeStr)-1]
	numStr := sizeStr[:len(sizeStr)-1]

	switch lastChar {
	case 'k':
		unit = SizeKB
	case 'm':
		unit = SizeMB
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		unit = SizeMB    // Default to MB if no unit is specified
		numStr = sizeStr // If the last character is a digit, treat the whole string as a number
	default:
		unit = SizeMB
	}

	num, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil || num < 1 {
		return SizeWithUnit{}, fmt.Errorf("invalid size value, must be an integer larger than 0: %s", sizeStr)
	}

	ret := SizeWithUnit{
		Size: num,
		Unit: unit,
	}

	if num > 1024 {
		ret.Size = 1024
	}

	return ret, nil
}

// NumberSizeConfig is a configuration that combines a number with a size. Used
// for directives that require a number and a size, like `proxy_buffer_size` or
// `client_max_body_size`.
//
// Example: "8 4k" represents 8 buffers of size 4 kilobytes.
type NumberSizeConfig struct {
	Number uint64
	Size   SizeWithUnit
}

func (nsc NumberSizeConfig) String() string {
	if nsc.Number == 0 || nsc.Size.Size == 0 {
		return ""
	}

	return fmt.Sprintf("%d %s", nsc.Number, nsc.Size)
}

// NewNumberSizeConfig creates a NumberSizeConfig from a string representation.
func NewNumberSizeConfig(sizeStr string) (NumberSizeConfig, error) {
	sizeStr = strings.ToLower(strings.TrimSpace(sizeStr))
	if sizeStr == "" {
		return NumberSizeConfig{}, nil
	}

	parts := strings.Fields(sizeStr)
	if len(parts) != 2 {
		return NumberSizeConfig{}, fmt.Errorf("invalid size format, expected '<number> <size>', got: %s", sizeStr)
	}

	num, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return NumberSizeConfig{}, fmt.Errorf("invalid number value, could not parse into unsigned integer: %s", parts[0])
	}

	if num < 2 {
		num = 2
	}

	size, err := NewSizeWithUnit(parts[1])
	if err != nil {
		return NumberSizeConfig{}, fmt.Errorf("could not parse size with unit: %s", parts[1])
	}

	return NumberSizeConfig{
		Number: num,
		Size:   size,
	}, nil
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
// This function returns new values and an error. The returns in order are:
// proxy_buffers, proxy_buffer_size, proxy_busy_buffers_size, error.
func BalanceProxyValues(proxyBuffers NumberSizeConfig, proxyBufferSize, proxyBusyBuffers SizeWithUnit, autoadjust bool) (NumberSizeConfig, SizeWithUnit, SizeWithUnit, []string, error) {
	if !autoadjust {
		return proxyBuffers, proxyBufferSize, proxyBusyBuffers, []string{"auto adjust is turned off, no changes have been made to the proxy values"}, nil
	}

	modifications := make([]string, 0)

	if proxyBuffers.String() == "" && proxyBufferSize.String() == "" && proxyBusyBuffers.String() == "" {
		return proxyBuffers, proxyBufferSize, proxyBusyBuffers, modifications, nil
	}

	// If any of them are defined, we'll align them.

	// Create a default size so we can use it in case the values are not set.
	defaultSize, err := NewSizeWithUnit(DefaultPageSize)
	if err != nil {
		return NumberSizeConfig{}, SizeWithUnit{}, SizeWithUnit{}, modifications, fmt.Errorf("could not create default size: %w", err)
	}

	// 1.a there must be at least 2 proxy buffers
	if proxyBuffers.Number < 2 {
		modifications = append(modifications, fmt.Sprintf("adjusted proxy_buffers size from %d to 2", proxyBuffers.Number))
		proxyBuffers.Number = 2
	}

	// 1.b there must be at most 1024 proxy buffers
	if proxyBuffers.Number > 1024 {
		modifications = append(modifications, fmt.Sprintf("adjusted proxy_buffers number from %d to 1024", proxyBuffers.Number))
		proxyBuffers.Number = 1024
	}

	// 2.a proxy_buffers size must be greater than 0
	if proxyBuffers.Size.Size == 0 || proxyBuffers.Size.Unit == BadUnit {
		modifications = append(modifications, fmt.Sprintf("proxy_buffers had an empty size, set it to [%s]", defaultSize))
		proxyBuffers.Size = defaultSize
	}

	maxProxyBusyBuffersSize := SizeWithUnit{
		Size: proxyBuffers.Size.Size * (proxyBuffers.Number - 1),
		Unit: proxyBuffers.Size.Unit,
	}

	// check if proxy_buffer_size is empty, and set it to one of proxy_buffers
	if proxyBufferSize.String() == "" {
		modifications = append(modifications, fmt.Sprintf("proxy_buffer_size was empty, set it to one of proxy_buffers: %s", proxyBuffers.Size))
		proxyBufferSize = proxyBuffers.Size
	}

	// 3. clamp proxy_buffer_size to be at most all of proxy_buffers minus one
	//    proxy buffer.
	//
	// This is needed in order to be conservative with memory (rather shrink
	// than grow so we don't run into resource issues), and also to avoid
	// undoing work in the last step when adjusting proxy_busy_buffers_size.
	if proxyBufferSize.SizeBytes() > (proxyBuffers.Size.SizeBytes() * (proxyBuffers.Number - 1)) {
		newSize := maxProxyBusyBuffersSize

		modifications = append(modifications, fmt.Sprintf("adjusted proxy_buffer_size from %s to %s because it was too big for proxy_buffers (%s)", proxyBufferSize, newSize, proxyBuffers))
		proxyBufferSize = newSize
	}

	// 4. grab the max of proxy_buffer_size and one of proxy_buffers
	var greaterSize SizeWithUnit
	if proxyBuffers.Size.SizeBytes() > proxyBufferSize.SizeBytes() {
		greaterSize = proxyBuffers.Size
	} else {
		greaterSize = proxyBufferSize
	}

	// 4. proxy_busy_buffers_size must be equal to or greater than the max of
	//    proxy_buffer_size and one of proxy_buffers (greater size from above)
	if proxyBusyBuffers.SizeBytes() < greaterSize.SizeBytes() {
		modifications = append(modifications, fmt.Sprintf("adjusted proxy_busy_buffers_size from %s to %s because it was too small", proxyBusyBuffers, greaterSize))
		proxyBusyBuffers = greaterSize
	}

	if proxyBusyBuffers.SizeBytes() > maxProxyBusyBuffersSize.SizeBytes() {
		modifications = append(modifications, fmt.Sprintf("adjusted proxy_busy_buffers_size from %s to %s because it was too large", proxyBusyBuffers, maxProxyBusyBuffersSize))

		proxyBusyBuffers = maxProxyBusyBuffersSize
	}

	return proxyBuffers, proxyBufferSize, proxyBusyBuffers, modifications, nil
}

// BalanceProxiesForUpstreams balances the proxy buffer settings for an Upstream
// struct. The only reason for this function is to convert between the data type
// in the Upstream struct and the data types used in the balancing logic and
// back.
func BalanceProxiesForUpstreams(in *conf_v1.Upstream, autoadjust bool) error {
	if in.ProxyBuffers == nil {
		return nil
	}

	pb, err := NewNumberSizeConfig(fmt.Sprintf("%d %s", in.ProxyBuffers.Number, in.ProxyBuffers.Size))
	if err != nil {
		// if there's an error, set it to default `8 4k`
		pb = NumberSizeConfig{
			Number: 8,
			Size: SizeWithUnit{
				Size: 4,
				Unit: SizeKB,
			},
		}
	}

	pbs, err := NewSizeWithUnit(in.ProxyBufferSize)
	if err != nil {
		// if there's an error, set it to default `4k`
		pbs = SizeWithUnit{
			Size: 4,
			Unit: SizeKB,
		}
	}

	pbbs, err := NewSizeWithUnit(in.ProxyBusyBuffersSize)
	if err != nil {
		// if there's an error, set it to default `4k`
		pbbs = SizeWithUnit{
			Size: 4,
			Unit: SizeKB,
		}
	}

	balancedPB, balancedPBS, balancedPBBS, _, err := BalanceProxyValues(pb, pbs, pbbs, autoadjust)
	if err != nil {
		return fmt.Errorf("error balancing proxy values: %w", err)
	}

	if balancedPB.Number > uint64(math.MaxInt) {
		balancedPB.Number = uint64(math.MaxInt)
	}

	in.ProxyBuffers = &conf_v1.UpstreamBuffers{
		Number: int(balancedPB.Number),
		Size:   balancedPB.Size.String(),
	}
	in.ProxyBufferSize = balancedPBS.String()
	in.ProxyBusyBuffersSize = balancedPBBS.String()

	return nil
}

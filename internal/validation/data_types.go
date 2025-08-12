package validation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SizeUnit moves validation and normalisation of incoming string into a custom
// type so we can pass that one around. Source for the size unit is from nginx
// documentation. @see https://nginx.org/en/docs/syntax.html
//
// This is also used for offsets like buffer sizes with badUnit.
type SizeUnit int

// SizeUnit represents the size unit used in NGINX configuration. It can be
// one of KB, MB, GB, or BadUnit for invalid sizes.
const (
	BadUnit SizeUnit = iota
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

// NewSizeWithUnit creates a SizeWithUnit from a string representation.
func NewSizeWithUnit(sizeStr string) (SizeWithUnit, error) {
	sizeStr = strings.ToLower(strings.TrimSpace(sizeStr))
	if sizeStr == "" {
		return SizeWithUnit{}, errors.New("size string is empty")
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
		// return SizeWithUnit{}, fmt.Errorf("invalid size unit, must be one of [k, m, g]: %s", sizeStr)
	}

	num, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil || num < 1 {
		return SizeWithUnit{}, fmt.Errorf("invalid size value, must be an integer above 0 and less than 18,446,744,073,709,551,615: %s", sizeStr)
	}

	return SizeWithUnit{
		Size: num,
		Unit: unit,
	}, nil
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
		return NumberSizeConfig{}, errors.New("size string is empty")
	}

	parts := strings.Fields(sizeStr)
	if len(parts) != 2 {
		return NumberSizeConfig{}, fmt.Errorf("invalid size format, expected '<number> <size>', got: %s", sizeStr)
	}

	num, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || num < 1 {
		return NumberSizeConfig{}, fmt.Errorf("invalid number value, must be an integer above 0: %s", parts[0])
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

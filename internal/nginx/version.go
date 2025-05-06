package nginx

import (
	"fmt"
	"regexp"
	"strconv"
)

// Version holds the parsed output from `nginx -v`.
type Version struct {
	Raw    string
	OSS    string
	IsPlus bool
	Plus   string
}

// NewVersion takes the output from `nginx -v` and explodes it into the `nginx.Version` struct.
func NewVersion(line string) Version {
	matches := ossre.FindStringSubmatch(line)
	plusmatches := plusre.FindStringSubmatch(line)
	nv := Version{
		Raw: line,
	}

	if len(plusmatches) > 0 {
		subNames := plusre.SubexpNames()
		nv.IsPlus = true
		for i, v := range plusmatches {
			switch subNames[i] {
			case "plus":
				nv.Plus = v
			case "version":
				nv.OSS = v
			}
		}
	}

	if len(matches) > 0 {
		for i, key := range ossre.SubexpNames() {
			val := matches[i]
			if key == "version" {
				nv.OSS = val
			}
		}
	}

	return nv
}

// String returns the raw Nginx version string from `nginx -v`.
func (v Version) String() string {
	return v.Raw
}

// Format returns a string representing Nginx version.
func (v Version) Format() string {
	if v.IsPlus {
		return fmt.Sprintf("%s-%s", v.OSS, v.Plus)
	}
	return v.OSS
}

// PlusGreaterThanOrEqualTo compares the supplied nginx-plus version string with the Version{} struct.
func (v Version) PlusGreaterThanOrEqualTo(target string) (bool, error) {
	r, p, err := extractPlusVersionValues(v.String())
	if err != nil {
		return false, err
	}
	tr, tp, err := extractPlusVersionValues(target)
	if err != nil {
		return false, err
	}

	return (r > tr || (r == tr && p >= tp)), nil
}

var rePlus = regexp.MustCompile(`-r(\d+)(?:-p(\d+))?`)

// extractPlusVersionValues
func extractPlusVersionValues(input string) (int, int, error) {
	var rValue, pValue int
	matches := rePlus.FindStringSubmatch(input)

	if len(matches) < 2 {
		return 0, 0, fmt.Errorf("no matches found in the input string")
	}

	rValue, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, fmt.Errorf("failed to convert rValue to integer: %w", err)
	}

	if len(matches) > 2 && len(matches[2]) > 0 {
		pValue, err = strconv.Atoi(matches[2])
		if err != nil {
			return 0, 0, fmt.Errorf("failed to convert pValue to integer: %w", err)
		}
	}

	return rValue, pValue, nil
}

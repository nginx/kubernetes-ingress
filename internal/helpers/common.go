package helpers

import (
	"fmt"
	"strings"
)

// ParseNamespaceName parses the string in the <namespace>/<name> format and returns the namespace and name.
// It returns an error in case the string does not follow the <namespace>/<name> format.
func ParseNamespaceName(value string) (ns string, name string, err error) {
	res := strings.Split(value, "/")
	if len(res) != 2 {
		return "", "", fmt.Errorf("%q must follow the format <namespace>/<name>", value)
	}
	return res[0], res[1], nil
}

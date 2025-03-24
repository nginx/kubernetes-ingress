package validation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	validDNSRegex      = regexp.MustCompile(`^(?:[A-Za-z0-9][A-Za-z0-9-]{1,62}\.)([A-Za-z0-9-]{1,63}\.)*[A-Za-z]{2,63}(?::\d{1,5})?$`)
	validIPRegex       = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(?::\d{1,5})?$`)
	validHostnameRegex = regexp.MustCompile(`^[a-z][A-Za-z0-9-]{1,62}(?::\d{1,5})?$`)
)

// ValidatePort ensure port matches rfc6335 https://www.rfc-editor.org/rfc/rfc6335.html
func ValidatePort(value int) error {
	if value > 65535 || value < 1 {
		return fmt.Errorf("error parsing port: %d not a valid port number", value)
	}
	return nil
}

// ValidateUnprivilegedPort ensure port is in the 1024-65535 range
func ValidateUnprivilegedPort(value int) error {
	if value > 65535 || value < 1023 {
		return fmt.Errorf("port outside of valid port range [1024 - 65535]: %d", value)
	}
	return nil
}

// ValidateHost ensures the host is a valid hostname/IP address or FQDN with an optional :port appended
func ValidateHost(host string) error {
	if host == "" {
		return fmt.Errorf("error parsing host: empty host")
	}

	if validIPRegex.MatchString(host) || validDNSRegex.MatchString(host) || validHostnameRegex.MatchString(host) {
		chunks := strings.Split(host, ":")
		if len(chunks) > 1 {
			port, err := strconv.Atoi(chunks[1])
			if err != nil {
				return err
			}
			err = ValidatePort(port)
			if err != nil {
				return fmt.Errorf("invalid port: %w", err)
			}
		}
		return nil
	}
	return fmt.Errorf("error parsing host: %s not a valid host", host)
}

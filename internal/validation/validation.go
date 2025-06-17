package validation

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const schemeSeparator = "://"

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

// URIValidationOption defines a functional option pattern for configuring the
// unexported uriValidator that gets used in ValidateURI.
type URIValidationOption func(u *uriValidator)

type uriValidator struct {
	allowedSchemes map[string]struct{}
	userAllowed    bool
	defaultScheme  string
}

// WithAllowedSchemes configures a URIValidator with allowed URI schemes. By
// default, http and https are the only schemes considered valid. This option
// allows changing the allowed schemes.
func WithAllowedSchemes(allowedSchemes ...string) URIValidationOption {
	return func(cfg *uriValidator) {
		schemes := make(map[string]struct{})
		for _, scheme := range allowedSchemes {
			schemes[scheme] = struct{}{}
		}

		cfg.allowedSchemes = schemes
	}
}

// WithUserAllowed configures a URIValidator with a flag for whether user
// information is allowed in the URI. Defaults to false. It is not recommended
// to pass user information in a URL as it's generally considered to be unsafe.
func WithUserAllowed(userAllowed bool) URIValidationOption {
	return func(cfg *uriValidator) {
		cfg.userAllowed = userAllowed
	}
}

// WithDefaultScheme configures a URIValidator with a default scheme that
// gets used if no scheme is present in the incoming URI. Defaults to "https".
func WithDefaultScheme(defaultScheme string) URIValidationOption {
	return func(cfg *uriValidator) {
		cfg.defaultScheme = defaultScheme
	}
}

// ValidateURI is a more robust extensible function to validate URIs. It
// improved on ValidateHost as that one wasn't able to handle addresses that
// start with a scheme.
func ValidateURI(uri string, options ...URIValidationOption) error {
	cfg := &uriValidator{
		allowedSchemes: map[string]struct{}{
			"http":  {},
			"https": {},
		},
		userAllowed:   false,
		defaultScheme: "https",
	}

	// Apply options to the configuration
	for _, option := range options {
		option(cfg)
	}

	// Check if the incoming uri is coming in with a scheme. At this point we'll
	// assume that any uri that does have a scheme will also have the :// in it.
	// If the uri does not have a scheme, let's add the default one so that
	// url.Parse can deal with situations like "localhost:80".
	if !strings.Contains(uri, schemeSeparator) {
		uri = cfg.defaultScheme + schemeSeparator + uri
	}

	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("error parsing uri: %w", err)
	}

	// Check whether the posted scheme is valid for the allowed list.
	if _, ok := cfg.allowedSchemes[parsed.Scheme]; !ok {
		return fmt.Errorf("scheme %s is not allowed", parsed.Scheme)
	}

	// Check whether the user:pass pattern is not allowed, but we have one.
	if !cfg.userAllowed && parsed.User != nil {
		return errors.New("user is not allowed")
	}

	// Check whether we're dealing with an IPV6 address.
	checkIPv6 := parsed.Host
	if strings.Contains(checkIPv6, "[") {
		checkIPv6 = parsed.Hostname()
	}

	if ip, err := netip.ParseAddr(checkIPv6); err == nil && !ip.Is4() {
		return fmt.Errorf("ipv6 addresses are not allowed")
	}

	// Check whether the ports posted are valid.
	if parsed.Port() != "" {
		// Turn the string port into an integer and check if it's in the correct
		// range. The net.url.Parse does not check whether the port is the allowed
		// value, only that it's syntactically correct. Similarly, the
		// net.SplitHostPort function also doesn't check whether the value is
		// correct.
		numericPort, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return fmt.Errorf("invalid port %s: %w", parsed.Port(), err)
		}

		if err = ValidatePort(numericPort); err != nil {
			return fmt.Errorf("invalid port %s: %w", parsed.Port(), err)
		}
	}

	// Check whether each part of the domain is not too long.
	// This should really be octets
	for _, part := range strings.Split(parsed.Hostname(), ".") {
		// turn each part into a byte array to get a length of octets.
		// max length of a subdomain is 63 octets per RFC 1035.
		if len([]byte(part)) > 63 {
			return fmt.Errorf("invalid hostname part %s, value must be between 1 and 63 octets", part)
		}
	}

	return nil
}

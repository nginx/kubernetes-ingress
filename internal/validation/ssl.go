package validation

import "regexp"

// SSLCiphersRegex validates OpenSSL cipher-list syntax while excluding NGINX directive delimiters.
// OpenSSL accepts colon, comma, or space separators, IANA names with underscores,
// and directives such as @SECLEVEL=2. At least one alphanumeric character is
// required, so a string made only of separators or operators (for example "   "
// or "!") is rejected: it carries no cipher token and produces an invalid
// ssl_ciphers value.
var SSLCiphersRegex = regexp.MustCompile(`^[A-Za-z0-9_:!@+.,= -]*[A-Za-z0-9][A-Za-z0-9_:!@+.,= -]*$`)

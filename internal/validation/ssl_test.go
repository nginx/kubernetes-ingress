package validation

import "testing"

// SSLCiphersRegex must accept real OpenSSL cipher lists and directives, and
// reject strings that match the allowed character class but carry no cipher
// token, such as separator- or operator-only input. Those render to an invalid
// ssl_ciphers value even though they contain no NGINX directive delimiter.
func TestSSLCiphersRegex(t *testing.T) {
	t.Parallel()

	accepted := []string{
		"HIGH:!aNULL:!MD5",
		"ECDHE-RSA-AES128-GCM-SHA256",
		"HIGH:!aNULL:!MD5:@SECLEVEL=2",
		"DEFAULT",
		"ALL:!EXPORT",
		"AES128-SHA AES256-SHA",
	}
	for _, value := range accepted {
		if !SSLCiphersRegex.MatchString(value) {
			t.Errorf("SSLCiphersRegex rejected %q, want accepted", value)
		}
	}

	rejected := []string{
		"",
		"   ",
		"!",
		":::",
		"@+.,= -",
		"value;inject",
	}
	for _, value := range rejected {
		if SSLCiphersRegex.MatchString(value) {
			t.Errorf("SSLCiphersRegex accepted %q, want rejected", value)
		}
	}
}

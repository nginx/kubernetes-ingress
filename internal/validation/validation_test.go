package validation

import (
	"strings"
	"testing"
)

func TestValidatePort_IsValidOnValidInput(t *testing.T) {
	t.Parallel()

	ports := []int{1, 65535}
	for _, p := range ports {
		if err := ValidatePort(p); err != nil {
			t.Error(err)
		}
	}
}

func TestValidatePort_ErrorsOnInvalidRange(t *testing.T) {
	t.Parallel()

	ports := []int{0, -1, 65536}
	for _, p := range ports {
		if err := ValidatePort(p); err == nil {
			t.Error("want error, got nil")
		}
	}
}

func TestValidateUnprivilegedPort_IsValidOnValidInput(t *testing.T) {
	t.Parallel()

	ports := []int{1024, 65535}
	for _, p := range ports {
		if err := ValidateUnprivilegedPort(p); err != nil {
			t.Error(err)
		}
	}
}

func TestValidateUnprivilegedPort_ErrorsOnInvalidRange(t *testing.T) {
	t.Parallel()

	ports := []int{0, -1, 80, 443, 65536}
	for _, p := range ports {
		if err := ValidateUnprivilegedPort(p); err == nil {
			t.Error("want error, got nil")
		}
	}
}

func TestValidateHost(t *testing.T) {
	t.Parallel()
	// Positive test cases
	posHosts := []string{
		"10.10.1.1:443",
		"10.10.1.1",
		"123.112.224.43:443",
		"172.120.3.222",
		"localhost:80",
		"localhost",
		"myhost:54321",
		"myhost",
		"my-host:54321",
		"my-host",
		"dns.test.svc.cluster.local:8443",
		"cluster.local:8443",
		"product.example.com",
		"product.example.com:443",
	}

	// Negative test cases item, expected error message
	negHosts := [][]string{
		{"NotValid", "not a valid host"},
		{"-cluster.local:514", "not a valid host"},
		{"10.10.1.1:99999", "not a valid port number"},
		{"333.333.333.333", "not a valid host"},
	}

	for _, tCase := range posHosts {
		err := ValidateHost(tCase)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	}

	for _, nTCase := range negHosts {
		err := ValidateHost(nTCase[0])
		if err == nil {
			t.Errorf("got no error expected error containing '%s'", nTCase[1])
		} else {
			if !strings.Contains(err.Error(), nTCase[1]) {
				t.Errorf("got '%v', expected: '%s'", err, nTCase[1])
			}
		}
	}
}

func TestValidateURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		options []URIValidationOption
		wantErr bool
	}{
		{
			name:    "simple uri with scheme",
			uri:     "https://localhost:8080",
			options: []URIValidationOption{},
			wantErr: false,
		},
		{
			name:    "simple uri without scheme",
			uri:     "localhost:8080",
			options: []URIValidationOption{},
			wantErr: false,
		},
		{
			name:    "uri with out of bounds port down",
			uri:     "http://localhost:0",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name:    "uri with out of bounds port up",
			uri:     "http://localhost:65536",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name:    "uri with bad port",
			uri:     "http://localhost:abc",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name: "uri with username and password and allowed",
			uri:  "http://user:password@localhost",
			options: []URIValidationOption{
				WithUserAllowed(true),
			},
			wantErr: false,
		},
		{
			name:    "uri with username and password and not allowed",
			uri:     "http://user:password@localhost",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name: "uri with http scheme but that's not allowed",
			uri:  "http://localhost",
			options: []URIValidationOption{
				WithAllowedSchemes("https"),
			},
			wantErr: true,
		},
		{
			name: "uri with https scheme but that's not allowed",
			uri:  "https://localhost",
			options: []URIValidationOption{
				WithAllowedSchemes("http"),
			},
			wantErr: true,
		},
		{
			name: "uri with no scheme, default set to https, not allowed",
			uri:  "localhost",
			options: []URIValidationOption{
				WithDefaultScheme("https"),
				WithAllowedSchemes("http"),
			},
			wantErr: true,
		},
		{
			name:    "uri that is an ipv6 address with a port",
			uri:     "https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:17000",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name:    "uri that is an ipv6 address without a port",
			uri:     "https://2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name:    "uri that is a short ipv6 without port without scheme",
			uri:     "fe80::1",
			options: []URIValidationOption{},
			wantErr: true,
		},
		{
			name:    "uri that is a short ipv6 with a port without scheme",
			uri:     "[fe80::1]:80",
			options: []URIValidationOption{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateURI(tt.uri, tt.options...); (err != nil) != tt.wantErr {
				t.Errorf("ValidateURI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSSLValidationRegexes(t *testing.T) {
	t.Parallel()

	t.Run("SSLCiphersRegex", func(t *testing.T) {
		validCiphers := []string{
			"HIGH:!aNULL:!MD5",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"DEFAULT:@SECLEVEL=2",
			"HIGH,MEDIUM",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"ALL",
		}
		for _, c := range validCiphers {
			if !SSLCiphersRegex.MatchString(c) {
				t.Errorf("expected valid cipher %q to match SSLCiphersRegex", c)
			}
		}
		invalidCiphers := []string{"HIGH;\nssl_ciphers bad", "HIGH\" injection"}
		for _, c := range invalidCiphers {
			if SSLCiphersRegex.MatchString(c) {
				t.Errorf("expected invalid cipher %q to fail SSLCiphersRegex", c)
			}
		}
	})
}

func TestValidateDirectiveValue(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"hash $request_uri consistent", "302 https://example.com/path", "302 https://${host}/", "200 don't", `200 "healthy; ready"`, "high=80 low=60"} {
		if err := ValidateDirectiveValue(value); err != nil {
			t.Errorf("ValidateDirectiveValue(%q) returned error: %v", value, err)
		}
	}

	for _, value := range []string{"", "value; return 200", "value # comment", "value\nreturn 200", "value {", "value }", `value "unterminated`, `404 x"; access_log off; # "`} {
		if err := ValidateDirectiveValue(value); err == nil {
			t.Errorf("ValidateDirectiveValue(%q) returned no error", value)
		}
	}
}

// TestValidateDirectiveValueBracedVariableMasking guards the masking of ${name}
// references. The mask must occupy the space of the variable it replaces: if a
// braced variable were removed instead, the character following it would move
// to the start of a token, and a double quote there would be treated as opening
// a quoted argument. NGINX only strips quotes at the start of a token, so it
// would keep reading the value as one unquoted token and terminate the
// directive at the first semicolon.
func TestValidateDirectiveValueBracedVariableMasking(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"${host}", `\\${host}`, "302 https://${host}/path", "hash ${remote_addr} consistent", "${scheme}://${host}"} {
		if err := ValidateDirectiveValue(value); err != nil {
			t.Errorf("ValidateDirectiveValue(%q) returned error: %v", value, err)
		}
	}

	// A quote directly after a braced variable is not at a token boundary, so
	// it cannot open a quoted argument and the semicolon still terminates the
	// directive.
	for _, value := range []string{
		`\${host}`,       // one backslash escapes '$'
		`\\\\\\\${host}`, // three escaped backslashes, then one escapes '$'
		`hash ${a}";x" consistent`,
		`${a}"; return 200; #"`,
		`${a}"; ip_hash; #"`,
		`302 ${host}"; access_log off; "`,
	} {
		if err := ValidateDirectiveValue(value); err == nil {
			t.Errorf("ValidateDirectiveValue(%q) returned no error; braced variable masking allowed a directive breakout", value)
		}
	}
}

func TestValidateSingleQuotedDirectiveValue(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"$remote_addr", `request: \'$request\'`, "status=$status; request=$request"} {
		if err := ValidateSingleQuotedDirectiveValue(value); err != nil {
			t.Errorf("ValidateSingleQuotedDirectiveValue(%q) returned error: %v", value, err)
		}
	}

	for _, value := range []string{"'$request'", "value\nreturn 200", `value\`} {
		if err := ValidateSingleQuotedDirectiveValue(value); err == nil {
			t.Errorf("ValidateSingleQuotedDirectiveValue(%q) returned no error", value)
		}
	}
}

func TestValidateQuotedDirectiveValue(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "NGINX Plus", `build-$hostname`, `quoted\"value`, "value; still quoted"} {
		if err := ValidateQuotedDirectiveValue(value); err != nil {
			t.Errorf("ValidateQuotedDirectiveValue(%q) returned error: %v", value, err)
		}
	}

	for _, value := range []string{"value\nreturn 200", `value"; return 200; "`, `trailing\`} {
		if err := ValidateQuotedDirectiveValue(value); err == nil {
			t.Errorf("ValidateQuotedDirectiveValue(%q) returned no error", value)
		}
	}
}

func TestValidateRawQuotedDirectiveValue(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", `pa"ss`, `path\\value`, "value; still data", "$hostname"} {
		if err := ValidateRawQuotedDirectiveValue(value); err != nil {
			t.Errorf("ValidateRawQuotedDirectiveValue(%q) returned error: %v", value, err)
		}
	}
	for _, value := range []string{"line\nbreak", "nul\x00byte"} {
		if err := ValidateRawQuotedDirectiveValue(value); err == nil {
			t.Errorf("ValidateRawQuotedDirectiveValue(%q) returned no error", value)
		}
	}
}

func TestValidateDirectiveToken(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"X-Forwarded-For", "example.com:53", "$request_uri", `value"quoted`} {
		if err := ValidateDirectiveToken(value); err != nil {
			t.Errorf("ValidateDirectiveToken(%q) returned error: %v", value, err)
		}
	}

	for _, value := range []string{"", "two tokens", "value#comment", `value\\escaped`} {
		if err := ValidateDirectiveToken(value); err == nil {
			t.Errorf("ValidateDirectiveToken(%q) returned no error", value)
		}
	}
}

func TestValidateTLSProtocols(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"TLSv1.2", "tlsv1.2 TLSv1.3", "TLSv1.2 TLSv1.2", "TLSv1 TLSv1.1 TLSv1.2"} {
		if err := ValidateTLSProtocols(value); err != nil {
			t.Errorf("ValidateTLSProtocols(%q) returned error: %v", value, err)
		}
	}

	for _, value := range []string{"", "TLSv2", "TLSv1.2; return 200", "TLSv1.2\u00a0TLSv1.3"} {
		if err := ValidateTLSProtocols(value); err == nil {
			t.Errorf("ValidateTLSProtocols(%q) returned no error", value)
		}
	}
}

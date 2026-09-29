package validation

import (
	"testing"
)

// The tests in this file exist because the escaping contract documented at the
// top of nginx.go had drifted from the code: it claimed ValidateDirectiveToken
// rejected quotes, while the function accepts them and a test asserted as much.
// A reader who trusted the comment could have picked the wrong rendering for a
// new field. Each test below asserts a property the contract relies on, so the
// prose and the behavior cannot separate again without something failing.

// backslashRejecters must reject '\' outright. That, not the treatment of
// quotes, is what makes printf "%q" safe for these values: with no backslash in
// the value there is no NGINX escape for %q to escape a second time.
//
// Each validator is paired with a value that it accepts once the backslash is
// removed, so the base value proves the value is otherwise valid and the only
// reason the backslash value is rejected is the backslash. A Cartesian product
// of every validator against every value would not do this: a value like
// "HIGH\x" is also rejected by a validator that fails it for another reason,
// so the test would still pass if backslash rejection regressed.
//
// ValidateTLSProtocols is deliberately absent: it is not rendered with
// printf "%q" (see the multi-token exception in nginx.go), and it rejects a
// backslash only incidentally, because no allowlisted protocol name contains
// one. There is no otherwise-valid protocol value carrying a backslash to pair
// it with.
func TestContract_LiteralValidatorsRejectBackslash(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		accepts       func(string) bool
		valid         string // accepted as-is
		withBackslash string // valid but for the added backslash
	}{
		{
			name:          "SSLCiphersRegex",
			accepts:       func(s string) bool { return SSLCiphersRegex.MatchString(s) },
			valid:         `HIGHx`,
			withBackslash: `HIGH\x`,
		},
		{
			name:          "ValidateHost",
			accepts:       func(s string) bool { return ValidateHost(s) == nil },
			valid:         `example.com`,
			withBackslash: `exa\mple.com`,
		},
		{
			name:          "ValidateDirectiveToken",
			accepts:       func(s string) bool { return ValidateDirectiveToken(s) == nil },
			valid:         `foobar`,
			withBackslash: `foo\bar`,
		},
	}

	for _, tc := range cases {
		if !tc.accepts(tc.valid) {
			t.Errorf("%s rejected %q; the paired value must be valid so the rejection below is attributable to the backslash", tc.name, tc.valid)
		}
		if tc.accepts(tc.withBackslash) {
			t.Errorf("%s accepted %q; values rendered with printf %%q must not be able to carry an NGINX escape", tc.name, tc.withBackslash)
		}
	}
}

// Quote handling mirrors ngx_conf_read_token rather than being stricter than it,
// because a value NGINX accepts is a value someone may already have configured.
// Each case below was traced through src/core/ngx_conf_file.c and then confirmed
// against nginx 1.31.3 with nginx -t; the note on directiveScanner cites the
// branches and quotes the measured errors.
//
// A review asked for a quote to be treated as quoting syntax wherever it appears.
// Measurement says otherwise: `add_header X-Test value";` and
// `add_header X-Test va"lue"x;` both parse. Adopting the suggestion would reject
// the values in the first group here, including "200 don't", and would make
// `404 x"; access_log off; # "` look safe when NGINX ends the directive at the
// semicolon.
func TestContract_QuoteHandlingMatchesNginxTokenizer(t *testing.T) {
	t.Parallel()

	// Position decides, not balance. A quote is only quoting syntax at the start
	// of a token; a trailing quote is unbalanced yet harmless because it never
	// opened anything.
	for _, value := range []string{
		`value"quoted`, // ordinary character mid-token
		`val"ue"x`,     // still ordinary, however many
		`value"`,       // unbalanced but harmless
		`value'`,       // same for a single quote
		`don"t`,        // bare word, mid-token double quote
		`200 don't`,    // the case that makes rejecting mid-token quotes wrong
		`"value"`,      // quoted in full: one token, NGINX strips the quotes
		`'value'`,      //
		`"don't"`,      // only the matching quote type closes a run
		`'don"t'`,      //
		`'don\'t'`,     // an escaped quote inside a run is data
		`200 "healthy; ready"`,
	} {
		if err := ValidateDirectiveValue(value); err != nil {
			t.Errorf("ValidateDirectiveValue(%q) = %v, want nil; NGINX accepts this", value, err)
		}
	}

	// A quote that does open an argument must close it, or NGINX reads on past
	// the directive looking for the closing quote.
	for _, value := range []string{`"value`, `'value`} {
		if err := ValidateDirectiveValue(value); err == nil {
			t.Errorf("ValidateDirectiveValue(%q) = nil, want an error; the quote opens an argument that is never closed", value)
		}
	}

	// Closing a quote sets need_space, after which NGINX accepts only whitespace,
	// ';', '{' or ')'. Anything else is `unexpected "%c"`.
	for _, value := range []string{`'don't'`, `"value"x`} {
		if err := ValidateDirectiveValue(value); err == nil {
			t.Errorf("ValidateDirectiveValue(%q) = nil, want an error; NGINX reports an unexpected character after a closing quote", value)
		}
	}

	// A backslash escapes the next character in any context, including the
	// semicolon that ends the directive, so a trailing one must be rejected.
	if err := ValidateDirectiveValue(`value\`); err == nil {
		t.Error(`ValidateDirectiveValue("value\\") = nil, want an error; the backslash would escape the directive terminator`)
	}
	if err := ValidateDirectiveValue(`value\"`); err != nil {
		t.Errorf(`ValidateDirectiveValue("value\\\"") = %v, want nil; an escaped quote is the correct way to embed one`, err)
	}
}

// ValidateDirectiveToken must reject everything that would let the value stop
// being a single token, since it is rendered unquoted.
func TestContract_DirectiveTokenRejectsTokenBreakers(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"two tokens",  // whitespace starts a second argument
		"two\ttokens", // tab likewise
		`esc\ape`,     // backslash escapes the next character
		"com#ment",    // starts a comment
		"end;",        // ends the directive
		"open{",       // opens a block
		"close}",      // closes a block
		"line\nbreak", //
		"line\rbreak", //
		"back`tick",   //
		"",            // empty is not a token
	} {
		if err := ValidateDirectiveToken(value); err == nil {
			t.Errorf("ValidateDirectiveToken(%q) = nil, want an error; the value would not stay one unquoted token", value)
		}
	}
}

// The pre-escaped validators must accept '\"' and reject an unescaped quote.
// That is what makes them pre-escaped, and why plain template quoting is
// correct for them and printf "%q" is not.
func TestContract_PreEscapedValidatorsAcceptEscapedQuotes(t *testing.T) {
	t.Parallel()

	validators := map[string]func(string) error{
		"ValidateQuotedDirectiveValue":       ValidateQuotedDirectiveValue,
		"ValidateSingleQuotedDirectiveValue": ValidateSingleQuotedDirectiveValue,
	}

	for name, validate := range validators {
		escaped := `say \"hi\"`
		if name == "ValidateSingleQuotedDirectiveValue" {
			escaped = `say \'hi\'`
		}
		if err := validate(escaped); err != nil {
			t.Errorf("%s(%q) = %v, want nil; a pre-escaped value must be accepted", name, escaped, err)
		}

		unescaped := `say "hi"`
		if name == "ValidateSingleQuotedDirectiveValue" {
			unescaped = `say 'hi'`
		}
		if err := validate(unescaped); err == nil {
			t.Errorf("%s(%q) = nil, want an error; an unescaped quote would end the argument", name, unescaped)
		}
	}
}

// ValidateRawQuotedDirectiveValue is the opaque contract: it accepts data that
// has not been escaped, including bare quotes and backslashes, because the
// template escapes it with printf "%q". It must still reject control characters,
// which no amount of quoting makes safe.
func TestContract_RawValidatorAcceptsUnescapedData(t *testing.T) {
	t.Parallel()

	for _, value := range []string{`pa"ss`, `pa\ss`, `pa\"ss`, "spaces are fine"} {
		if err := ValidateRawQuotedDirectiveValue(value); err != nil {
			t.Errorf("ValidateRawQuotedDirectiveValue(%q) = %v, want nil; opaque data is escaped by the template", value, err)
		}
	}
	// ASCII controls and non-printable Unicode alike, because printf "%q" escapes
	// them into \u.... sequences that NGINX does not decode, so accepting them
	// would let the stored value differ from the configured one.
	for _, value := range []string{
		"line\nbreak", "nul\x00byte", "tab\there",
		"nel\u0085here",  // U+0085, a non-ASCII control
		"nbsp\u00a0here", // U+00A0, a non-ASCII space
	} {
		if err := ValidateRawQuotedDirectiveValue(value); err == nil {
			t.Errorf("ValidateRawQuotedDirectiveValue(%q) = nil, want an error for a non-printable character", value)
		}
	}
}

// TestContract_BlockInjectionIsRejectedByEveryUnquotedContract states the threat
// these validators exist to stop, rather than the character rules that implement
// it.
//
// A quote is not the hazard; a semicolon is. Rendered unquoted, this value
//
//	value"; location / { return 500; } #
//
// becomes three statements: add_header X-Test value" ends at the injected
// semicolon, location / { return 500; } opens and closes an attacker-controlled
// block, and the '#' comments out the terminator the template appends, so the
// configuration loads. Measured with nginx -t against 1.31.3: it loads, giving
// an attacker-controlled location / that answers every request. That is a block
// injection, strictly worse than injecting one directive, and it is why a
// semicolon outside a quoted run is rejected unconditionally.
//
// The same value rendered through printf "%q" also loads, as
// add_header X-Test "value\"; location / { return 500; } #";, but as a single
// argument with no injection: the escaped quote keeps the run open so the
// semicolon and the braces are data. That contrast is the whole reason the
// opaque contract exists.
//
// Without the trailing '#' NGINX reports `unexpected ";"` for the orphaned
// terminator, so the naive form fails to load. That is not a defense worth
// relying on: one character removes it.
func TestContract_BlockInjectionIsRejectedByEveryUnquotedContract(t *testing.T) {
	t.Parallel()

	payloads := []string{
		`value"; location / { return 500; }`,   // orphaned terminator, fails to load
		`value"; location / { return 500; } #`, // terminator commented out, loads
		`value";`,                              // the minimal form
		`value'; location / { return 500; } #`, // a single quote reads the same way
	}

	// Anything rendered unquoted must refuse the payload, because the semicolon
	// ends the directive whatever precedes it.
	for _, payload := range payloads {
		if err := ValidateDirectiveValue(payload); err == nil {
			t.Errorf("ValidateDirectiveValue(%q) = nil, want an error; the semicolon would end the directive and open a block", payload)
		}
		if err := ValidateDirectiveToken(payload); err == nil {
			t.Errorf("ValidateDirectiveToken(%q) = nil, want an error", payload)
		}
	}

	// Pre-escaped fields render inside "{{ . }}", so what matters there is only
	// whether the value can close that argument. A double quote can and is
	// refused; a single quote cannot, and the semicolon after it stays quoted
	// data, so it is correctly allowed. The contract is about the rendering, not
	// about the payload looking dangerous.
	if err := ValidateQuotedDirectiveValue(`value"; location / { return 500; } #`); err == nil {
		t.Error(`ValidateQuotedDirectiveValue = nil, want an error; the unescaped double quote would close the argument`)
	}
	if err := ValidateQuotedDirectiveValue(`value'; location / { return 500; } #`); err != nil {
		t.Errorf(`ValidateQuotedDirectiveValue = %v, want nil; inside a double-quoted argument a single quote and a semicolon are both data`, err)
	}

	// The opaque contract accepts it deliberately: those values are rendered with
	// printf %q, which escapes the payload into a single argument. Accepting it
	// here and rejecting it above is the contract working as intended, not a gap.
	for _, payload := range payloads {
		if err := ValidateRawQuotedDirectiveValue(payload); err != nil {
			t.Errorf("ValidateRawQuotedDirectiveValue(%q) = %v, want nil; the template escapes this with printf %%q", payload, err)
		}
	}

	// The distinction that matters: the quote alone is inert, the semicolon is the
	// payload. Both measured with nginx -t; see the note on directiveScanner.
	if err := ValidateDirectiveValue(`value"`); err != nil {
		t.Errorf(`ValidateDirectiveValue("value\"") = %v, want nil; a mid-token quote is ordinary text to NGINX`, err)
	}

	// NGINX separates tokens only on space, tab, CR and LF. A non-breaking space
	// (U+00A0) is an ordinary token character to NGINX, so value"\u00a0"... stays
	// one token, the following quote is mid-token and inert, and the ';' ends the
	// directive and opens the injected payload. If the validator treated U+00A0 as
	// whitespace (as unicode.IsSpace does), it would see a separator, then a quote
	// opening a quoted argument, and accept the ';' as quoted data.
	nbspPayloads := []string{
		"value\u00a0\";return 200;#\"",
		"value\u0085\";return 200;#\"",
	}
	for _, payload := range nbspPayloads {
		if err := ValidateDirectiveValue(payload); err == nil {
			t.Errorf("ValidateDirectiveValue(%q) = nil, want an error; NGINX does not treat this rune as a token separator, so the ';' ends the directive", payload)
		}
		if err := ValidateDirectiveToken(payload); err == nil {
			t.Errorf("ValidateDirectiveToken(%q) = nil, want an error", payload)
		}
	}
}

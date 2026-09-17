package validation

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Escaping contract for values rendered into NGINX configuration.
//
// NIC validates configuration strings under one of four contracts, and which one
// applies decides how the value must be rendered by the templates. Getting this
// wrong in either direction is silent: the config still passes nginx -t, but the
// value NGINX ends up with is not the value the user configured.
//
// The properties each contract relies on are asserted in contract_test.go, so
// this description cannot drift away from the code again.
//
// The contract is not free to choose for an existing field. It is decided by
// what the template already did, because that is what determines which values
// are already in use and working. Changing the pairing changes the meaning of
// deployed configuration without any error being reported.
//
// What separates the contracts is how the validator treats a backslash, not how
// it treats a quote. printf "%q" escapes a bare quote correctly, so a quote in
// the value is not by itself a problem. A backslash is, because NGINX reads it
// as an escape: if the validator already accepts '\"' then the value arrives
// escaped and %q would escape it a second time.
//
// Literal contract. The value carries no NGINX escapes and means exactly what it
// says, so it is rendered with printf "%q", which turns it into one quoted
// argument whatever it contains. Validators in this group are SSLCiphersRegex,
// ValidateHost and the pathFmt in pkg/apis/configuration/validation, all of
// which reject '\' outright. Some also reject '"', but that is incidental rather
// than what makes the rendering safe.
//
// Multi-token exception. ValidateTLSProtocols is not in the literal group. Its
// directives, ssl_protocols and proxy_ssl_protocols, take one argument per
// protocol, and the templates render .SSLProtocols/.Protocols unquoted (for
// example internal/configs/version1/nginx.tmpl and
// internal/configs/version2/nginx.virtualserver.tmpl), so "TLSv1.2 TLSv1.3" must
// stay several arguments; printf "%q" would quote it into one and break the
// config. It is injection-safe not through escaping but because every
// space-separated token must match the fixed allowlist of six protocol names, so
// no delimiter or escape can survive validation.
//
// Ingress paths belong here too, by virtue of the rendering rather than the
// validator: pathFmt in internal/k8s permits both '"' and '\', so
// quoteLocationPath in internal/configs/version1 escapes with printf "%q" before
// quoting. Without that a path of /foo\ would escape its own closing quote.
//
// Single-token contract. ValidateDirectiveToken guarantees the value stays one
// NGINX token when rendered unquoted, which is how every caller renders it:
// app_protect_enforcer_address, the OpenTelemetry exporter endpoint, ssl_crl,
// app_protect_security_log, rewrite targets, and the map keys and limit_req_zone
// keys built from Policy fields. It rejects whitespace, '\', '#', ';', '{', '}',
// CR, LF and a backtick.
//
// It does not reject quotes, because NGINX does not: a quote is ordinary
// mid-token, and "value" is one token whose outer quotes NGINX strips. Do not
// render these with printf "%q" either: that would quote a value NGINX is going
// to read unquoted, and the quotes would become part of it.
//
// A field under this contract whose value is also read as a Go string needs a
// further check of its own, because a quoted form would make Go and NGINX
// disagree about the same field. validateCRLFileName is the example.
//
// Pre-escaped contract. A value under this contract is already escaped for
// NGINX, and is rendered with plain "{{ . }}" quoting so that NGINX performs the
// unescaping. Applying printf "%q" to it would escape the backslashes a second
// time: a realm stored as My \"API\" would render as "My \\\"API\\\"" and reach
// NGINX as My \"API\" rather than My "API".
//
// Dollar-rejecting validators such as realmFmt, clientSecretValueFmtRegexp,
// validAnnotationValueRegex, and headerValueFmt have the shape
// ([^"$\\]|\\[^$])*: they reject an unescaped '"' and '$', reject a trailing '\',
// and accept '\"' and '\\'. Variable-aware validators such as
// ValidateEscapedString and ValidateQuotedDirectiveValue allow an unescaped '$'
// for NGINX variable expansion, while still rejecting an unescaped double quote
// and incomplete escape. Every field whose template already quoted it plainly
// belongs here, including otel-exporter-header-value and the NGINX Plus custom
// server-tokens string.
//
// Opaque contract. ValidateRawQuotedDirectiveValue accepts any printable UTF-8,
// including bare quotes and backslashes, and the template renders it with
// printf "%q". This suits values that are data rather than configuration syntax,
// where asking a user to escape would be a trap: the mgmt proxy_username and
// proxy_password, and otel-service-name. It is only safe for a field whose
// template did not previously quote the value, because an unquoted NGINX token
// processes backslash escapes the same way a quoted one does, so a bare quote
// keeps its meaning while a backslash-escaped value does not. Do not move a
// field from the pre-escaped contract to this one.
//
// Name=value parameters. NGINX only strips quotes from a token when the quote is
// the token's first character, so quoting just the value half of a parameter
// does not produce a quoted argument: token="$http_token" leaves the quotes in
// the compiled value. Quote the whole token instead, as
// printf "%q" (printf "uri=%s" .URI) does.

// errDirectiveDelimiter is returned for a character that would end the current
// directive or change the block structure around it.
var errDirectiveDelimiter = errors.New("must not contain NGINX directive delimiters")

// ValidateDirectiveValue rejects characters that can terminate an NGINX
// directive or change its block structure. It is intended for values whose
// documented grammar may contain multiple tokens or NGINX variables.
func ValidateDirectiveValue(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("must not be empty")
	}

	// Mask braced variables without changing their token position. Removing one
	// would move the following character to the start of a token and could make a
	// double quote appear to open an argument that NGINX would not honor.
	value = maskBracedNginxVariables(value)

	scanner := directiveScanner{tokenBoundary: true}
	for _, char := range value {
		if err := scanner.next(char); err != nil {
			return err
		}
	}
	return scanner.atEnd()
}

// maskBracedNginxVariables replaces braced NGINX variables with a plain token
// so their braces are not mistaken for block delimiters. A dollar preceded by an
// odd number of backslashes is escaped by NGINX and must not be masked: its '{'
// still opens a block.
func maskBracedNginxVariables(value string) string {
	var masked strings.Builder
	for i := 0; i < len(value); {
		if end, ok := bracedNginxVariableEnd(value, i); ok {
			masked.WriteString("$variable")
			i = end
			continue
		}
		masked.WriteByte(value[i])
		i++
	}
	return masked.String()
}

func bracedNginxVariableEnd(value string, start int) (int, bool) {
	if start+3 > len(value) || value[start] != '$' || value[start+1] != '{' || isEscaped(value, start) || !isNginxVariableStart(value[start+2]) {
		return 0, false
	}

	end := start + 3
	for end < len(value) && isNginxVariableChar(value[end]) {
		end++
	}
	if end == len(value) || value[end] != '}' {
		return 0, false
	}
	return end + 1, true
}

func isEscaped(value string, index int) bool {
	backslashes := 0
	for index > 0 && value[index-1] == '\\' {
		backslashes++
		index--
	}
	return backslashes%2 != 0
}

func isNginxVariableStart(char byte) bool {
	return char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z'
}

func isNginxVariableChar(char byte) bool {
	return isNginxVariableStart(char) || char >= '0' && char <= '9'
}

// directiveScanner tracks the position of a scan through an NGINX directive
// value: whether a quoted argument is open, whether the previous character was
// an escape, and whether the next character would start a new token.
//
// It mirrors ngx_conf_read_token in src/core/ngx_conf_file.c. The line numbers
// below are from nginx 1.31.3 and the behavior has been stable for years, but
// the structure is what matters rather than the exact lines:
//
//   - d_quoted and s_quoted are set to 1 in only two places, at lines 703 and
//     709, both inside the `if (last_space)` branch opened at line 658. That
//     branch runs only at the start of a token, so a quote opens a quoted
//     argument only there.
//   - The mid-token branch at line 722 tests for `{` after a variable, `\`, `$`,
//     then `if (d_quoted)`, `else if (s_quoted)`, then whitespace, `;` and `{`.
//     A quote with neither flag set matches none of them and is copied into the
//     token as an ordinary character. This is why value" and don't are valid
//     NGINX and are accepted here.
//   - Because the quote tests are an else-if chain, only the matching quote type
//     closes a run: the `'` in "don't" is ordinary data.
//   - Closing a quote sets need_space (741, 748). The block at 632 then accepts
//     only whitespace, `;`, `{` or `)`; anything else is `unexpected "%c"`. That
//     is what rejects 'don't' and "value"x.
//   - The `quoted` flag is tested at the top of the loop, before every other
//     branch, so a backslash escapes the next character in any context. It can
//     escape the `;` that terminates the directive, which is why a value ending
//     in a lone backslash has to be rejected.
//
// A previous review asked for a quote to be tracked regardless of position.
// Doing so would accept `404 x"; access_log off; # "`, because the semicolon
// would be treated as quoted data, when NGINX in fact ends the directive there.
//
// The reading above was confirmed against nginx 1.31.3 with nginx -t, not just
// by reading the source. The cases that decide it:
//
//	add_header X-Test value";      parses; value is  value"
//	add_header X-Test va"lue"x;    parses; value is  va"lue"x
//	add_header X-Test 'don't';     unexpected "t"
//	add_header X-Test "value"x;    unexpected "x"
//	add_header X-Test value\;      unexpected "}"    the ; was escaped
//
// and, for why this matters here rather than being trivia, the same shape
// rendered into an upstream block:
//
//	hash $scheme";ip_hash;#" consistent;
//	    [warn] load balancing method redefined
//	    configuration file test is successful
//
// The semicolon ended the hash directive, ip_hash was parsed as a directive of
// its own, and because ngx_http_upstream_ip_hash only warns before overwriting
// peer.init_upstream the configuration loads with the upstream's load balancing
// method silently replaced. ip_hash, least_conn and random are the OSS
// upstream-context directives that take no arguments, so no whitespace is needed
// in the payload and the value still satisfies the three-token shape that
// validateHashLBMethod requires.
//
// Check the source, and preferably nginx -t, before changing the quote handling
// below.
type directiveScanner struct {
	quote         rune
	escaped       bool
	tokenBoundary bool
	needSpace     bool
}

func (s *directiveScanner) next(char rune) error {
	if char == '\r' || char == '\n' || char == '`' {
		return errDirectiveDelimiter
	}
	if s.escaped {
		s.escaped = false
		s.tokenBoundary = false
		return nil
	}
	if s.quote != 0 {
		s.insideQuote(char)
		return nil
	}
	return s.outsideQuote(char)
}

func (s *directiveScanner) insideQuote(char rune) {
	switch char {
	case '\\':
		s.escaped = true
	case s.quote:
		s.quote = 0
		s.needSpace = true
	}
}

// isNginxSpace reports whether char is one of the four bytes ngx_conf_read_token
// treats as whitespace between tokens: space, tab, CR and LF. unicode.IsSpace is
// deliberately not used: it also matches U+00A0, U+0085 and other runes that
// NGINX reads as ordinary token characters, so treating them as separators here
// would accept a value NGINX splits differently — letting a mid-token quote and
// a following ';' inject a directive that this validator believed was quoted.
func isNginxSpace(char rune) bool {
	return char == ' ' || char == '\t' || char == '\r' || char == '\n'
}

func (s *directiveScanner) outsideQuote(char rune) error {
	if s.needSpace {
		if !isNginxSpace(char) {
			return fmt.Errorf("quoted NGINX argument must be followed by whitespace")
		}
		s.needSpace = false
		s.tokenBoundary = true
		return nil
	}
	if isNginxSpace(char) {
		s.tokenBoundary = true
		return nil
	}
	if char == '\\' {
		s.escaped = true
		s.tokenBoundary = false
		return nil
	}
	if char == '\'' || char == '"' {
		// A quote opens a quoted argument only at the start of a token. Mid-token
		// it is an ordinary character, exactly as in the else branch of
		// ngx_conf_read_token; see the note on directiveScanner. Rejecting it
		// here instead would reject valid values such as "200 don't".
		if s.tokenBoundary {
			s.quote = char
		}
		s.tokenBoundary = false
		return nil
	}
	if char == '#' || strings.ContainsRune(";{}", char) {
		return errDirectiveDelimiter
	}
	s.tokenBoundary = false
	return nil
}

func (s *directiveScanner) atEnd() error {
	if s.escaped || s.quote != 0 {
		return fmt.Errorf("must contain balanced quotes and escapes")
	}
	return nil
}

// ValidateSingleQuotedDirectiveValue validates content rendered inside an
// NGINX single-quoted argument. Variables and semicolons are valid data in
// this context, but quote breakout and line breaks are not.
func ValidateSingleQuotedDirectiveValue(value string) error {
	escaped := false
	for _, char := range value {
		if char == '\r' || char == '\n' {
			return fmt.Errorf("must not contain line breaks")
		}
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == '\'' {
			return fmt.Errorf("single quotes must be escaped")
		}
	}
	if escaped {
		return fmt.Errorf("must not end with an unescaped backslash")
	}
	return nil
}

// ValidateDirectiveToken validates a value that must remain one NGINX token
// when rendered unquoted. It rejects whitespace, '\', '#' and everything
// ValidateDirectiveValue rejects, so the value cannot split into a second
// argument, start a comment, escape the character after it, or end the
// directive.
//
// It does not reject quotes, because NGINX does not either: a quote is ordinary
// mid-token, and "value" is one token whose outer quotes NGINX strips. A literal
// quote in a rewrite target is valid configuration and is accepted here.
//
// Callers whose value is also read as a Go string need more than this. A quoted
// form makes Go and NGINX disagree about the same field: a CRL file name of
// "ca.crl" leads policy.go to build /etc/nginx/secrets/"ca.crl" with path.Join
// while NGINX reads /etc/nginx/secrets/ca.crl, so the file is silently not
// found. That is a property of the field, not of NGINX tokens, so it is enforced
// at the field: see validateCRLFileName.
func ValidateDirectiveToken(value string) error {
	if value == "" {
		return fmt.Errorf("must not be empty")
	}
	if err := ValidateDirectiveValue(value); err != nil {
		return err
	}
	if strings.ContainsAny(value, "#\\ \t") {
		return fmt.Errorf("must be a single NGINX token")
	}
	return nil
}

// ValidateRawQuotedDirectiveValue validates opaque data that will be escaped
// and rendered as one quoted NGINX argument.
func ValidateRawQuotedDirectiveValue(value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("must be valid UTF-8")
	}
	for _, char := range value {
		// Reject every non-printable rune, not just ASCII controls. printf "%q"
		// renders a rune like U+0085 as the escape \u0085, and NGINX strips the
		// backslash rather than decoding a Go escape, so it would store u0085 and
		// silently change the value. Only runes unicode.IsPrint keeps verbatim
		// survive the printf "%q" rendering unchanged, which is what the opaque
		// contract promises. ASCII space stays printable; other spaces do not.
		if !unicode.IsPrint(char) {
			return fmt.Errorf("must not contain non-printable characters")
		}
	}
	return nil
}

// ValidateQuotedDirectiveValue validates content rendered inside an NGINX
// double-quoted argument. Quotes must be escaped and escapes must be complete.
func ValidateQuotedDirectiveValue(value string) error {
	escaped := false
	for _, char := range value {
		if char == '\r' || char == '\n' {
			return fmt.Errorf("must not contain line breaks")
		}
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == '"' {
			return fmt.Errorf("double quotes must be escaped")
		}
	}
	if escaped {
		return fmt.Errorf("must not end with an unescaped backslash")
	}
	return nil
}

var validTLSProtocols = map[string]struct{}{
	"sslv2":   {},
	"sslv3":   {},
	"tlsv1":   {},
	"tlsv1.1": {},
	"tlsv1.2": {},
	"tlsv1.3": {},
}

// ValidateTLSProtocols validates the space-separated token grammar accepted
// by the ssl_protocols and proxy_ssl_protocols directives.
func ValidateTLSProtocols(value string) error {
	protocols := strings.FieldsFunc(value, isNginxSpace)
	if len(protocols) == 0 {
		return fmt.Errorf("must contain at least one TLS protocol")
	}

	for _, protocol := range protocols {
		if _, ok := validTLSProtocols[strings.ToLower(protocol)]; !ok {
			return fmt.Errorf("unsupported TLS protocol %q", protocol)
		}
	}

	return nil
}

// UnescapeNGINXToken returns the string NGINX stores for a token after applying
// the backslash processing ngx_conf_read_token performs. NGINX collapses \\, \"
// and \' to the bare character and decodes \t, \r and \n; every other escape
// keeps its backslash, so a regex escape such as \. is preserved. It applies in
// both quoted and unquoted token contexts because the backslash handling is the
// same in each.
//
// A regex rendered into NGINX config must be validated against this form rather
// than its pre-NGINX text: NGINX unescapes the value before its PCRE engine
// compiles it, so a value that compiles as written (for example one ending in
// \\) can still reach PCRE as an invalid pattern (a lone trailing \) and fail
// nginx -t. A trailing lone backslash is preserved here; callers reject it
// separately (see ValidateEscapedString).
func UnescapeNGINXToken(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	runes := []rune(value)
	for i := 0; i < len(runes); i++ {
		if runes[i] != '\\' || i == len(runes)-1 {
			b.WriteRune(runes[i])
			continue
		}
		switch next := runes[i+1]; next {
		case '"', '\'', '\\':
			b.WriteRune(next)
		case 't':
			b.WriteRune('\t')
		case 'r':
			b.WriteRune('\r')
		case 'n':
			b.WriteRune('\n')
		default:
			b.WriteRune('\\')
			b.WriteRune(next)
		}
		i++
	}
	return b.String()
}

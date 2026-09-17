package validation

import "testing"

// TestUnescapeNGINXToken pins the helper to ngx_conf_read_token's backslash
// processing: \\, \" and \' collapse to the bare character, \t/\r/\n decode, and
// every other escape keeps its backslash so regex escapes such as \. survive.
func TestUnescapeNGINXToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "no escapes", in: `^/images`, want: `^/images`},
		{name: "escaped backslash collapses", in: `^/foo\\`, want: `^/foo\`},
		{name: "double escaped backslash", in: `a\\\\b`, want: `a\\b`},
		{name: "regex dot escape preserved", in: `^/foo\.png$`, want: `^/foo\.png$`},
		{name: "escaped quote collapses", in: `a\"b`, want: `a"b`},
		{name: "escaped single quote collapses", in: `a\'b`, want: `a'b`},
		{name: "decodes tab", in: `a\tb`, want: "a\tb"},
		{name: "decodes cr and lf", in: `a\r\nb`, want: "a\r\nb"},
		{name: "unknown escape keeps backslash", in: `\d+`, want: `\d+`},
		{name: "trailing lone backslash preserved", in: `abc\`, want: `abc\`},
	}

	for _, test := range tests {
		if got := UnescapeNGINXToken(test.in); got != test.want {
			t.Errorf("UnescapeNGINXToken(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

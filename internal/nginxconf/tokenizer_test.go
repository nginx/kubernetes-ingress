package nginxconf

import (
	"reflect"
	"testing"
)

// TestTokenizerMatchesMeasuredNginx pins the tokenizer to the behavior measured
// with nginx -t against 1.31.3. Every case here was run through a real NGINX; the
// G-numbers refer to that run. If the tokenizer and NGINX ever disagree, the
// injection tests built on it are worthless, so this is checked directly.
func TestTokenizerMatchesMeasuredNginx(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value    string
		wantFail bool
		note     string
	}{
		{`value`, false, "G-1"},
		{`"value"`, false, "G-2"},
		{`'value'`, false, "G-3"},
		{`"value`, true, "G-4"},
		{`don't`, false, "G-5"},
		{`value"`, false, "G-6 KEY"},
		{`value'`, false, "G-7"},
		{`don"t`, false, "G-8"},
		{`va"lue"x`, false, "G-9 KEY"},
		{`"don't"`, false, "G-10"},
		{`'don"t'`, false, "G-11"},
		{`'don't'`, true, "G-12 unexpected t"},
		{`"value"x`, true, "G-13 unexpected x"},
		{`'don\'t'`, false, "G-14"},
		{`value\"`, false, "G-15"},
		{`value\`, true, "G-16 escaped its own ;"},
	}
	for _, c := range cases {
		conf := "server {\n    add_header X-Test " + c.value + ";\n}\n"
		_, err := Tokenize(conf)
		got := err != nil
		if got != c.wantFail {
			t.Errorf("%-28s value=%-14q tokenizer fail=%v, nginx fail=%v  err=%v", c.note, c.value, got, c.wantFail, err)
		}
	}
}

// TestTokenizerBraceRulesFromSource covers the '{' and '}' rules from
// ngx_conf_read_token. The cases were also measured against nginx 1.31.3; the
// runnable record is quote-tokenizer-tests.conf.
//
// The rules, with the line in src/core/ngx_conf_file.c that decides each:
//
//	:722  '{' straight after '$' is ordinary, which is how ${name} is written
//	:753  any other '{' part-way through a token ends it and opens a block
//	:682  '}' closes a block only at the start of a token
//	:753  '}' part-way through a token is ordinary, being absent from the
//	      terminator set there
func TestTokenizerBraceRulesFromSource(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value    string
		wantFail bool
		note     string
	}{
		{`${name}`, false, "the form NIC generates for a rate limit key"},
		{`${a}${b}`, false, "two references in one token"},
		{`a${b}c`, false, "a reference inside a larger token"},
		{`a}b`, false, "a '}' mid-token is ordinary"},
		{`value}`, false, "trailing '}' does not close the server block"},
		{`a{b`, true, "a '{' not after '$' opens a block, leaving it unclosed"},
		{`$a{b`, true, "'variable' is cleared by 'a', so this '{' opens a block"},
		{`"${name}"`, false, "quoted, where braces are ordinary anyway"},
		{`"a}b"`, false, "quoted '}'"},
	}
	for _, c := range cases {
		conf := "server {\n    add_header X-Test " + c.value + ";\n}\n"
		_, err := Tokenize(conf)
		if got := err != nil; got != c.wantFail {
			t.Errorf("value=%-12q tokenizer fail=%v, source says fail=%v  err=%v  (%s)",
				c.value, got, c.wantFail, err, c.note)
		}
	}
}

func TestTokenizerMatchesNginxCore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		conf    string
		want    []string
		wantErr bool
	}{
		{
			name: "only NGINX whitespace separates tokens",
			conf: "server {\n    add_header X-Test value\u00a0other;\n}\n",
			want: []string{"0:server {", "1:add_header X-Test value\u00a0other", "0:}"},
		},
		{
			name: "parenthesis after a quoted token begins another token",
			conf: "server {\n    directive \"value\");\n}\n",
			want: []string{"0:server {", "1:directive value )", "0:}"},
		},
		{
			name: "NGINX escape decoding",
			conf: "server {\n    directive value\\tother value\\q;\n}\n",
			want: []string{"0:server {", "1:directive value\tother value\\q", "0:}"},
		},
		{name: "empty statement", conf: ";", wantErr: true},
		{name: "anonymous block", conf: "{}", wantErr: true},
		{name: "unterminated statement", conf: "worker_processes 1", wantErr: true},
		{
			// ngx_conf_read_token imposes no argument limit; NGX_CONF_MAX_ARGS is
			// enforced later in ngx_conf_handler and only for fixed-arity masks, so
			// NGX_CONF_1MORE/2MORE/ANY directives such as log_format carry more than
			// eight arguments legally. The tokenizer must not reject them.
			name: "directive with more than eight arguments",
			conf: "http {\n    log_format m a b c d e f g h i;\n}\n",
			want: []string{"0:http {", "1:log_format m a b c d e f g h i", "0:}"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statements, err := Tokenize(test.conf)
			if (err != nil) != test.wantErr {
				t.Fatalf("Tokenize() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantErr {
				return
			}

			got := make([]string, len(statements))
			for i, statement := range statements {
				got[i] = statement.String()
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("Tokenize() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestShapeLeavesDataBlockWhenItCloses(t *testing.T) {
	t.Parallel()
	shape, err := Shape("map $a $b {\n    default one;\n}\nserver {\n    listen 80;\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"0:map", "1:<entry>", "0:}", "0:server", "1:listen", "0:}"}
	if !reflect.DeepEqual(shape, want) {
		t.Errorf("Shape() = %v, want %v", shape, want)
	}
}

// The block injection, and the mitigation.
func TestTokenizerDetectsBlockInjection(t *testing.T) {
	t.Parallel()
	benign := "server {\n    add_header X-Test benign;\n}\n"
	inject := "server {\n    add_header X-Test value\"; location / { return 500; } #;\n}\n"
	quoted := "server {\n    add_header X-Test \"value\\\"; location / { return 500; } #\";\n}\n"

	bs, err := Shape(benign)
	if err != nil {
		t.Fatal(err)
	}
	is, err := Shape(inject)
	if err != nil {
		t.Fatalf("injected config should parse (nginx -t said it loads): %v", err)
	}
	qs, err := Shape(quoted)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("benign   shape: %v", bs)
	t.Logf("injected shape: %v", is)
	t.Logf("%%q       shape: %v", qs)
	if want := []string{"0:server", "1:add_header", "1:location", "2:return", "1:}", "0:}"}; !reflect.DeepEqual(is, want) {
		t.Errorf("injected Shape() = %v, want %v", is, want)
	}
	if !reflect.DeepEqual(bs, qs) {
		t.Errorf("quoted Shape() = %v, want %v", qs, bs)
	}
}

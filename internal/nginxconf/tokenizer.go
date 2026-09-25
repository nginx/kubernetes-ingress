// Package nginxconf tokenizes NGINX configuration the way NGINX itself does.
//
// It exists so that injection tests can ask the question that matters — did a
// configuration value become configuration syntax — instead of searching rendered
// output for suspicious substrings. Comparing the Shape of two renderings that
// differ only in one field's value tells you whether that value was treated as
// data or as syntax.
//
// It has no production callers by design; the generators write configuration, they
// do not read it.
package nginxconf

import (
	"fmt"
	"strings"
)

// This file implements a tokenizer faithful to ngx_conf_read_token in
// src/core/ngx_conf_file.c, for use by injection tests. It exists so a test can
// ask the question that matters — did a configuration value become configuration
// syntax — instead of grepping the rendered output for suspicious substrings.
//
// The rules it mirrors, each verified against nginx 1.31.3 with nginx -t:
//
//   - whitespace ends a token; ';' ends a statement; '{' opens a block, even
//     part-way through a token
//   - '}' closes a block only at the start of a token; part-way through one it
//     is an ordinary character
//   - '{' is ordinary when it immediately follows '$', so ${name} is one token
//   - '#' starts a comment to end of line, but only at the start of a token
//   - '\' escapes the following character in any context, including a ';'
//   - a quote opens a quoted run only as the first character of a token, and
//     only the matching quote type closes it
//   - after a closing quote only whitespace, ';', '{' or ')' may follow
//
// A statement is a directive name plus its arguments. Comparing the statement
// structure of two renderings tells us whether a value injected syntax, whatever
// that value happened to be.

// Statement is one tokenized NGINX directive: its block-nesting depth and the
// words it is composed of.
type Statement struct {
	depth int
	words []string
}

func (s Statement) String() string {
	return fmt.Sprintf("%d:%s", s.depth, strings.Join(s.words, " "))
}

// Tokenize returns the statements of a configuration, or an error where
// NGINX itself would refuse to parse it.
func Tokenize(conf string) ([]Statement, error) {
	var z confTokenizer
	for i := 0; i < len(conf); i++ {
		if err := z.next(conf[i]); err != nil {
			return nil, err
		}
	}
	return z.atEnd()
}

// confTokenizer holds the position of a scan through a configuration file. The
// state and the dispatch below follow ngx_conf_read_token: a comment runs to end
// of line, a backslash escapes the next character in any context, a quoted run is
// opened only at the start of a token, and a closing quote must be followed by
// whitespace, ';', '{' or ')'.
type confTokenizer struct {
	statements []Statement
	words      []string
	token      strings.Builder
	depth      int

	inToken   bool
	quote     byte
	escaped   bool
	needSpace bool
	comment   bool
	variable  bool
}

func (z *confTokenizer) next(char byte) error {
	switch {
	case z.comment:
		if char == '\n' {
			z.comment = false
		}
		return nil
	case z.escaped:
		z.escaped = false
		z.writeEscaped(char)
		return nil
	case z.quote != 0:
		z.inQuote(char)
		return nil
	case z.needSpace:
		return z.afterQuote(char)
	default:
		return z.outsideQuote(char)
	}
}

func (z *confTokenizer) inQuote(char byte) {
	switch char {
	case '\\':
		z.escaped = true
	case z.quote:
		z.quote = 0
		z.needSpace = true
	default:
		z.token.WriteByte(char)
	}
}

// afterQuote implements the need_space rule: only these four characters may
// follow a closing quote.
func (z *confTokenizer) afterQuote(char byte) error {
	z.needSpace = false
	switch {
	case isSpace(char):
		z.flushToken()
	case char == ';':
		return z.flushStatement()
	case char == '{':
		return z.openBlock()
	case char == ')':
		z.flushToken()
		z.write(char)
	default:
		return fmt.Errorf("unexpected %q", char)
	}
	return nil
}

func (z *confTokenizer) outsideQuote(char byte) error {
	// '{' is an ordinary character when it immediately follows '$', which is how
	// the ${name} form of a variable reference is written. ngx_conf_read_token
	// tracks this with its `variable` flag and tests it before anything else, so
	// the flag survives a run of '{' as that code does.
	if char == '{' && z.variable {
		z.write(char)
		return nil
	}
	z.variable = false
	return z.classifyOutsideQuote(char)
}

// classifyOutsideQuote dispatches a character that is not inside a quoted
// argument to the state change it triggers. It is split out of outsideQuote so
// that neither function carries the whole tokenizer's branching on its own.
func (z *confTokenizer) classifyOutsideQuote(char byte) error {
	switch {
	case isSpace(char):
		z.flushToken()
	case char == ';':
		return z.flushStatement()
	case char == '{':
		return z.openBlock()
	case char == '}' && z.inToken:
		// A '}' part-way through a token is an ordinary character: nginx only
		// treats it as closing a block at the start of a token. This is what
		// lets ${name} end without closing the enclosing block.
		z.write(char)
	case char == '}':
		return z.closeBlock()
	case char == '#' && !z.inToken:
		z.comment = true
	case char == '\\':
		z.escaped = true
		z.inToken = true
	case (char == '"' || char == '\'') && !z.inToken:
		z.quote = char
		z.inToken = true
	case char == '$':
		z.variable = true
		z.write(char)
	default:
		z.write(char)
	}
	return nil
}

func (z *confTokenizer) write(char byte) {
	z.token.WriteByte(char)
	z.inToken = true
}

func (z *confTokenizer) writeEscaped(char byte) {
	switch char {
	case '"', '\'', '\\':
		z.write(char)
	case 't':
		z.write('\t')
	case 'r':
		z.write('\r')
	case 'n':
		z.write('\n')
	default:
		z.write('\\')
		z.write(char)
	}
}

func (z *confTokenizer) flushToken() {
	if z.inToken {
		z.words = append(z.words, z.token.String())
		z.token.Reset()
		z.inToken = false
	}
}

func (z *confTokenizer) flushStatement() error {
	z.flushToken()
	if len(z.words) == 0 {
		return fmt.Errorf(`unexpected ";"`)
	}
	z.statements = append(z.statements, Statement{depth: z.depth, words: z.words})
	z.words = nil
	return nil
}

func (z *confTokenizer) openBlock() error {
	z.flushToken()
	if len(z.words) == 0 {
		return fmt.Errorf(`unexpected "{"`)
	}
	z.statements = append(z.statements, Statement{depth: z.depth, words: append(z.words, "{")})
	z.words = nil
	z.depth++
	return nil
}

func (z *confTokenizer) closeBlock() error {
	z.flushToken()
	if len(z.words) != 0 {
		return fmt.Errorf(`unexpected "}"`)
	}
	z.depth--
	if z.depth < 0 {
		return fmt.Errorf(`unexpected "}"`)
	}
	z.statements = append(z.statements, Statement{depth: z.depth, words: []string{"}"}})
	return nil
}

func (z *confTokenizer) atEnd() ([]Statement, error) {
	if z.quote != 0 || z.escaped || z.inToken || len(z.words) != 0 {
		return nil, fmt.Errorf(`unexpected end of file, expecting ";" or "}"`)
	}
	if z.depth != 0 {
		return nil, fmt.Errorf("unexpected end of file, expecting %q", "}")
	}
	return z.statements, nil
}

func isSpace(char byte) bool {
	return char == ' ' || char == '\t' || char == '\r' || char == '\n'
}

// dataBlocks are directives whose blocks contain data rather than directives.
// The first word of an entry in one of these is a key chosen by the user, not a
// directive name, so Shape records a placeholder for it: a map key that changes
// because a field changed is not a structural difference, and treating it as one
// reports every value change as an injection.
//
// Breaking out of such a block is still caught, because that alters the nesting
// and adds statements outside it.
var dataBlocks = map[string]bool{
	"map":           true,
	"geo":           true,
	"split_clients": true,
	"types":         true,
	"charset_map":   true,
}

// Shape reduces a configuration to its directive structure: the name of
// every statement and the block nesting it sits at, with arguments discarded.
// Two renderings that differ only in the value of one field share a shape; a
// rendering where a value became syntax does not.
func Shape(conf string) ([]string, error) {
	statements, err := Tokenize(conf)
	if err != nil {
		return nil, err
	}

	shape := make([]string, 0, len(statements))
	// Depths at which a data block is open, so entries below them are recorded as
	// data rather than as directive names.
	inDataBlock := map[int]bool{}

	for _, statement := range statements {
		name := statement.words[0]
		opensBlock := statement.words[len(statement.words)-1] == "{"

		if name == "}" {
			delete(inDataBlock, statement.depth+1)
			shape = append(shape, fmt.Sprintf("%d:}", statement.depth))
			continue
		}

		if inDataBlock[statement.depth] {
			name = "<entry>"
		} else if opensBlock && dataBlocks[name] {
			inDataBlock[statement.depth+1] = true
		}

		shape = append(shape, fmt.Sprintf("%d:%s", statement.depth, name))
	}
	return shape, nil
}

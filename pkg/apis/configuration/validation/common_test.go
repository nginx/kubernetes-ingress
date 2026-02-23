package validation

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

func createPointerFromInt(n int) *int {
	return &n
}

func TestValidateVariable(t *testing.T) {
	t.Parallel()
	validVars := map[string]bool{
		"scheme":                 true,
		"http_x_forwarded_proto": true,
		"request_uri":            true,
		"host":                   true,
	}

	validTests := []string{
		"scheme",
		"http_x_forwarded_proto",
		"request_uri",
		"host",
	}
	for _, nVar := range validTests {
		allErrs := validateVariable(nVar, validVars, field.NewPath("url"))
		if len(allErrs) != 0 {
			t.Errorf("validateVariable(%v) returned errors %v for valid input", nVar, allErrs)
		}
	}
}

func TestValidateVariableFails(t *testing.T) {
	t.Parallel()
	validVars := map[string]bool{
		"host": true,
	}
	invalidVars := []string{
		"",
		"hostinvalid.com",
		"$a",
		"host${host}",
		"host${host}}",
		"host$${host}",
	}
	for _, nVar := range invalidVars {
		allErrs := validateVariable(nVar, validVars, field.NewPath("url"))
		if len(allErrs) == 0 {
			t.Errorf("validateVariable(%v) returned no errors for invalid input", nVar)
		}
	}
}

func TestParseSpecialVariable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		specialVar    string
		expectedName  string
		expectedValue string
	}{
		{
			specialVar:    "arg_username",
			expectedName:  "arg",
			expectedValue: "username",
		},
		{
			specialVar:    "arg_user_name",
			expectedName:  "arg",
			expectedValue: "user_name",
		},
		{
			specialVar:    "jwt_header_username",
			expectedName:  "jwt_header",
			expectedValue: "username",
		},
		{
			specialVar:    "jwt_header_user_name",
			expectedName:  "jwt_header",
			expectedValue: "user_name",
		},
		{
			specialVar:    "jwt_claim_username",
			expectedName:  "jwt_claim",
			expectedValue: "username",
		},
		{
			specialVar:    "jwt_claim_user_name",
			expectedName:  "jwt_claim",
			expectedValue: "user_name",
		},
	}

	for _, test := range tests {
		name, value, allErrs := parseSpecialVariable(test.specialVar, field.NewPath("variable"))
		if name != test.expectedName {
			t.Errorf("parseSpecialVariable(%v) returned name %v but expected %v", test.specialVar, name, test.expectedName)
		}
		if value != test.expectedValue {
			t.Errorf("parseSpecialVariable(%v) returned value %v but expected %v", test.specialVar, value, test.expectedValue)
		}
		if len(allErrs) != 0 {
			t.Errorf("parseSpecialVariable(%v) returned errors for valid case: %v", test.specialVar, allErrs)
		}
	}
}

func TestParseSpecialVariableFails(t *testing.T) {
	t.Parallel()
	specialVars := []string{
		"arg",
		"jwt_header",
		"jwt_claim",
	}

	for _, v := range specialVars {
		_, _, allErrs := parseSpecialVariable(v, field.NewPath("variable"))
		if len(allErrs) == 0 {
			t.Errorf("parseSpecialVariable(%v) returned no errors for invalid case", v)
		}
	}
}

func TestValidateSpecialVariable(t *testing.T) {
	t.Parallel()
	specialVars := []string{
		"arg_username",
		"arg_user_name",
		"http_header_name",
		"cookie_cookie_name",
	}

	isPlus := false

	for _, v := range specialVars {
		allErrs := validateSpecialVariable(v, field.NewPath("variable"), isPlus)
		if len(allErrs) != 0 {
			t.Errorf("validateSpecialVariable(%v) returned errors for valid case: %v", v, allErrs)
		}
	}
}

func TestValidateSpecialVariableForPlus(t *testing.T) {
	t.Parallel()
	specialVars := []string{
		"arg_username",
		"arg_user_name",
		"http_header_name",
		"cookie_cookie_name",
		"jwt_header_alg",
		"jwt_claim_user",
	}

	isPlus := true

	for _, v := range specialVars {
		allErrs := validateSpecialVariable(v, field.NewPath("variable"), isPlus)
		if len(allErrs) != 0 {
			t.Errorf("validateSpecialVariable(%v) returned errors for valid case: %v", v, allErrs)
		}
	}
}

func TestValidateSpecialVariableFails(t *testing.T) {
	t.Parallel()
	specialVars := []string{
		"arg",
		"arg_invalid%",
		"http_header+invalid",
		"cookie_cookie_name?invalid",
		"jwt_header_alg",
		"jwt_claim_user",
		"some_var",
	}

	isPlus := false

	for _, v := range specialVars {
		allErrs := validateSpecialVariable(v, field.NewPath("variable"), isPlus)
		if len(allErrs) == 0 {
			t.Errorf("validateSpecialVariable(%v) returned no errors for invalid case", v)
		}
	}
}

func TestValidateSpecialVariableForPlusFails(t *testing.T) {
	t.Parallel()
	specialVars := []string{
		"arg",
		"arg_invalid%",
		"http_header+invalid",
		"cookie_cookie_name?invalid",
		"jwt_header_+invalid",
		"wt_claim_invalid?",
		"some_var",
	}

	isPlus := true

	for _, v := range specialVars {
		allErrs := validateSpecialVariable(v, field.NewPath("variable"), isPlus)
		if len(allErrs) == 0 {
			t.Errorf("validateSpecialVariable(%v) returned no errors for invalid case", v)
		}
	}
}

func TestValidateStringWithVariables(t *testing.T) {
	t.Parallel()
	isPlus := false

	testStrings := []string{
		"",
		"${scheme}",
		"${scheme}${host}",
		"foo.bar",
	}
	validVars := map[string]bool{"scheme": true, "host": true}

	for _, test := range testStrings {
		allErrs := validateStringWithVariables(test, field.NewPath("string"), nil, validVars, isPlus)
		if len(allErrs) != 0 {
			t.Errorf("validateStringWithVariables(%v) returned errors for valid input: %v", test, allErrs)
		}
	}

	specialVars := []string{"arg", "http", "cookie"}
	testStringsSpecial := []string{
		"${arg_username}",
		"${http_header_name}",
		"${cookie_cookie_name}",
	}

	for _, test := range testStringsSpecial {
		allErrs := validateStringWithVariables(test, field.NewPath("string"), specialVars, validVars, isPlus)
		if len(allErrs) != 0 {
			t.Errorf("validateStringWithVariables(%v) returned errors for valid input: %v", test, allErrs)
		}
	}
}

func TestValidateStringWithVariablesFail(t *testing.T) {
	t.Parallel()
	isPlus := false

	testStrings := []string{
		"$scheme}",
		"${sch${eme}${host}",
		"host$",
		"${host",
		"${invalid}",
	}
	validVars := map[string]bool{"scheme": true, "host": true}

	for _, test := range testStrings {
		allErrs := validateStringWithVariables(test, field.NewPath("string"), nil, validVars, isPlus)
		if len(allErrs) == 0 {
			t.Errorf("validateStringWithVariables(%v) returned no errors for invalid input", test)
		}
	}

	specialVars := []string{"arg", "http", "cookie"}
	testStringsSpecial := []string{
		"${arg_username%}",
		"${http_header-name}",
		"${cookie_cookie?name}",
	}

	for _, test := range testStringsSpecial {
		allErrs := validateStringWithVariables(test, field.NewPath("string"), specialVars, validVars, isPlus)
		if len(allErrs) == 0 {
			t.Errorf("validateStringWithVariables(%v) returned no errors for invalid input", test)
		}
	}
}

func TestValidateSize(t *testing.T) {
	t.Parallel()
	validInput := []string{"", "4k", "8K", "16m", "32M"}
	for _, test := range validInput {
		allErrs := validateSize(test, field.NewPath("size-field"))
		if len(allErrs) != 0 {
			t.Errorf("validateSize(%q) returned an error for valid input", test)
		}
	}

	invalidInput := []string{"55mm", "2mG", "6kb", "-5k", "1L", "5G"}
	for _, test := range invalidInput {
		allErrs := validateSize(test, field.NewPath("size-field"))
		if len(allErrs) == 0 {
			t.Errorf("validateSize(%q) didn't return error for invalid input.", test)
		}
	}
}

func TestValidateTime(t *testing.T) {
	t.Parallel()
	time := "1h 2s"
	allErrs := validateTime(time, field.NewPath("time-field"))

	if len(allErrs) != 0 {
		t.Errorf("validateTime returned errors %v valid input %v", allErrs, time)
	}
}

func TestValidateTimeFails(t *testing.T) {
	t.Parallel()
	time := "invalid"
	allErrs := validateTime(time, field.NewPath("time-field"))

	if len(allErrs) == 0 {
		t.Errorf("validateTime returned no errors for invalid input %v", time)
	}
}

func TestValidateOffset(t *testing.T) {
	t.Parallel()
	validInput := []string{"", "1", "10k", "11m", "1K", "100M", "5G"}
	for _, test := range validInput {
		allErrs := validateOffset(test, field.NewPath("offset-field"))
		if len(allErrs) != 0 {
			t.Errorf("validateOffset(%q) returned an error for valid input", test)
		}
	}

	invalidInput := []string{"55mm", "2mG", "6kb", "-5k", "1L", "5Gb"}
	for _, test := range invalidInput {
		allErrs := validateOffset(test, field.NewPath("offset-field"))
		if len(allErrs) == 0 {
			t.Errorf("validateOffset(%q) didn't return error for invalid input.", test)
		}
	}
}

func TestHeaderValidation(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		hasError   bool
	}{
		{
			name:       "Valid header name",
			headerName: "Content-Type",
			hasError:   false,
		},
		{
			name:       "Valid header with numbers",
			headerName: "X-Custom-Header-123",
			hasError:   false,
		},
		{
			name:       "Invalid header with special chars",
			headerName: "Content@Type",
			hasError:   true,
		},
		{
			name:       "Invalid empty header",
			headerName: "",
			hasError:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isValid := isValidHeaderName(test.headerName)

			if test.hasError && isValid {
				t.Errorf("Expected error for header name %s, but got none", test.headerName)
			}
			if !test.hasError && !isValid {
				t.Errorf("Expected no error for header name %s, but got error", test.headerName)
			}
		})
	}
}

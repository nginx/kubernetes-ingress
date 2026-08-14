package validation

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestValidateRequiredFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		obj        *unstructured.Unstructured
		fieldsList [][]string
		expectErr  bool
		msg        string
	}{
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": map[string]interface{}{},
					"b": map[string]interface{}{},
				},
			},
			fieldsList: [][]string{{"a"}, {"b"}},
			expectErr:  false,
			msg:        "valid object with 2 fields",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": map[string]interface{}{},
				},
			},
			fieldsList: [][]string{{"a"}, {"b"}},
			expectErr:  true,
			msg:        "invalid object with a missing field",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": map[string]interface{}{},
					"x": map[string]interface{}{},
				},
			},
			fieldsList: [][]string{{"a"}, {"b"}},
			expectErr:  true,
			msg:        "invalid object with a wrong field",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": map[string]interface{}{
						"b": map[string]interface{}{},
					},
				},
			},
			fieldsList: [][]string{{"a", "b"}},
			expectErr:  false,
			msg:        "valid object with nested field",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": map[string]interface{}{
						"x": map[string]interface{}{},
					},
				},
			},
			fieldsList: [][]string{{"a", "b"}},
			expectErr:  true,
			msg:        "invalid object with a wrong nested field",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			fieldsList: nil,
			expectErr:  false,
			msg:        "valid object with no validation",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": "wrong-type", // must be map[string]interface{}
				},
			},
			fieldsList: [][]string{{"a"}},
			expectErr:  true,
			msg:        "invalid object with a field of wrong type",
		},
	}

	for _, test := range tests {
		err := ValidateRequiredFields(test.obj, test.fieldsList)
		if test.expectErr && err == nil {
			t.Errorf("ValidateRequiredFields() returned no error for the case of %s", test.msg)
		}
		if !test.expectErr && err != nil {
			t.Errorf("ValidateRequiredFields() returned unexpected error %v for the case of %s", err, test.msg)
		}
	}
}

func TestValidateRequiredSlices(t *testing.T) {
	t.Parallel()
	tests := []struct {
		obj        *unstructured.Unstructured
		fieldsList [][]string
		expectErr  bool
		msg        string
	}{
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": []interface{}{},
					"b": []interface{}{},
				},
			},
			fieldsList: [][]string{{"a"}, {"b"}},
			expectErr:  false,
			msg:        "valid object with 2 fields",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": []interface{}{},
				},
			},
			fieldsList: [][]string{{"a"}, {"b"}},
			expectErr:  true,
			msg:        "invalid object with a field",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": []interface{}{},
					"x": []interface{}{},
				},
			},
			fieldsList: [][]string{{"a"}, {"b"}},
			expectErr:  true,
			msg:        "invalid object with a wrong field",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": map[string]interface{}{
						"b": []interface{}{},
					},
				},
			},
			fieldsList: [][]string{{"a", "b"}},
			expectErr:  false,
			msg:        "valid object with nested field",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": map[string]interface{}{
						"x": []interface{}{},
					},
				},
			},
			fieldsList: [][]string{{"a", "b"}},
			expectErr:  true,
			msg:        "invalid object with a wrong nested field",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{},
			},
			fieldsList: nil,
			expectErr:  false,
			msg:        "valid object with no validation",
		},
		{
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"a": "wrong-type", // must be [string]interface{}
				},
			},
			fieldsList: [][]string{{"a"}},
			expectErr:  true,
			msg:        "invalid object with a field of wrong type",
		},
	}

	for _, test := range tests {
		err := ValidateRequiredSlices(test.obj, test.fieldsList)
		if test.expectErr && err == nil {
			t.Errorf("ValidateRequiredSlices() returned no error for the case of %s", test.msg)
		}
		if !test.expectErr && err != nil {
			t.Errorf("ValidateRequiredSlices() returned unexpected error %v for the case of %s", err, test.msg)
		}
	}
}

func TestValidateAppProtectLogDestinationAnnotation(t *testing.T) {
	t.Parallel()
	// Positive test cases
	posDstAntns := []string{"stderr", "syslog:server=localhost:9000", "syslog:server=10.1.1.2:9000", "/var/log/ap.log", "syslog:server=my-syslog-server.my-namespace:515"}

	// Negative test cases item, expected error message
	negDstAntns := [][]string{
		{"stdout", "Log Destination did not follow format"},
		{"syslog:server=localhost:99999", "not a valid port number"},
		{"syslog:server=mysyslog-server:999", "not a valid ip address"},
		{"XXstderrXX", "Log Destination did not follow format"},
		{"/var/log/ap.log trailing", "Log Destination did not follow format"},
		{"syslog:server=10.1.1.2:9000extra", "Log Destination did not follow format"},
		{"syslog:server=localhost:9000;one", "contains dangerous characters"},
		{"/var/log/ap.log$", "contains dangerous characters"},
		{"/var/log/ap`log", "contains dangerous characters"},
		{"/var/log/{ap}.log", "contains dangerous characters"},
		{"stderr\r", "contains dangerous characters"},
		{"syslog:server=localhost:9000\nnewline", "contains dangerous characters"},
	}

	for _, tCase := range posDstAntns {
		err := ValidateAppProtectLogDestination(tCase)
		if err != nil {
			t.Errorf("got %v expected nil", err)
		}
	}
	for _, nTCase := range negDstAntns {
		err := ValidateAppProtectLogDestination(nTCase[0])
		if err == nil {
			t.Errorf("got no error expected error containing %s", nTCase[1])
		} else {
			if !strings.Contains(err.Error(), nTCase[1]) {
				t.Errorf("got %v expected to contain: %s", err, nTCase[1])
			}
		}
	}
}

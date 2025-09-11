package configs

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/nginx/kubernetes-ingress/internal/configs/version2"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var configMap = v1.ConfigMap{
	ObjectMeta: meta_v1.ObjectMeta{
		Name:      "test",
		Namespace: "default",
	},
	TypeMeta: meta_v1.TypeMeta{
		Kind:       "ConfigMap",
		APIVersion: "v1",
	},
}

var ingress = networking.Ingress{
	ObjectMeta: meta_v1.ObjectMeta{
		Name:      "test",
		Namespace: "kube-system",
	},
	TypeMeta: meta_v1.TypeMeta{
		Kind:       "Ingress",
		APIVersion: "extensions/v1beta1",
	},
}

func TestParseProxySetHeader_ReturnsHeadersOnValidInput(t *testing.T) {
	t.Parallel()

	got := parseProxySetHeaders([]string{"abc:def"})
	want := []version2.Header{
		{
			Name:  "abc",
			Value: "def",
		},
	}
	if !cmp.Equal(want, got) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestParseProxySetHeaders_ReturnsEmptyHeaderOnEmptyInput(t *testing.T) {
	t.Parallel()

	got := parseProxySetHeaders([]string{""})
	want := make([]version2.Header, 1)

	if !cmp.Equal(want, got) {
		t.Error(cmp.Diff(want, got))
	}
}

func TestParseProxySetHeaders_ReturnsNilOnInputWithNoHeaders(t *testing.T) {
	t.Parallel()

	got := parseProxySetHeaders([]string{})
	if got != nil {
		t.Errorf("want nil headers, got %v", got)
	}
}

func TestParseStickyServicesLists_FailsOnBogusInputString(t *testing.T) {
	t.Parallel()

	invalidInputs := []string{
		"",
		",",
		"a,b",
		";abc",
		"abc;def",
	}
	for _, s := range invalidInputs {
		_, err := ParseStickyServiceList(s)
		if err == nil {
			t.Errorf("want err on invalid input %q, got nil", s)
		}
	}
}

func TestParseRewritesList_FailsOnBogusInputString(t *testing.T) {
	t.Parallel()

	invalidRewrites := []string{
		"; ",
		";abc",
		"abc;def",
	}
	for _, s := range invalidRewrites {
		_, err := ParseRewriteList(s)
		if err == nil {
			t.Errorf("want err on invalid input: %q, got nil", s)
		}
	}
}

func TestParseServicesFromString(t *testing.T) {
	t.Parallel()

	tt := []struct {
		input string
		want  map[string]bool
	}{
		{
			input: "",
			want:  map[string]bool{"": true},
		},
		{
			input: "serviceA",
			want:  map[string]bool{"serviceA": true},
		},
		{
			input: "serviceA,serviceB",
			want: map[string]bool{
				"serviceA": true,
				"serviceB": true,
			},
		},
	}

	for _, tc := range tt {
		got := ParseServiceList(tc.input)
		if !cmp.Equal(tc.want, got) {
			t.Error(cmp.Diff(tc.want, got))
		}
	}
}

func TestParsePortList_FailsOnBogusStrings(t *testing.T) {
	t.Parallel()

	invalidPortList := []string{"", ".", "abs", "34.", "3.4", ":2", "8080,", ",1024", "-90"}
	for _, s := range invalidPortList {
		_, err := ParsePortList(s)
		if err == nil {
			t.Fatal(err)
		}
	}
}

func TestParsePortList_ParsesPortsFromValidString(t *testing.T) {
	t.Parallel()

	tt := []struct {
		input string
		want  []int
	}{
		{
			input: "22,23,80",
			want:  []int{22, 23, 80},
		},
		{
			input: "8080",
			want:  []int{8080},
		},
	}

	for _, tc := range tt {
		got, err := ParsePortList(tc.input)
		if err != nil {
			t.Fatal(err)
		}
		if !cmp.Equal(tc.want, got) {
			t.Error(cmp.Diff(tc.want, got))
		}
	}
}

func TestGetMapKeyAsBool(t *testing.T) {
	t.Parallel()
	configMap := configMap
	configMap.Data = map[string]string{
		"key": "True",
	}

	b, exists, err := GetMapKeyAsBool(configMap.Data, "key", &configMap)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !exists {
		t.Error("The key 'key' must exist in the configMap")
	}
	if b != true {
		t.Error("Result should be true")
	}
}

func TestGetMapKeyAsBoolNotFound(t *testing.T) {
	t.Parallel()
	configMap := configMap
	configMap.Data = map[string]string{}

	_, exists, _ := GetMapKeyAsBool(configMap.Data, "key", &configMap)
	if exists {
		t.Error("The key 'key' must not exist in the configMap")
	}
}

func TestGetMapKeyAsBoolErrorMessage(t *testing.T) {
	t.Parallel()
	cfgm := configMap
	cfgm.Data = map[string]string{
		"key": "string",
	}

	// Test with configmap
	_, _, err := GetMapKeyAsBool(cfgm.Data, "key", &cfgm)
	if err == nil {
		t.Fatal("An error was expected")
	}
	expected := `ConfigMap default/test 'key' contains invalid bool: strconv.ParseBool: parsing "string": invalid syntax, ignoring`
	if err.Error() != expected {
		t.Errorf("The error message does not match expectations:\nGot: %v\nExpected: %v", err, expected)
	}

	// Test with ingress object
	ingress := ingress
	ingress.Annotations = map[string]string{
		"key": "other_string",
	}

	_, _, err = GetMapKeyAsBool(ingress.Annotations, "key", &ingress)
	if err == nil {
		t.Fatal("An error was expected")
	}
	expected = `Ingress kube-system/test 'key' contains invalid bool: strconv.ParseBool: parsing "other_string": invalid syntax, ignoring`
	if err.Error() != expected {
		t.Errorf("The error message does not match expectations:\nGot: %v\nExpected: %v", err, expected)
	}
}

func TestGetMapKeyAsInt(t *testing.T) {
	t.Parallel()
	configMap := configMap
	configMap.Data = map[string]string{
		"key": "123456789",
	}

	i, exists, err := GetMapKeyAsInt(configMap.Data, "key", &configMap)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !exists {
		t.Error("The key 'key' must exist in the configMap")
	}
	expected := 123456789
	if i != expected {
		t.Errorf("Unexpected return value:\nGot: %v\nExpected: %v", i, expected)
	}
}

func TestGetMapKeyAsIntNotFound(t *testing.T) {
	t.Parallel()
	configMap := configMap
	configMap.Data = map[string]string{}

	_, exists, _ := GetMapKeyAsInt(configMap.Data, "key", &configMap)
	if exists {
		t.Error("The key 'key' must not exist in the configMap")
	}
}

func TestGetMapKeyAsIntErrorMessage(t *testing.T) {
	t.Parallel()
	cfgm := configMap
	cfgm.Data = map[string]string{
		"key": "string",
	}

	// Test with configmap
	_, _, err := GetMapKeyAsInt(cfgm.Data, "key", &cfgm)
	if err == nil {
		t.Fatal("An error was expected")
	}
	expected := `ConfigMap default/test 'key' contains invalid integer: strconv.Atoi: parsing "string": invalid syntax, ignoring`
	if err.Error() != expected {
		t.Errorf("The error message does not match expectations:\nGot: %v\nExpected: %v", err, expected)
	}

	// Test with ingress object
	ingress := ingress
	ingress.Annotations = map[string]string{
		"key": "other_string",
	}

	_, _, err = GetMapKeyAsInt(ingress.Annotations, "key", &ingress)
	if err == nil {
		t.Fatal("An error was expected")
	}
	expected = `Ingress kube-system/test 'key' contains invalid integer: strconv.Atoi: parsing "other_string": invalid syntax, ignoring`
	if err.Error() != expected {
		t.Errorf("The error message does not match expectations:\nGot: %v\nExpected: %v", err, expected)
	}
}

func TestGetMapKeyAsInt64(t *testing.T) {
	t.Parallel()
	configMap := configMap
	configMap.Data = map[string]string{
		"key": "123456789",
	}

	i, exists, err := GetMapKeyAsInt64(configMap.Data, "key", &configMap)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !exists {
		t.Error("The key 'key' must exist in the configMap")
	}
	var expected int64 = 123456789
	if i != expected {
		t.Errorf("Unexpected return value:\nGot: %v\nExpected: %v", i, expected)
	}
}

func TestGetMapKeyAsInt64NotFound(t *testing.T) {
	t.Parallel()
	configMap := configMap
	configMap.Data = map[string]string{}

	_, exists, _ := GetMapKeyAsInt64(configMap.Data, "key", &configMap)
	if exists {
		t.Error("The key 'key' must not exist in the configMap")
	}
}

func TestGetMapKeyAsInt64ErrorMessage(t *testing.T) {
	t.Parallel()
	cfgm := configMap
	cfgm.Data = map[string]string{
		"key": "string",
	}

	// Test with configmap
	_, _, err := GetMapKeyAsInt64(cfgm.Data, "key", &cfgm)
	if err == nil {
		t.Fatal("An error was expected")
	}
	expected := `ConfigMap default/test 'key' contains invalid integer: strconv.ParseInt: parsing "string": invalid syntax, ignoring`
	if err.Error() != expected {
		t.Errorf("The error message does not match expectations:\nGot: %v\nExpected: %v", err, expected)
	}

	// Test with ingress object
	ingress := ingress
	ingress.Annotations = map[string]string{
		"key": "other_string",
	}

	_, _, err = GetMapKeyAsInt64(ingress.Annotations, "key", &ingress)
	if err == nil {
		t.Fatal("An error was expected")
	}
	expected = `Ingress kube-system/test 'key' contains invalid integer: strconv.ParseInt: parsing "other_string": invalid syntax, ignoring`
	if err.Error() != expected {
		t.Errorf("The error message does not match expectations:\nGot: %v\nExpected: %v", err, expected)
	}
}

func TestGetMapKeyAsStringSlice(t *testing.T) {
	t.Parallel()
	configMap := configMap
	configMap.Data = map[string]string{
		"key": "1.String,2.String,3.String",
	}

	slice, exists := GetMapKeyAsStringSlice(configMap.Data, "key", &configMap, ",")
	if !exists {
		t.Errorf("The key 'key' must exist in the configMap")
	}
	expected := []string{"1.String", "2.String", "3.String"}
	t.Log(expected)
	if !reflect.DeepEqual(expected, slice) {
		t.Errorf("Unexpected return value:\nGot: %#v\nExpected: %#v", slice, expected)
	}
}

func TestGetMapKeyAsStringSliceMultilineSnippets(t *testing.T) {
	t.Parallel()
	configMap := configMap
	configMap.Data = map[string]string{
		"server-snippets": `
			if ($new_uri) {
				rewrite ^ $new_uri permanent;
			}`,
	}

	slice, exists := GetMapKeyAsStringSlice(configMap.Data, "server-snippets", &configMap, "\n")
	if !exists {
		t.Errorf("The key 'server-snippets' must exist in the configMap")
	}
	expected := []string{"", "\t\t\tif ($new_uri) {", "\t\t\t\trewrite ^ $new_uri permanent;", "\t\t\t}"}
	t.Log(expected)
	if !reflect.DeepEqual(expected, slice) {
		t.Errorf("Unexpected return value:\nGot: %#v\nExpected: %#v", slice, expected)
	}
}

func TestGetMapKeyAsStringSliceNotFound(t *testing.T) {
	t.Parallel()
	configMap := configMap
	configMap.Data = map[string]string{}

	_, exists := GetMapKeyAsStringSlice(configMap.Data, "key", &configMap, ",")
	if exists {
		t.Error("The key 'key' must not exist in the configMap")
	}
}

func TestParseLBMethod(t *testing.T) {
	t.Parallel()
	testsWithValidInput := []struct {
		input    string
		expected string
	}{
		{"least_conn", "least_conn"},
		{"round_robin", ""},
		{"ip_hash", "ip_hash"},
		{"random", "random"},
		{"random two", "random two"},
		{"random two least_conn", "random two least_conn"},
		{"hash $request_id", "hash $request_id"},
		{"hash $request_id consistent", "hash $request_id consistent"},
	}

	invalidInput := []string{
		"",
		"blabla",
		"least_time header",
		"hash123",
		"hash $request_id conwrongspelling",
		"random one",
		"random two least_time=header",
		"random two least_time=last_byte",
		"random two ip_hash",
	}

	for _, test := range testsWithValidInput {
		result, err := ParseLBMethod(test.input)
		if err != nil {
			t.Fatalf("TestParseLBMethod(%q) returned an error for valid input", test.input)
		}

		if result != test.expected {
			t.Errorf("TestParseLBMethod(%q) returned %q expected %q", test.input, result, test.expected)
		}
	}

	for _, input := range invalidInput {
		_, err := ParseLBMethod(input)
		if err == nil {
			t.Fatalf("TestParseLBMethod(%q) does not return an error for invalid input", input)
		}
	}
}

func TestParseLBMethodForPlus(t *testing.T) {
	t.Parallel()
	testsWithValidInput := []struct {
		input    string
		expected string
	}{
		{"least_conn", "least_conn"},
		{"round_robin", ""},
		{"ip_hash", "ip_hash"},
		{"random", "random"},
		{"random two", "random two"},
		{"random two least_conn", "random two least_conn"},
		{"random two least_time=header", "random two least_time=header"},
		{"random two least_time=last_byte", "random two least_time=last_byte"},
		{"hash $request_id", "hash $request_id"},
		{"least_time header", "least_time header"},
		{"least_time last_byte", "least_time last_byte"},
		{"least_time header inflight", "least_time header inflight"},
		{"least_time last_byte inflight", "least_time last_byte inflight"},
	}

	invalidInput := []string{
		"",
		"blabla",
		"hash123",
		"least_time",
		"last_byte",
		"least_time inflight header",
		"random one",
		"random two ip_hash",
		"random two least_time",
	}

	for _, test := range testsWithValidInput {
		result, err := ParseLBMethodForPlus(test.input)
		if err != nil {
			t.Fatalf("TestParseLBMethod(%q) returned an error for valid input", test.input)
		}

		if result != test.expected {
			t.Errorf("TestParseLBMethod(%q) returned %q expected %q", test.input, result, test.expected)
		}
	}

	for _, input := range invalidInput {
		_, err := ParseLBMethodForPlus(input)
		if err == nil {
			t.Errorf("TestParseLBMethod(%q) does not return an error for invalid input", input)
		}
	}
}

func TestParseTime(t *testing.T) {
	t.Parallel()
	testsWithValidInput := []struct {
		input    string
		expected string
	}{
		{"1h30m 5 100ms", "1h30m5s100ms"},
		{"10ms", "10ms"},
		{"1", "1s"},
		{"5m 30s", "5m30s"},
		{"1s", "1s"},
		{"100m", "100m"},
		{"5w", "5w"},
		{"15m", "15m"},
		{"11M", "11M"},
		{"3h", "3h"},
		{"100y", "100y"},
		{"600", "600s"},
	}
	invalidInput := []string{"5s 5s", "ss", "rM", "m0m", "s1s", "-5s", "", "1L", "11 11", " ", "   "}

	for _, test := range testsWithValidInput {
		result, err := ParseTime(test.input)
		if err != nil {
			t.Fatalf("TestparseTime(%q) returned an error for valid input", test.input)
		}

		if result != test.expected {
			t.Errorf("TestparseTime(%q) returned %q expected %q", test.input, result, test.expected)
		}
	}

	for _, test := range invalidInput {
		result, err := ParseTime(test)
		if err == nil {
			t.Errorf("TestparseTime(%q) didn't return error. Returned: %q", test, result)
		}
	}
}

func TestParseOffset(t *testing.T) {
	t.Parallel()
	testsWithValidInput := []string{"1", "2k", "2K", "3m", "3M", "4g", "4G"}
	invalidInput := []string{"-1", "", "blah"}
	for _, test := range testsWithValidInput {
		result, err := ParseOffset(test)
		if err != nil {
			t.Fatalf("TestParseOffset(%q) returned an error for valid input", test)
		}
		if test != result {
			t.Errorf("TestParseOffset(%q) returned %q expected %q", test, result, test)
		}
	}
	for _, test := range invalidInput {
		result, err := ParseOffset(test)
		if err == nil {
			t.Errorf("TestParseOffset(%q) didn't return error. Returned: %q", test, result)
		}
	}
}

func TestParseSize(t *testing.T) {
	t.Parallel()
	testsWithValidInput := []string{"1", "2k", "2K", "3m", "3M"}
	invalidInput := []string{"-1", "", "blah", "4g", "4G"}
	for _, test := range testsWithValidInput {
		result, err := ParseSize(test)
		if err != nil {
			t.Fatalf("TestParseSize(%q) returned an error for valid input", test)
		}
		if test != result {
			t.Errorf("TestParseSize(%q) returned %q expected %q", test, result, test)
		}
	}
	for _, test := range invalidInput {
		result, err := ParseSize(test)
		if err == nil {
			t.Errorf("TestParseSize(%q) didn't return error. Returned: %q", test, result)
		}
	}
}

func TestParseProxyBuffersSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
		hasError bool
	}{
		{
			name:     "valid proxy buffers with k unit",
			input:    "8 4k",
			expected: "8 4k",
			hasError: false,
		},
		{
			name:     "valid proxy buffers with M unit",
			input:    "32 2M",
			expected: "32 2M",
			hasError: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
			hasError: true,
		},
		{
			name:     "only buffer count",
			input:    "8",
			expected: "",
			hasError: true,
		},
		{
			name:     "negative buffer count",
			input:    "-8 4k",
			expected: "",
			hasError: true,
		},
		{
			name:     "non-numeric buffer size",
			input:    "8 abc",
			expected: "",
			hasError: true,
		},
		{
			name:     "blah",
			input:    "blah",
			expected: "",
			hasError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseProxyBuffersSpec(tc.input)

			if tc.hasError && err == nil {
				t.Errorf("ParseProxyBuffersSpecWithAutoAdjust(%q) expected error but got none, result: %q", tc.input, result)
			}
			if !tc.hasError && err != nil {
				t.Errorf("ParseProxyBuffersSpecWithAutoAdjust(%q) unexpected error: %v", tc.input, err)
			}
			if result != tc.expected {
				t.Errorf("ParseProxyBuffersSpecWithAutoAdjust(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestVerifyThresholds(t *testing.T) {
	t.Parallel()
	validInput := []string{
		"high=3 low=1",
		"high=12 low=2",
		"high=100 low=3",
		"high=12 low=10",
		"high=100 low=11",
		"low=1 high=3",
		"low=2 high=12",
		"low=3 high=100",
		"low=10 high=12",
		"low=11 high=100",
	}
	invalidInput := []string{
		"high=101 low=10",
		"high=101 low=999",
		"high=1 high=1",
		"low=1 low=20",
		"low=",
		"high=12",
		"a string",
	}
	for _, input := range validInput {
		if !VerifyAppProtectThresholds(input) {
			t.Errorf("VerifyAppProtectThresholds(%s) returned false,expected true", input)
		}
	}
	for _, input := range invalidInput {
		if VerifyAppProtectThresholds(input) {
			t.Errorf("VerifyAppProtectThresholds(%s) returned true,expected false", input)
		}
	}
}

func TestParseBool(t *testing.T) {
	t.Parallel()
	testsWithValidInput := []struct {
		input    string
		expected bool
	}{
		{"0", false},
		{"1", true},
		{"true", true},
		{"false", false},
	}

	invalidInput := []string{
		"",
		"blablah",
		"-100",
		"-1",
	}

	for _, test := range testsWithValidInput {
		result, err := ParseBool(test.input)
		if err != nil {
			t.Fatalf("TestParseBool(%q) returned an error for valid input", test.input)
		}

		if result != test.expected {
			t.Errorf("TestParseBool(%q) returned %t expected %t", test.input, result, test.expected)
		}
	}

	for _, input := range invalidInput {
		_, err := ParseBool(input)
		if err == nil {
			t.Errorf("TestParseBool(%q) does not return an error for invalid input", input)
		}
	}
}

func TestParseInt(t *testing.T) {
	t.Parallel()
	testsWithValidInput := []struct {
		input    string
		expected int
	}{
		{"0", 0},
		{"1", 1},
		{"-100", -100},
		{"123456789", 123456789},
	}

	invalidInput := []string{
		"",
		"blablah",
		"10000000000000000000000000000000000000000000000000000000000000000",
		"1,000",
	}

	for _, test := range testsWithValidInput {
		result, err := ParseInt(test.input)
		if err != nil {
			t.Fatalf("TestParseInt(%q) returned an error for valid input", test.input)
		}

		if result != test.expected {
			t.Errorf("TestParseInt(%q) returned %d expected %d", test.input, result, test.expected)
		}
	}

	for _, input := range invalidInput {
		_, err := ParseInt(input)
		if err == nil {
			t.Errorf("TestParseInt(%q) does not return an error for invalid input", input)
		}
	}
}

func TestParseInt64(t *testing.T) {
	t.Parallel()
	testsWithValidInput := []struct {
		input    string
		expected int64
	}{
		{"0", 0},
		{"1", 1},
		{"-100", -100},
		{"123456789", 123456789},
	}

	invalidInput := []string{
		"",
		"blablah",
		"10000000000000000000000000000000000000000000000000000000000000000",
		"1,000",
	}

	for _, test := range testsWithValidInput {
		result, err := ParseInt64(test.input)
		if err != nil {
			t.Fatalf("TestParseInt64(%q) returned an error for valid input", test.input)
		}

		if result != test.expected {
			t.Errorf("TestParseInt64(%q) returned %d expected %d", test.input, result, test.expected)
		}
	}

	for _, input := range invalidInput {
		_, err := ParseInt64(input)
		if err == nil {
			t.Errorf("TestParseInt64(%q) does not return an error for invalid input", input)
		}
	}
}

func TestParseUint64(t *testing.T) {
	t.Parallel()
	testsWithValidInput := []struct {
		input    string
		expected uint64
	}{
		{"0", 0},
		{"1", 1},
		{"100", 100},
		{"123456789", 123456789},
	}

	invalidInput := []string{
		"",
		"blablah",
		"10000000000000000000000000000000000000000000000000000000000000000",
		"1,000",
		"-1023",
	}

	for _, test := range testsWithValidInput {
		result, err := ParseUint64(test.input)
		if err != nil {
			t.Fatalf("TestParseUint64(%q) returned an error for valid input", test.input)
		}

		if result != test.expected {
			t.Errorf("TestParseUint64(%q) returned %d expected %d", test.input, result, test.expected)
		}
	}

	for _, input := range invalidInput {
		_, err := ParseUint64(input)
		if err == nil {
			t.Errorf("TestParseUint64(%q) does not return an error for invalid input", input)
		}
	}
}

func TestParseFloat64(t *testing.T) {
	testsWithValidInput := []struct {
		input    string
		expected float64
	}{
		{"0", 0},
		{"1", 1},
		{"123.456", 123.456},
		{"-100", -100},
		{"-12345.6789", -12345.6789},
		{"123456789", 123456789},
		{"1.7E+308", 1.7e+308},
		{"-1.7E+308", -1.7e+308},
	}

	invalidInput := []string{
		"",
		"blablah",
		"100.15.12",
		"1,000",
		"1.8E+308",
		"-1.8E+308",
	}

	for _, test := range testsWithValidInput {
		result, err := ParseFloat64(test.input)
		if err != nil {
			t.Fatalf("TestParseFloat64(%q) returned an error for valid input", test.input)
		}

		if result != test.expected {
			t.Errorf("TestParseFloat64(%q) returned %e expected %e", test.input, result, test.expected)
		}
	}

	for _, input := range invalidInput {
		_, err := ParseFloat64(input)
		if err == nil {
			t.Errorf("TestParseFloat64(%q) does not return an error for invalid input", input)
		}
	}
}

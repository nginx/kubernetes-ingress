package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseNginxStatusAllowCIDRs(t *testing.T) {
	badCIDRs := []struct {
		input         string
		expectedError error
	}{
		{
			"earth, ,,furball",
			errors.New("invalid IP address: earth"),
		},
		{
			"127.0.0.1,10.0.1.0/24, ,,furball",
			errors.New("invalid CIDR address: an empty string is an invalid CIDR block or IP address"),
		},
		{
			"false",
			errors.New("invalid IP address: false"),
		},
	}
	for _, badCIDR := range badCIDRs {
		_, err := parseNginxStatusAllowCIDRs(badCIDR.input)
		if err == nil {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned no error when it should have returned error %q", badCIDR.input, badCIDR.expectedError)
		} else if err.Error() != badCIDR.expectedError.Error() {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned error %q when it should have returned error %q", badCIDR.input, err, badCIDR.expectedError)
		}
	}

	goodCIDRs := []struct {
		input    string
		expected []string
	}{
		{
			"127.0.0.1",
			[]string{"127.0.0.1"},
		},
		{
			"10.0.1.0/24",
			[]string{"10.0.1.0/24"},
		},
		{
			"127.0.0.1,10.0.1.0/24,68.121.233.214 , 24.24.24.24/32",
			[]string{"127.0.0.1", "10.0.1.0/24", "68.121.233.214", "24.24.24.24/32"},
		},
	}
	for _, goodCIDR := range goodCIDRs {
		result, err := parseNginxStatusAllowCIDRs(goodCIDR.input)
		if err != nil {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned an error when it should have returned no error: %q", goodCIDR.input, err)
		}

		if !reflect.DeepEqual(result, goodCIDR.expected) {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned %v expected %v: ", goodCIDR.input, result, goodCIDR.expected)
		}
	}
}

func TestValidateCIDRorIP(t *testing.T) {
	badCIDRs := []string{"localhost", "thing", "~", "!!!", "", " ", "-1"}
	for _, badCIDR := range badCIDRs {
		err := validateCIDRorIP(badCIDR)
		if err == nil {
			t.Errorf(`Expected error for invalid CIDR "%v"\n`, badCIDR)
		}
	}

	goodCIDRs := []string{"0.0.0.0/32", "0.0.0.0/0", "127.0.0.1/32", "127.0.0.0/24", "23.232.65.42"}
	for _, goodCIDR := range goodCIDRs {
		err := validateCIDRorIP(goodCIDR)
		if err != nil {
			t.Errorf("Error for valid CIDR: %v err: %v\n", goodCIDR, err)
		}
	}
}

func TestValidateLocation(t *testing.T) {
	badLocations := []string{
		"",
		"/",
		" /test",
		"/bad;",
	}
	for _, badLocation := range badLocations {
		err := validateLocation(badLocation)
		if err == nil {
			t.Errorf("validateLocation(%v) returned no error when it should have returned an error", badLocation)
		}
	}

	goodLocations := []string{
		"/test",
		"/test/subtest",
	}
	for _, goodLocation := range goodLocations {
		err := validateLocation(goodLocation)
		if err != nil {
			t.Errorf("validateLocation(%v) returned an error when it should have returned no error: %v", goodLocation, err)
		}
	}
}

func TestValidateLogLevel(t *testing.T) {
	badLogLevels := []string{
		"",
		"critical",
		"none",
		"info;",
	}
	for _, badLogLevel := range badLogLevels {
		err := validateLogLevel(badLogLevel)
		if err == nil {
			t.Errorf("validateLogLevel(%v) returned no error when it should have returned an error", badLogLevel)
		}
	}

	goodLogLevels := []string{
		"fatal",
		"Error",
		"WARN",
		"info",
		"debug",
		"trace",
	}
	for _, goodLogLevel := range goodLogLevels {
		err := validateLogLevel(goodLogLevel)
		if err != nil {
			t.Errorf("validateLogLevel(%v) returned an error when it should have returned no error: %v", goodLogLevel, err)
		}
	}
}

func TestValidateNamespaces(t *testing.T) {
	badNamespaces := []string{"watchns1, watchns2, watchns%$", "watchns1,watchns2,watchns%$"}
	for _, badNs := range badNamespaces {
		err := validateNamespaceNames(strings.Split(badNs, ","))
		if err == nil {
			t.Errorf("Expected error for invalid namespace %v\n", badNs)
		}
	}

	goodNamespaces := []string{"watched-namespace", "watched-namespace,", "watched-namespace1,watched-namespace2", "watched-namespace1, watched-namespace2"}
	for _, goodNs := range goodNamespaces {
		err := validateNamespaceNames(strings.Split(goodNs, ","))
		if err != nil {
			t.Errorf("Error for valid namespace:  %v err: %v\n", goodNs, err)
		}
	}
}

func TestValidateLogFormat(t *testing.T) {
	badLogFormats := []string{
		"",
		"jason",
		"txt",
		"gloog",
	}
	for _, badLogFormat := range badLogFormats {
		err := validateLogFormat(badLogFormat)
		if err == nil {
			t.Errorf("validateLogFormat(%v) returned no error when it should have returned an error", badLogFormat)
		}
	}

	goodLogFormats := []string{
		"json",
		"text",
		"glog",
	}
	for _, goodLogFormat := range goodLogFormats {
		err := validateLogFormat(goodLogFormat)
		if err != nil {
			t.Errorf("validateLogFormat(%v) returned an error when it should have returned no error: %v", goodLogFormat, err)
		}
	}
}

func TestParseLatencyBuckets(t *testing.T) {
	t.Parallel()

	badInputs := []string{
		"",           // empty
		"abc",        // not a number
		"5,abc,10",   // contains a non-number
		"5,,10",      // empty element
		"-5,10",      // negative value
		"0,10",       // zero is not positive
		"10,5",       // not ascending
		"5,5",        // not strictly ascending (equal)
		"5,10,10,20", // duplicate value
	}
	for _, in := range badInputs {
		if _, err := parseLatencyBuckets(in); err == nil {
			t.Errorf("parseLatencyBuckets(%q) returned no error when it should have returned an error", in)
		}
	}

	goodInputs := []struct {
		input    string
		expected []float64
	}{
		{"5", []float64{5}},
		{"5,10,25,50,100", []float64{5, 10, 25, 50, 100}},
		{" 1 , 2 , 3 ", []float64{1, 2, 3}},
		{"0.5,1.5,2.5", []float64{0.5, 1.5, 2.5}},
	}
	for _, tc := range goodInputs {
		got, err := parseLatencyBuckets(tc.input)
		if err != nil {
			t.Errorf("parseLatencyBuckets(%q) returned an unexpected error: %v", tc.input, err)
		}
		if !reflect.DeepEqual(got, tc.expected) {
			t.Errorf("parseLatencyBuckets(%q) = %v, expected %v", tc.input, got, tc.expected)
		}
	}
}

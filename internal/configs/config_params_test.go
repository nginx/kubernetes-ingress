package configs

import (
	"context"
	"testing"
)

func TestNewDefaultConfigParamsUpstreamZoneSize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		isPlus   bool
		expected string
	}{
		{
			isPlus:   false,
			expected: "256k",
		},
		{
			isPlus:   true,
			expected: "512k",
		},
	}

	for _, test := range tests {
		cfgParams := NewDefaultConfigParams(context.Background(), test.isPlus)
		if cfgParams == nil {
			t.Fatalf("NewDefaultConfigParams(context.Background(), %v) returned nil", test.isPlus)
		}

		if cfgParams.UpstreamZoneSize != test.expected {
			t.Errorf("NewDefaultConfigParams(context.Background(), %v) returned %s but expected %s", test.isPlus, cfgParams.UpstreamZoneSize, test.expected)
		}
	}
}

package validation

import (
	"fmt"
	"testing"

	conf_v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"github.com/stretchr/testify/assert"
)

func TestNewSizeWithUnit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sizeStr string
		want    string
		wantErr bool
	}{
		{
			name:    "empty string gets an empty response",
			sizeStr: "",
			want:    "",
			wantErr: false,
		},
		{
			name:    "invalid non-numeric string",
			sizeStr: "invalid",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric string with whitespace",
			sizeStr: "  invalid  value ",
			want:    "",
			wantErr: true,
		},
		{
			name:    "size without unit will be assumed to be mb",
			sizeStr: "1024",
			want:    "1024m",
			wantErr: false,
		},
		{
			name:    "valid size with k unit",
			sizeStr: "4k",
			want:    "4k",
			wantErr: false,
		},
		{
			name:    "valid size with m unit",
			sizeStr: "2m",
			want:    "2m",
			wantErr: false,
		},
		{
			name:    "invalid size with g unit to be replaced with m",
			sizeStr: "1g",
			want:    "1m",
			wantErr: false,
		},
		{
			name:    "valid size with uppercase unit",
			sizeStr: "8K",
			want:    "8k",
			wantErr: false,
		},
		{
			name:    "valid size with whitespace",
			sizeStr: "  16m  ",
			want:    "16m",
			wantErr: false,
		},
		{
			name:    "valid size with invalid unit replaced with m",
			sizeStr: "32x",
			want:    "32m",
			wantErr: false,
		},
		{
			name:    "invalid negative size",
			sizeStr: "-4k",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid non-integer size",
			sizeStr: "4.5m",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid size exceeding uint64",
			sizeStr: "18446744073709551616k", // 1 more than max uint64
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid size with unit because zero",
			sizeStr: "0k",
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewSizeWithUnit(tt.sizeStr, true)
			if (err != nil) != tt.wantErr {
				t.Errorf("Newvalidation.SizeWithUnit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != tt.want {
				t.Errorf("Newvalidation.SizeWithUnit() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewNumberSizeConfig(t *testing.T) {
	tests := []struct {
		name    string
		sizeStr string
		want    string
		wantErr bool
	}{
		{
			name:    "valid number and size with k unit",
			sizeStr: "8 4k",
			want:    "8 4k",
			wantErr: false,
		},
		{
			name:    "valid number and size with m unit",
			sizeStr: "10 2m",
			want:    "10 2m",
			wantErr: false,
		},
		{
			name:    "valid number and size with g unit, replaced with m",
			sizeStr: "3 1g",
			want:    "3 1m",
			wantErr: false,
		},
		{
			name:    "zero number gets parsed as 0",
			sizeStr: "0 4k",
			want:    "0 4k",
			wantErr: false,
		},
		{
			name:    "valid number with invalid size unit, replaced with m",
			sizeStr: "5 4x",
			want:    "5 4m",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := newNumberSizeConfig(tt.sizeStr, true)
			if (err != nil) != tt.wantErr {
				t.Errorf("Newvalidation.NumberSizeConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Newvalidation.NumberSizeConfig() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBalanceProxyValues(t *testing.T) {
	type args struct {
		proxyBuffers         string
		proxyBufferSize      string
		proxyBusyBuffersSize string
	}
	tests := []struct {
		name                    string
		args                    args
		wantProxyBuffers        string
		wantProxyBufferSize     string
		wantProxyBusyBufferSize string
		wantErr                 bool
	}{
		{
			name:    "All empty",
			wantErr: false,
		},

		{
			name: "only proxy_buffer_size is defined",
			args: args{
				proxyBufferSize: "4k",
			},
			wantProxyBuffers:        "2 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "4k",
			wantErr:                 false,
		},

		{
			name: "only proxy_buffers is defined",
			args: args{
				proxyBuffers: "4 16k",
			},
			wantProxyBuffers:        "4 16k",
			wantProxyBufferSize:     "16k",
			wantProxyBusyBufferSize: "16k",
			wantErr:                 false,
		},

		{
			name: "Invalid combination that should correct itself",
			args: args{
				proxyBuffers:    "8 1m",
				proxyBufferSize: "5m",
			},
			wantProxyBuffers:        "8 1m",
			wantProxyBufferSize:     "5m",
			wantProxyBusyBufferSize: "5m",
			wantErr:                 false,
		},

		{
			name: "Buffer-size smaller than individual buffer size",
			args: args{
				proxyBuffers:    "4 1m",
				proxyBufferSize: "512k",
			},
			wantProxyBuffers:        "4 1m",
			wantProxyBufferSize:     "512k",
			wantProxyBusyBufferSize: "1m",
		},

		{
			name: "Minimum buffers configuration",
			args: args{
				proxyBuffers:    "2 4k",
				proxyBufferSize: "4k",
			},
			wantProxyBuffers:        "2 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "4k",
			wantErr:                 false,
		},

		{
			name: "All three parameters set",
			args: args{
				proxyBuffers:         "8 4k",
				proxyBufferSize:      "4k",
				proxyBusyBuffersSize: "16k",
			},
			wantProxyBuffers:        "8 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "16k",
			wantErr:                 false,
		},

		{
			name: "Busy buffer too large  - reduces in size",
			args: args{
				proxyBuffers:         "4 8k",
				proxyBufferSize:      "8k",
				proxyBusyBuffersSize: "40k",
			},
			wantProxyBuffers:        "4 8k",
			wantProxyBufferSize:     "8k",
			wantProxyBusyBufferSize: "24k",
			wantErr:                 false,
		},

		{
			name: "Empty/zero values - corrected to minimum",
			args: args{
				proxyBuffers: "0 4k",
			},
			wantProxyBuffers:        "2 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "4k",
			wantErr:                 false,
		},

		{
			name: "Extreme values - autocorrect",
			args: args{
				proxyBuffers:    "1000000 1k",
				proxyBufferSize: "999m",
			},
			wantProxyBuffers:        "1024 1k",
			wantProxyBufferSize:     "1023k",
			wantProxyBusyBufferSize: "1023k",
			wantErr:                 false,
		},

		{
			name: "Autocorrect buffer size and buffers",
			args: args{
				proxyBuffers:    "8 4k",
				proxyBufferSize: "64k",
			},
			wantProxyBuffers:        "8 4k",
			wantProxyBufferSize:     "28k",
			wantProxyBusyBufferSize: "28k",
			wantErr:                 false,
		},

		{
			name: "Buffer size with busy buffer calculates minimum buffers",
			args: args{
				proxyBufferSize:      "4k",
				proxyBusyBuffersSize: "20k",
			},
			wantProxyBuffers:        "2 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "4k",
			wantErr:                 false,
		},

		{
			name: "Single buffer corrected to minimum count",
			args: args{
				proxyBuffers: "1 2k",
			},
			wantProxyBuffers:        "2 2k",
			wantProxyBufferSize:     "2k",
			wantProxyBusyBufferSize: "2k",
			wantErr:                 false,
		},

		{
			name: "Single buffer with larger buffer size gets corrected",
			args: args{
				proxyBuffers:    "1 2k",
				proxyBufferSize: "8k",
			},
			wantProxyBuffers:        "2 2k",
			wantProxyBufferSize:     "2k",
			wantProxyBusyBufferSize: "2k",
			wantErr:                 false,
		},

		{
			name: "Zero buffers corrected to minimum 2",
			args: args{
				proxyBuffers: "0 4k",
			},
			wantProxyBuffers:        "2 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "4k",
			wantErr:                 false,
		},

		{
			name: "Large buffer count unchanged",
			args: args{
				proxyBuffers: "16 1k",
			},
			wantProxyBuffers:        "16 1k",
			wantProxyBufferSize:     "1k",
			wantProxyBusyBufferSize: "1k",
			wantErr:                 false,
		},

		{
			name: "Only busy buffer size set",
			args: args{
				proxyBusyBuffersSize: "8k",
			},
			wantProxyBuffers:        "2 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "4k",
			wantErr:                 false,
		},

		{
			name: "Very small buffers with large buffer size",
			args: args{
				proxyBuffers:    "2 1k",
				proxyBufferSize: "2k",
			},
			wantProxyBuffers:        "2 1k",
			wantProxyBufferSize:     "1k",
			wantProxyBusyBufferSize: "1k",
			wantErr:                 false,
		},

		{
			name: "Busy buffer exactly at limit",
			args: args{
				proxyBuffers:         "4 4k",
				proxyBusyBuffersSize: "12k",
			},
			wantProxyBuffers:        "4 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "12k",
			wantErr:                 false,
		},

		{
			name: "Busy buffer too small - gets adjusted",
			args: args{
				proxyBuffers:         "4 8k",
				proxyBufferSize:      "16k",
				proxyBusyBuffersSize: "4k",
			},
			wantProxyBuffers:        "4 8k",
			wantProxyBufferSize:     "16k",
			wantProxyBusyBufferSize: "16k",
			wantErr:                 false,
		},
		// no no no no
		{
			name: "Both buffers and buffer-size set",
			args: args{
				proxyBuffers:    "4 16k",
				proxyBufferSize: "8k",
			},
			wantProxyBuffers:        "4 16k",
			wantProxyBufferSize:     "8k",
			wantProxyBusyBufferSize: "16k",
			wantErr:                 false,
		},

		{
			name: "proxy_buffers empty, others aren't, fix proxy_buffers, adjust everything too",
			args: args{
				proxyBufferSize:      "8k",
				proxyBusyBuffersSize: "16k",
			},
			wantProxyBuffers:        "2 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "4k",
			wantErr:                 false,
		},
		{
			name: "proxy_buffers is too small, but valid",
			args: args{
				proxyBuffers:         "24 1k",
				proxyBufferSize:      "32k",
				proxyBusyBuffersSize: "64k",
			},
			wantProxyBuffers:        "24 1k",
			wantProxyBufferSize:     "23k",
			wantProxyBusyBufferSize: "23k",
			wantErr:                 false,
		},
		{
			name: "trio should pass unchanged",
			args: args{
				proxyBuffers:         "8 4k",
				proxyBufferSize:      "8k",
				proxyBusyBuffersSize: "16k",
			},
			wantProxyBuffers:        "8 4k",
			wantProxyBufferSize:     "8k",
			wantProxyBusyBufferSize: "16k",
			wantErr:                 false,
		},
		{
			name: "proxy_busy_buffers is in MB",
			args: args{
				proxyBuffers:         "8 4k",
				proxyBufferSize:      "4k",
				proxyBusyBuffersSize: "1m",
			},
			wantProxyBuffers:        "8 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "28k",
			wantErr:                 false,
		},

		{
			name: "proxy busy buffers ends up as 1k even though it should not",
			args: args{
				proxyBuffers:    "4 2k",
				proxyBufferSize: "2k",
			},
			wantProxyBuffers:        "4 2k",
			wantProxyBufferSize:     "2k",
			wantProxyBusyBufferSize: "2k",
			wantErr:                 false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb, err := newNumberSizeConfig(tt.args.proxyBuffers, true)
			if err != nil {
				t.Fatalf("Failed to parse proxyBuffers: %v", err)
			}

			pbs, err := NewSizeWithUnit(tt.args.proxyBufferSize, true)
			if err != nil {
				t.Fatalf("Failed to parse proxyBufferSize: %v", err)
			}

			pbbs, err := NewSizeWithUnit(tt.args.proxyBusyBuffersSize, true)
			if err != nil {
				t.Fatalf("Failed to parse proxyBusyBuffers: %v", err)
			}

			gotProxyBuffers, gotProxyBufferSize, gotProxyBusyBufferSize, m, err := BalanceProxyValues(pb, pbs, pbbs, true)

			assert.NoError(t, err)

			for _, mm := range m {
				t.Logf("Modification: %s", mm)
			}

			assert.Equalf(t, tt.wantProxyBuffers, gotProxyBuffers, "proxy buffers, want: %s, got: %s", tt.wantProxyBuffers, gotProxyBuffers)
			assert.Equalf(t, tt.wantProxyBufferSize, gotProxyBufferSize, "proxy_buffer_size, want: %s, got: %s", tt.wantProxyBufferSize, gotProxyBufferSize)
			assert.Equalf(t, tt.wantProxyBusyBufferSize, gotProxyBusyBufferSize, "proxy_busy_buffers_size, want: %s, got: %s", tt.wantProxyBusyBufferSize, gotProxyBusyBufferSize)
		})
	}
}

func TestBalanceProxiesForUpstreams(t *testing.T) {
	tests := []struct {
		name                    string
		upstream                *conf_v1.Upstream
		autoadjust              bool
		wantProxyBuffers        string
		wantProxyBufferSize     string
		wantProxyBusyBufferSize string
		wantErr                 bool
	}{
		{
			name: "nil ProxyBuffers - no changes",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: nil,
			},
			autoadjust: true,
			wantErr:    false,
		},
		{
			name: "valid configuration unchanged",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 8,
					Size:   "4k",
				},
				ProxyBufferSize:      "4k",
				ProxyBusyBuffersSize: "16k",
			},
			autoadjust:              true,
			wantProxyBuffers:        "8 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "16k",
			wantErr:                 false,
		},
		{
			name: "invalid proxy buffers get default values",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 0,
					Size:   "invalid",
				},
				ProxyBufferSize:      "invalid",
				ProxyBusyBuffersSize: "invalid",
			},
			autoadjust:              true,
			wantProxyBuffers:        "8 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "4k",
			wantErr:                 false,
		},
		{
			name: "minimum buffer count enforced",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 1,
					Size:   "8k",
				},
				ProxyBufferSize:      "8k",
				ProxyBusyBuffersSize: "16k",
			},
			autoadjust:              true,
			wantProxyBuffers:        "2 8k",
			wantProxyBufferSize:     "8k",
			wantProxyBusyBufferSize: "8k",
			wantErr:                 false,
		},
		{
			name: "maximum buffer count enforced",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 2000,
					Size:   "4k",
				},
				ProxyBufferSize:      "4k",
				ProxyBusyBuffersSize: "8k",
			},
			autoadjust:              true,
			wantProxyBuffers:        "1024 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "8k",
			wantErr:                 false,
		},
		{
			name: "proxy buffer size too large gets adjusted",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 4,
					Size:   "4k",
				},
				ProxyBufferSize:      "32k",
				ProxyBusyBuffersSize: "8k",
			},
			autoadjust:              true,
			wantProxyBuffers:        "4 4k",
			wantProxyBufferSize:     "12k",
			wantProxyBusyBufferSize: "12k",
			wantErr:                 false,
		},
		{
			name: "proxy busy buffer size too large gets adjusted",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 4,
					Size:   "8k",
				},
				ProxyBufferSize:      "8k",
				ProxyBusyBuffersSize: "64k",
			},
			autoadjust:              true,
			wantProxyBuffers:        "4 8k",
			wantProxyBufferSize:     "8k",
			wantProxyBusyBufferSize: "24k",
			wantErr:                 false,
		},
		{
			name: "proxy busy buffer size too small gets adjusted",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 8,
					Size:   "4k",
				},
				ProxyBufferSize:      "8k",
				ProxyBusyBuffersSize: "2k",
			},
			autoadjust:              true,
			wantProxyBuffers:        "8 4k",
			wantProxyBufferSize:     "8k",
			wantProxyBusyBufferSize: "8k",
			wantErr:                 false,
		},
		{
			name: "empty proxy buffer size gets set to proxy buffers size",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 6,
					Size:   "16k",
				},
				ProxyBufferSize:      "",
				ProxyBusyBuffersSize: "32k",
			},
			autoadjust:              true,
			wantProxyBuffers:        "6 16k",
			wantProxyBufferSize:     "16k",
			wantProxyBusyBufferSize: "32k",
			wantErr:                 false,
		},
		{
			name: "autoadjust disabled - no changes to valid configuration",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 8,
					Size:   "4k",
				},
				ProxyBufferSize:      "4k",
				ProxyBusyBuffersSize: "16k",
			},
			autoadjust:              false,
			wantProxyBuffers:        "8 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "16k",
			wantErr:                 false,
		},
		{
			name: "autoadjust disabled - invalid buffer count unchanged",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 1,
					Size:   "8k",
				},
				ProxyBufferSize:      "8k",
				ProxyBusyBuffersSize: "16k",
			},
			autoadjust:              false,
			wantProxyBuffers:        "1 8k",
			wantProxyBufferSize:     "8k",
			wantProxyBusyBufferSize: "16k",
			wantErr:                 false,
		},
		{
			name: "autoadjust disabled - oversized buffer size unchanged",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 4,
					Size:   "4k",
				},
				ProxyBufferSize:      "64k",
				ProxyBusyBuffersSize: "8k",
			},
			autoadjust:              false,
			wantProxyBuffers:        "4 4k",
			wantProxyBufferSize:     "64k",
			wantProxyBusyBufferSize: "8k",
			wantErr:                 false,
		},
		{
			name: "autoadjust disabled - undersized busy buffer unchanged",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 8,
					Size:   "4k",
				},
				ProxyBufferSize:      "8k",
				ProxyBusyBuffersSize: "2k",
			},
			autoadjust:              false,
			wantProxyBuffers:        "8 4k",
			wantProxyBufferSize:     "8k",
			wantProxyBusyBufferSize: "2k",
			wantErr:                 false,
		},
		{
			name: "autoadjust disabled - oversized busy buffer unchanged",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 4,
					Size:   "8k",
				},
				ProxyBufferSize:      "8k",
				ProxyBusyBuffersSize: "64k",
			},
			autoadjust:              false,
			wantProxyBuffers:        "4 8k",
			wantProxyBufferSize:     "8k",
			wantProxyBusyBufferSize: "64k",
			wantErr:                 false,
		},
		{
			name: "autoadjust disabled - zero buffer count unchanged",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 0,
					Size:   "4k",
				},
				ProxyBufferSize:      "4k",
				ProxyBusyBuffersSize: "8k",
			},
			autoadjust:              false,
			wantProxyBuffers:        "0 4k",
			wantProxyBufferSize:     "4k",
			wantProxyBusyBufferSize: "8k",
			wantErr:                 false,
		},
		{
			name: "autoadjust disabled - extreme buffer count unchanged",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 2000,
					Size:   "1k",
				},
				ProxyBufferSize:      "1k",
				ProxyBusyBuffersSize: "2k",
			},
			autoadjust:              false,
			wantProxyBuffers:        "2000 1k",
			wantProxyBufferSize:     "1k",
			wantProxyBusyBufferSize: "2k",
			wantErr:                 false,
		},
		{
			name: "autoadjust disabled - empty buffer size unchanged",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 6,
					Size:   "16k",
				},
				ProxyBufferSize:      "",
				ProxyBusyBuffersSize: "32k",
			},
			autoadjust:              false,
			wantProxyBuffers:        "6 16k",
			wantProxyBufferSize:     "",
			wantProxyBusyBufferSize: "32k",
			wantErr:                 false,
		},
		{
			name: "autoadjust disabled - invalid size values get defaults but no balancing",
			upstream: &conf_v1.Upstream{
				ProxyBuffers: &conf_v1.UpstreamBuffers{
					Number: 0,
					Size:   "invalid",
				},
				ProxyBufferSize:      "invalid",
				ProxyBusyBuffersSize: "invalid",
			},
			autoadjust:              false,
			wantProxyBuffers:        "0 invalid",
			wantProxyBufferSize:     "invalid",
			wantProxyBusyBufferSize: "invalid",
			wantErr:                 false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := BalanceProxiesForUpstreams(tt.upstream, tt.autoadjust)

			if (err != nil) != tt.wantErr {
				t.Errorf("BalanceProxiesForUpstreams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.upstream.ProxyBuffers != nil {
				gotProxyBuffers := fmt.Sprintf("%d %s", tt.upstream.ProxyBuffers.Number, tt.upstream.ProxyBuffers.Size)
				if tt.wantProxyBuffers != "" {
					assert.Equal(t, tt.wantProxyBuffers, gotProxyBuffers, "proxy buffers mismatch")
				}
			}

			if tt.wantProxyBufferSize != "" {
				assert.Equal(t, tt.wantProxyBufferSize, tt.upstream.ProxyBufferSize, "proxy buffer size mismatch")
			}

			if tt.wantProxyBusyBufferSize != "" {
				assert.Equal(t, tt.wantProxyBusyBufferSize, tt.upstream.ProxyBusyBuffersSize, "proxy busy buffer size mismatch")
			}
		})
	}
}

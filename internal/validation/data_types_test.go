package validation_test

import (
	"testing"

	"github.com/nginx/kubernetes-ingress/internal/validation"
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
			name:    "invalid empty string",
			sizeStr: "",
			want:    "",
			wantErr: true,
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

			got, err := validation.NewSizeWithUnit(tt.sizeStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("Newvalidation.SizeWithUnit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got.String() != tt.want {
				t.Errorf("Newvalidation.SizeWithUnit() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewNumberSizeConfig(t *testing.T) {
	tests := []struct {
		name    string
		sizeStr string
		want    validation.NumberSizeConfig
		wantErr bool
	}{
		{
			name:    "valid number and size with k unit",
			sizeStr: "8 4k",
			want: validation.NumberSizeConfig{
				Number: 8,
				Size:   validation.SizeWithUnit{Size: 4, Unit: validation.SizeKB},
			},
			wantErr: false,
		},
		{
			name:    "valid number and size with m unit",
			sizeStr: "10 2m",
			want: validation.NumberSizeConfig{
				Number: 10,
				Size:   validation.SizeWithUnit{Size: 2, Unit: validation.SizeMB},
			},
			wantErr: false,
		},
		{
			name:    "valid number and size with g unit, replaced with m",
			sizeStr: "3 1g",
			want: validation.NumberSizeConfig{
				Number: 3,
				Size:   validation.SizeWithUnit{Size: 1, Unit: validation.SizeMB},
			},
			wantErr: false,
		},
		{
			name:    "invalid zero number with valid size",
			sizeStr: "0 4k",
			want:    validation.NumberSizeConfig{},
			wantErr: true,
		},
		{
			name:    "valid number with invalid size unit, replaced with m",
			sizeStr: "5 4x",
			want: validation.NumberSizeConfig{
				Number: 5,
				Size: validation.SizeWithUnit{
					Size: 4,
					Unit: validation.SizeMB,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validation.NewNumberSizeConfig(tt.sizeStr)
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

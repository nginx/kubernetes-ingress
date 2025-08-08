package version2

import (
	"testing"
)

func TestNewSizeWithUnit(t *testing.T) {
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
			name:    "invalid size without unit",
			sizeStr: "1024",
			want:    "",
			wantErr: true,
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
			name:    "valid size with g unit",
			sizeStr: "1g",
			want:    "1g",
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
			name:    "invalid size with invalid unit",
			sizeStr: "32x",
			want:    "",
			wantErr: true,
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
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSizeWithUnit(tt.sizeStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSizeWithUnit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got.String() != tt.want {
				t.Errorf("NewSizeWithUnit() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewNumberSizeConfig(t *testing.T) {
	tests := []struct {
		name    string
		sizeStr string
		want    NumberSizeConfig
		wantErr bool
	}{
		{
			name:    "valid number and size with k unit",
			sizeStr: "8 4k",
			want: NumberSizeConfig{
				Number: 8,
				Size:   SizeWithUnit{Size: 4, Unit: SizeKB},
			},
			wantErr: false,
		},
		{
			name:    "valid number and size with m unit",
			sizeStr: "10 2m",
			want: NumberSizeConfig{
				Number: 10,
				Size:   SizeWithUnit{Size: 2, Unit: SizeMB},
			},
			wantErr: false,
		},
		{
			name:    "valid number and size with g unit",
			sizeStr: "3 1g",
			want: NumberSizeConfig{
				Number: 3,
				Size:   SizeWithUnit{Size: 1, Unit: SizeGB},
			},
			wantErr: false,
		},
		{
			name:    "invalid zero number with valid size",
			sizeStr: "0 4k",
			want:    NumberSizeConfig{},
			wantErr: true,
		},
		{
			name:    "valid number with invalid size unit",
			sizeStr: "5 4x",
			want:    NumberSizeConfig{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewNumberSizeConfig(tt.sizeStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewNumberSizeConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NewNumberSizeConfig() got = %v, want %v", got, tt.want)
			}
		})
	}
}

package validation_test

import (
	"errors"
	"testing"

	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/externaldns/v1"
	"github.com/nginx/kubernetes-ingress/pkg/apis/externaldns/validation"
)

func TestValidateDNSEndpoint(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name     string
		endpoint v1.DNSEndpoint
	}{
		{
			name: "with a single valid endpoint",
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"10.2.2.3"},
							RecordType: "A",
							RecordTTL:  600,
						},
					},
				},
			},
		},
		{
			name: "with a single IPv6 target",
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"2001:db8:0:0:0:0:2:1"},
							RecordType: "A",
							RecordTTL:  600,
						},
					},
				},
			},
		},
		{
			name: "with multiple valid endpoints",
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"10.2.2.3"},
							RecordType: "A",
							RecordTTL:  600,
						},
						{
							DNSName:    "example.co.uk",
							Targets:    v1.Targets{"10.2.2.3"},
							RecordType: "CNAME",
							RecordTTL:  900,
						},
						{
							DNSName:    "example.ie",
							Targets:    v1.Targets{"2001:db8:0:0:0:0:2:1"},
							RecordType: "AAAA",
							RecordTTL:  900,
						},
					},
				},
			},
		},
		{
			name: "with multiple valid endpoints and multiple targets",
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"example.ie", "example.io"},
							RecordType: "CNAME",
							RecordTTL:  600,
						},
						{
							DNSName:    "example.co.uk",
							Targets:    v1.Targets{"10.2.2.3", "192.123.23.4"},
							RecordType: "A",
							RecordTTL:  900,
						},
					},
				},
			},
		},
	}

	for _, tc := range tt {
		tc := tc // address gosec G601
		t.Run(tc.name, func(t *testing.T) {
			if err := validation.ValidateDNSEndpoint(&tc.endpoint); err != nil {
				t.Errorf("want no error on %v, got %v", tc.endpoint, err)
			}
		})
	}
}

func TestValidateDNSEndpoint_ReturnsErrorOn(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name     string
		want     error
		endpoint v1.DNSEndpoint
	}{
		{
			name: "not supported DNS record type",
			want: validation.ErrTypeNotSupported,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"10.2.2.3"},
							RecordType: "bogusRecordType",
							RecordTTL:  600,
						},
					},
				},
			},
		},
		{
			name: "bogus target hostname",
			want: validation.ErrTypeInvalid,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"bogusTargetName"},
							RecordType: "A",
							RecordTTL:  600,
						},
					},
				},
			},
		},
		{
			name: "bogus target IPv6 address",
			want: validation.ErrTypeInvalid,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"2001:::0:0:0:0:2:1"},
							RecordType: "A",
							RecordTTL:  600,
						},
					},
				},
			},
		},
		{
			name: "duplicated target",
			want: validation.ErrTypeDuplicated,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"acme.com", "10.2.2.3", "acme.com"},
							RecordType: "A",
							RecordTTL:  600,
						},
					},
				},
			},
		},
		{
			name: "bogus ttl record",
			want: validation.ErrTypeNotInRange,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"10.2.2.3", "acme.com"},
							RecordType: "A",
							RecordTTL:  -1,
						},
					},
				},
			},
		},
		{
			name: "bogus dns name",
			want: validation.ErrTypeInvalid,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "bogusDNSName",
							Targets:    v1.Targets{"acme.com"},
							RecordType: "A",
							RecordTTL:  1800,
						},
					},
				},
			},
		},
		{
			name: "empty dns name",
			want: validation.ErrTypeInvalid,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "",
							Targets:    v1.Targets{"acme.com"},
							RecordType: "A",
							RecordTTL:  1800,
						},
					},
				},
			},
		},
		{
			name: "bogus target name",
			want: validation.ErrTypeInvalid,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"acme."},
							RecordType: "A",
							RecordTTL:  1800,
						},
					},
				},
			},
		},
		{
			name: "empty target name",
			want: validation.ErrTypeInvalid,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{""},
							RecordType: "A",
							RecordTTL:  1800,
						},
					},
				},
			},
		},
		{
			name: "bogus target name",
			want: validation.ErrTypeInvalid,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{
						{
							DNSName:    "example.com",
							Targets:    v1.Targets{"&$$.*&^"},
							RecordType: "A",
							RecordTTL:  1800,
						},
					},
				},
			},
		},
		{
			name: "empty slice of endpoints",
			want: validation.ErrTypeRequired,
			endpoint: v1.DNSEndpoint{
				Spec: v1.DNSEndpointSpec{
					Endpoints: []*v1.Endpoint{},
				},
			},
		},
	}

	for _, tc := range tt {
		tc := tc // address gosec G601
		t.Run(tc.name, func(t *testing.T) {
			err := validation.ValidateDNSEndpoint(&tc.endpoint)
			if !errors.Is(err, tc.want) {
				t.Errorf("want %s, got %v", tc.want, err)
			}
		})
	}
}

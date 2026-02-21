package validation

import (
	"strings"
	"testing"

	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidatePolicy_JWTIsNotValidOn(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name   string
		policy *v1.Policy
	}{
		{
			name: "missing realm when using secret",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:  "",
						Secret: "my-jwk",
					},
				},
			},
		},
		{
			name: "missing realm when using jwks from remote location",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:    "",
						JwksURI:  "https://mystore-jsonwebkeys.com",
						KeyCache: "1h",
					},
				},
			},
		},
		{
			name: "missing secret and Jwks at the same time",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm: "my-realm",
					},
				},
			},
		},
		{
			name: "provided both Secret and JWKs at the same time",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:   "my-realm",
						Secret:  "my-secret",
						JwksURI: "https://mystore-jsonwebkey.com",
					},
				},
			},
		},

		{
			name: "keyCache must not be present when using Secret",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:    "My Product API",
						Secret:   "my-jwk",
						KeyCache: "1h",
					},
				},
			},
		},
		{
			name: "invalid keyCache time syntax",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:    "My Product API",
						JwksURI:  "https://myjwksuri.com",
						KeyCache: "bogus-time-value",
					},
				},
			},
		},
		{
			name: "missing keyCache when using JWKS",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:   "My Product API",
						JwksURI: "https://myjwksuri.com",
					},
				},
			},
		},
		{
			name: "If JwksURI is not set, then none of the SNI fields should be set.",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:      "My Product API",
						Secret:     "my-jwk",
						KeyCache:   "1h",
						SNIName:    "ipd.org",
						SNIEnabled: true,
					},
				},
			},
		},
		{
			name: "SNI server name passed, but SNI not enabled",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:    "My Product API",
						JwksURI:  "https://myjwksuri.com",
						KeyCache: "1h",
						SNIName:  "ipd.org",
					},
				},
			},
		},
		{
			name: "SNI server name passed, SNI enabled, bad SNI server name",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:      "My Product API",
						JwksURI:    "https://myjwksuri.com",
						KeyCache:   "1h",
						SNIEnabled: true,
						SNIName:    "msql://ipd.org",
					},
				},
			},
		},
		{
			name: "SNI enabled, but no JwksURI",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:      "My Product API",
						Token:      "$cookie_auth_token",
						SNIEnabled: true,
					},
				},
			},
		},
		{
			name: "Jwks URI not set, but SNIName is set",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:   "My Product API",
						Token:   "$cookie_auth_token",
						SNIName: "https://idp.com",
					},
				},
			},
		},
		{
			name: "Jwks URI not set, Secret set, but SNIName is set and SNI is enabled",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:      "My Product API",
						Token:      "$cookie_auth_token",
						Secret:     "my-jwk",
						SNIName:    "https://idp.com",
						SNIEnabled: true,
					},
				},
			},
		},
		{
			name: "Jwks URI not set, SNIName set, but SNI is not enabled",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:   "My Product API",
						Token:   "$cookie_auth_token",
						Secret:  "my-jwk",
						SNIName: "https://idp.com",
					},
				},
			},
		},
		{
			name: "SSL verification enabled but no trusted cert secret",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:     "My Product API",
						JwksURI:   "https://myjwksuri.com",
						KeyCache:  "1h",
						SSLVerify: true,
					},
				},
			},
		},
		{
			name: "Trusted cert secret provided but SSL verification disabled",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:             "My Product API",
						JwksURI:           "https://myjwksuri.com",
						KeyCache:          "1h",
						SSLVerify:         false,
						TrustedCertSecret: "my-ca-secret",
					},
				},
			},
		},
		{
			name: "Invalid SSL verify depth",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:             "My Product API",
						JwksURI:           "https://myjwksuri.com",
						KeyCache:          "1h",
						SSLVerify:         true,
						TrustedCertSecret: "my-ca-secret",
						SSLVerifyDepth:    new(0),
					},
				},
			},
		},
		{
			name: "Invalid trusted cert secret name with special characters",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:             "My Product API",
						JwksURI:           "https://myjwksuri.com",
						KeyCache:          "1h",
						SSLVerify:         true,
						TrustedCertSecret: "my-ca-secret.invalid!",
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePolicy(tc.policy, PolicyValidationConfig{
				IsPlus: true,
			})
			if err == nil {
				t.Errorf("got no errors on invalid JWTAuth policy spec input")
			}
		})
	}
}

func TestValidatePolicy_IsValidOnJWTPolicy(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name   string
		policy *v1.Policy
	}{
		{
			name: "with Secret and Token",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:  "My Product API",
						Secret: "my-secret",
						Token:  "$http_token",
					},
				},
			},
		},
		{
			name: "with Secret and without Token",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:  "My Product API",
						Secret: "my-jwk",
					},
				},
			},
		},
		{
			name: "with JWKS and Token",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:    "My Product API",
						KeyCache: "1h",
						JwksURI:  "https://login.mydomain.com/keys",
						Token:    "$http_token",
					},
				},
			},
		},
		{
			name: "with JWKS and without Token",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:    "My Product API",
						KeyCache: "1h",
						JwksURI:  "https://login.mydomain.com/keys",
					},
				},
			},
		},
		{
			name: "with SNI and without SNI server name",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:      "My Product API",
						KeyCache:   "1h",
						JwksURI:    "https://login.mydomain.com/keys",
						SNIEnabled: true,
					},
				},
			},
		},
		{
			name: "with SNI and with SNI server name",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:      "My Product API",
						KeyCache:   "1h",
						JwksURI:    "https://login.mydomain.com/keys",
						SNIEnabled: true,
						SNIName:    "https://example.org",
					},
				},
			},
		},
		{
			name: "with SSL verification and trusted cert secret",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:             "My Product API",
						KeyCache:          "1h",
						JwksURI:           "https://login.mydomain.com/keys",
						SSLVerify:         true,
						TrustedCertSecret: "my-ca-secret",
					},
				},
			},
		},
		{
			name: "with SSL verification and custom verify depth",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:             "My Product API",
						KeyCache:          "1h",
						JwksURI:           "https://login.mydomain.com/keys",
						SSLVerify:         true,
						TrustedCertSecret: "my-ca-secret",
						SSLVerifyDepth:    new(2),
					},
				},
			},
		},
		{
			name: "with SSL verification and SNI",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:             "My Product API",
						KeyCache:          "1h",
						JwksURI:           "https://login.mydomain.com/keys",
						SSLVerify:         true,
						TrustedCertSecret: "my-ca-secret",
						SNIEnabled:        true,
						SNIName:           "login.mydomain.com",
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePolicy(tc.policy, PolicyValidationConfig{
				IsPlus: true,
			})
			if err != nil {
				t.Errorf("want no errors, got %+v\n", err)
			}
		})
	}
}

func TestValidatePolicy_RequiresKeyCacheValueForJWTPolicy(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name   string
		policy *v1.Policy
	}{
		{
			name: "keyCache in hours",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:    "My Product API",
						JwksURI:  "https://foo.bar/certs",
						KeyCache: "1h",
					},
				},
			},
		},
		{
			name: "keyCache in minutes",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:    "My Product API",
						JwksURI:  "https://foo.bar/certs",
						KeyCache: "120m",
					},
				},
			},
		},
		{
			name: "keyCache in seconds",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:    "My Product API",
						JwksURI:  "https://foo.bar/certs",
						KeyCache: "60000s",
					},
				},
			},
		},
		{
			name: "keyCache in days",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:    "My Product API",
						JwksURI:  "https://foo.bar/certs",
						KeyCache: "3d",
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePolicy(tc.policy, PolicyValidationConfig{
				IsPlus: true,
			})
			if err != nil {
				t.Errorf("got error on valid JWT policy: %+v\n", err)
			}
			t.Log(err)
		})
	}
}

func TestValidatePolicy_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		policy *v1.Policy
		cfg    PolicyValidationConfig
		msg    string
	}{
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					AccessControl: &v1.AccessControl{
						Allow: []string{"127.0.0.1"},
					},
				},
			},
			cfg: PolicyValidationConfig{},
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:  "My Product API",
						Secret: "my-jwk",
					},
				},
			},
			cfg: PolicyValidationConfig{IsPlus: true},
			msg: "use jwt(plus only) policy",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					OIDC: &v1.OIDC{
						AuthEndpoint:          "https://foo.bar/auth",
						AuthExtraArgs:         []string{"foo=bar"},
						TokenEndpoint:         "https://foo.bar/token",
						JWKSURI:               "https://foo.bar/certs",
						EndSessionEndpoint:    "https://foo.bar/logout",
						PostLogoutRedirectURI: "/_logout",
						RedirectURI:           "/_codexch",
						ClientID:              "random-string",
						ClientSecret:          "random-secret",
						Scope:                 "openid",
						ZoneSyncLeeway:        new(10),
						AccessTokenEnable:     true,
					},
				},
			},
			cfg: PolicyValidationConfig{IsPlus: true, EnableOIDC: true},
			msg: "use OIDC (plus only)",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					WAF: &v1.WAF{
						Enable: true,
					},
				},
			},
			cfg: PolicyValidationConfig{IsPlus: true, EnableAppProtect: true},
			msg: "use WAF(plus only) policy",
		},
	}
	for _, test := range tests {
		err := ValidatePolicy(test.policy, test.cfg)
		if err != nil {
			t.Errorf("ValidatePolicy() returned error %v for valid input for the case of %v", err, test.msg)
		}
	}
}

func TestValidatePolicy_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		policy *v1.Policy
		cfg    PolicyValidationConfig
		msg    string
	}{
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{},
			},
			cfg: PolicyValidationConfig{},
			msg: "empty policy spec",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					AccessControl: &v1.AccessControl{
						Allow: []string{"127.0.0.1"},
					},
					RateLimit: &v1.RateLimit{
						Key:      "${uri}",
						ZoneSize: "10M",
						Rate:     "10r/s",
					},
				},
			},
			cfg: PolicyValidationConfig{IsPlus: true},
			msg: "multiple policies in spec",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					JWTAuth: &v1.JWTAuth{
						Realm:  "My Product API",
						Secret: "my-jwk",
					},
				},
			},
			cfg: PolicyValidationConfig{},
			msg: "jwt(plus only) policy on OSS",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					WAF: &v1.WAF{
						Enable: true,
					},
				},
			},
			cfg: PolicyValidationConfig{},
			msg: "WAF(plus only) policy on OSS",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					OIDC: &v1.OIDC{
						AuthEndpoint:          "https://foo.bar/auth",
						TokenEndpoint:         "https://foo.bar/token",
						JWKSURI:               "https://foo.bar/certs",
						RedirectURI:           "/_codexch",
						EndSessionEndpoint:    "https://foo.bar/logout",
						PostLogoutRedirectURI: "/_logout",
						ClientID:              "random-string",
						ClientSecret:          "random-secret",
						Scope:                 "openid",
						AccessTokenEnable:     true,
					},
				},
			},
			cfg: PolicyValidationConfig{IsPlus: true},
			msg: "OIDC policy with enable OIDC flag disabled",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					OIDC: &v1.OIDC{
						AuthEndpoint:          "https://foo.bar/auth",
						TokenEndpoint:         "https://foo.bar/token",
						JWKSURI:               "https://foo.bar/certs",
						RedirectURI:           "/_codexch",
						EndSessionEndpoint:    "https://foo.bar/logout",
						PostLogoutRedirectURI: "/_logout",
						ClientID:              "random-string",
						ClientSecret:          "random-secret",
						Scope:                 "openid",
						AccessTokenEnable:     true,
					},
				},
			},
			cfg: PolicyValidationConfig{EnableOIDC: true},
			msg: "OIDC policy in OSS",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					WAF: &v1.WAF{
						Enable: true,
					},
				},
			},
			cfg: PolicyValidationConfig{IsPlus: true},
			msg: "WAF policy with AP disabled",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					OIDC: &v1.OIDC{
						AuthEndpoint:          "https://foo.bar/auth",
						TokenEndpoint:         "https://foo.bar/token",
						JWKSURI:               "https://foo.bar/certs",
						RedirectURI:           "/_codexch",
						EndSessionEndpoint:    "https://foo.bar/logout",
						PostLogoutRedirectURI: "/_logout",
						ClientID:              "random-string",
						ClientSecret:          "random-secret",
						Scope:                 "openid",
						ZoneSyncLeeway:        new(-1),
						AccessTokenEnable:     false,
					},
				},
			},
			cfg: PolicyValidationConfig{IsPlus: true, EnableOIDC: true},
			msg: "OIDC policy with invalid ZoneSyncLeeway",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					OIDC: &v1.OIDC{
						AuthEndpoint:          "https://foo.bar/auth",
						AuthExtraArgs:         []string{"foo;bar"},
						TokenEndpoint:         "https://foo.bar/token",
						JWKSURI:               "https://foo.bar/certs",
						RedirectURI:           "/_codexch",
						EndSessionEndpoint:    "https://foo.bar/logout",
						PostLogoutRedirectURI: "/_logout",
						ClientID:              "random-string",
						ClientSecret:          "random-secret",
						Scope:                 "openid",
					},
				},
			},
			cfg: PolicyValidationConfig{IsPlus: true, EnableOIDC: true},
			msg: "OIDC policy with invalid AuthExtraArgs",
		},
	}
	for _, test := range tests {
		err := ValidatePolicy(test.policy, test.cfg)
		if err == nil {
			t.Errorf("ValidatePolicy() returned no error for invalid input")
		}
	}
}

func TestValidateAccessControl_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	validInput := []*v1.AccessControl{
		{
			Allow: []string{},
		},
		{
			Allow: []string{"127.0.0.1"},
		},
		{
			Deny: []string{},
		},
		{
			Deny: []string{"127.0.0.1"},
		},
	}

	for _, input := range validInput {
		allErrs := validateAccessControl(input, field.NewPath("accessControl"))
		if len(allErrs) > 0 {
			t.Errorf("validateAccessControl(%+v) returned errors %v for valid input", input, allErrs)
		}
	}
}

func TestValidateAccessControl_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		accessControl *v1.AccessControl
		msg           string
	}{
		{
			accessControl: &v1.AccessControl{
				Allow: nil,
				Deny:  nil,
			},
			msg: "neither allow nor deny is defined",
		},
		{
			accessControl: &v1.AccessControl{
				Allow: []string{},
				Deny:  []string{},
			},
			msg: "both allow and deny are defined",
		},
		{
			accessControl: &v1.AccessControl{
				Allow: []string{"invalid"},
			},
			msg: "invalid allow",
		},
		{
			accessControl: &v1.AccessControl{
				Deny: []string{"invalid"},
			},
			msg: "invalid deny",
		},
	}

	for _, test := range tests {
		allErrs := validateAccessControl(test.accessControl, field.NewPath("accessControl"))
		if len(allErrs) == 0 {
			t.Errorf("validateAccessControl() returned no errors for invalid input for the case of %s", test.msg)
		}
	}
}

func TestValidateRateLimit_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rateLimit *v1.RateLimit
		isPlus    bool
		msg       string
	}{
		{
			rateLimit: &v1.RateLimit{
				Rate:     "10r/s",
				ZoneSize: "10M",
				Key:      "${request_uri}",
			},
			isPlus: false,
			msg:    "only required fields are set",
		},
		{
			rateLimit: &v1.RateLimit{
				Rate:       "30r/m",
				Key:        "${request_uri}",
				Delay:      new(5),
				NoDelay:    new(false),
				Burst:      new(10),
				ZoneSize:   "10M",
				DryRun:     new(true),
				LogLevel:   "info",
				RejectCode: new(505),
			},
			isPlus: false,
			msg:    "ratelimit all fields set",
		},
		{
			rateLimit: &v1.RateLimit{
				Rate:     "30r/m",
				Key:      "${request_uri}",
				ZoneSize: "10M",
				Condition: &v1.RateLimitCondition{
					JWT: &v1.JWTCondition{
						Claim: "sub",
						Match: "Gold",
					},
					Default: false,
				},
			},
			isPlus: true,
			msg:    "ratelimit JWT Condition",
		},
	}

	for _, test := range tests {
		allErrs := validateRateLimit(test.rateLimit, field.NewPath("rateLimit"), test.isPlus)
		if len(allErrs) > 0 {
			t.Errorf("validateRateLimit() returned errors %v for valid input for the case of %v", allErrs, test.msg)
		}
	}
}

func createInvalidRateLimit(f func(r *v1.RateLimit)) *v1.RateLimit {
	validRateLimit := &v1.RateLimit{
		Rate:     "10r/s",
		ZoneSize: "10M",
		Key:      "${request_uri}",
	}
	f(validRateLimit)
	return validRateLimit
}

func TestValidateRateLimit_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		rateLimit *v1.RateLimit
		isPlus    bool
		msg       string
	}{
		{
			rateLimit: createInvalidRateLimit(func(r *v1.RateLimit) {
				r.Rate = "0r/s"
			}),
			isPlus: false,
			msg:    "invalid rateLimit rate",
		},
		{
			rateLimit: createInvalidRateLimit(func(r *v1.RateLimit) {
				r.Key = "${fail}"
			}),
			isPlus: false,
			msg:    "invalid rateLimit key variable use",
		},
		{
			rateLimit: createInvalidRateLimit(func(r *v1.RateLimit) {
				r.Delay = new(0)
			}),
			isPlus: false,
			msg:    "invalid rateLimit delay",
		},
		{
			rateLimit: createInvalidRateLimit(func(r *v1.RateLimit) {
				r.Burst = new(0)
			}),
			isPlus: false,
			msg:    "invalid rateLimit burst",
		},
		{
			rateLimit: createInvalidRateLimit(func(r *v1.RateLimit) {
				r.ZoneSize = "31k"
			}),
			isPlus: false,
			msg:    "invalid rateLimit zoneSize",
		},
		{
			rateLimit: createInvalidRateLimit(func(r *v1.RateLimit) {
				r.RejectCode = new(600)
			}),
			isPlus: false,
			msg:    "invalid rateLimit rejectCode",
		},
		{
			rateLimit: createInvalidRateLimit(func(r *v1.RateLimit) {
				r.LogLevel = "invalid"
			}),
			isPlus: false,
			msg:    "invalid rateLimit logLevel",
		},
		{
			rateLimit: createInvalidRateLimit(func(r *v1.RateLimit) {
				r.Condition = &v1.RateLimitCondition{
					JWT: &v1.JWTCondition{
						Claim: "sub",
						Match: "Gold",
					},
				}
			}),
			isPlus: false,
			msg:    "must be plus",
		},
		{
			rateLimit: createInvalidRateLimit(func(r *v1.RateLimit) {
				r.Condition = &v1.RateLimitCondition{
					Default: false,
				}
			}),
			isPlus: true,
			msg:    "missing JWTCondition",
		},
	}

	for _, test := range tests {
		allErrs := validateRateLimit(test.rateLimit, field.NewPath("rateLimit"), test.isPlus)
		if len(allErrs) == 0 {
			t.Errorf("validateRateLimit() returned no errors for invalid input for the case of %v", test.msg)
		}
	}
}

func TestValidateRateLimitKey(t *testing.T) {
	t.Parallel()

	for varName := range rateLimitKeyVariables {
		keyToTest := "${" + varName + "}"
		testMsg := "validating key: " + keyToTest

		t.Run(testMsg, func(t *testing.T) {
			t.Parallel()
			allErrs := validateRateLimitKey(keyToTest, field.NewPath("key"), false)
			if len(allErrs) > 0 {
				t.Errorf("validateRateLimitKey returned error for valid key %q, error %v", keyToTest, allErrs)
			}
		})
	}

	t.Run("invalid unknown key", func(t *testing.T) {
		t.Parallel()
		invalidKey := "${not_a_valid_key}"
		allErrs := validateRateLimitKey(invalidKey, field.NewPath("key"), false)
		if len(allErrs) == 0 {
			t.Errorf("validateRateLimitKey returned no errors for an unknown key %q", invalidKey)
		}
	})

	t.Run("empty key", func(t *testing.T) {
		t.Parallel()
		emptyKey := ""
		allErrs := validateRateLimitKey(emptyKey, field.NewPath("key"), false)
		if len(allErrs) == 0 {
			t.Errorf("validateRateLimitKey %q returned no errors for an empty key", emptyKey)
		}
	})
}

func TestValidateJWT_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		jwt *v1.JWTAuth
		msg string
	}{
		{
			jwt: &v1.JWTAuth{
				Realm:  "My Product API",
				Secret: "my-jwk",
			},
			msg: "basic",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:  "My Product API",
				Secret: "my-jwk",
				Token:  "$cookie_auth_token",
			},
			msg: "jwt with token",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:    "My Product API",
				Token:    "$cookie_auth_token",
				JwksURI:  "https://idp.com/token",
				KeyCache: "1h",
			},
			msg: "jwt with jwksURI",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:      "My Product API",
				Token:      "$cookie_auth_token",
				JwksURI:    "https://idp.com/token",
				KeyCache:   "1h",
				SNIEnabled: true,
				SNIName:    "https://ipd.com:9999",
			},
			msg: "SNI enabled and valid SNI server name",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:      "My Product API",
				Token:      "$cookie_auth_token",
				JwksURI:    "https://idp.com/token",
				KeyCache:   "1h",
				SNIEnabled: true,
			},
			msg: "SNI enabled and no server name passed",
		},
	}
	for _, test := range tests {
		allErrs := validateJWT(test.jwt, field.NewPath("jwt"))
		if len(allErrs) != 0 {
			t.Errorf("validateJWT() returned errors %v for valid input for the case of %v", allErrs, test.msg)
		}
	}
}

func TestValidateJWT_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		msg string
		jwt *v1.JWTAuth
	}{
		{
			jwt: &v1.JWTAuth{
				Realm: "My Product API",
			},
			msg: "missing secret and jwksURI",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:   "My Product API",
				Secret:  "my-jwk",
				JwksURI: "https://idp.com/token",
			},
			msg: "both secret and jwksURI present",
		},
		{
			jwt: &v1.JWTAuth{
				Secret: "my-jwk",
			},
			msg: "missing realm",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:  "My Product API",
				Secret: "my-jwk",
				Token:  "$uri",
			},
			msg: "invalid variable use in token",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:  "My Product API",
				Secret: "my-\"jwk",
			},
			msg: "invalid secret name",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:  "My \"Product API",
				Secret: "my-jwk",
			},
			msg: "invalid realm due to escaped string",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:  "My Product ${api}",
				Secret: "my-jwk",
			},
			msg: "invalid variable use in realm with curly braces",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:  "My Product $api",
				Secret: "my-jwk",
			},
			msg: "invalid variable use in realm without curly braces",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:    "My Product api",
				Secret:   "my-jwk",
				KeyCache: "1h",
			},
			msg: "using KeyCache with Secret",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:    "My Product api",
				JwksURI:  "https://idp.com/token",
				KeyCache: "1k",
			},
			msg: "invalid suffix for KeyCache",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:    "My Product api",
				JwksURI:  "https://idp.com/token",
				KeyCache: "oneM",
			},
			msg: "invalid unit for KeyCache",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:    "My Product api",
				JwksURI:  "myidp",
				KeyCache: "1h",
			},
			msg: "invalid JwksURI",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:      "My Product api",
				JwksURI:    "https://idp.com/token",
				KeyCache:   "1h",
				SNIEnabled: true,
				SNIName:    "msql://not-\\\\a-valid-sni",
			},
			msg: "invalid SNI server name",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:      "My Product api",
				JwksURI:    "https://idp.com/token",
				KeyCache:   "1h",
				SNIEnabled: false,
				SNIName:    "https://idp.com",
			},
			msg: "SNI server name passed, SNI not enabled",
		},
		{
			jwt: &v1.JWTAuth{
				Realm:    "My Product api",
				JwksURI:  "https://idp.com/token",
				KeyCache: "1h",
				SNIName:  "https://idp.com",
			},
			msg: "SNI server name passed, SNI not passed",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.msg, func(t *testing.T) {
			t.Parallel()
			allErrs := validateJWT(test.jwt, field.NewPath("jwt"))
			if len(allErrs) == 0 {
				t.Errorf("validateJWT() returned no errors for invalid input for the case of %v", test.msg)
			}
		})
	}
}

func TestValidateIPorCIDR_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	validInput := []string{
		"192.168.1.1",
		"192.168.1.0/24",
		"2001:0db8::1",
		"2001:0db8::/32",
	}

	for _, input := range validInput {
		allErrs := validateIPorCIDR(input, field.NewPath("ipOrCIDR"))
		if len(allErrs) > 0 {
			t.Errorf("validateIPorCIDR(%q) returned errors %v for valid input", input, allErrs)
		}
	}
}

func TestValidateIPorCIDR_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()

	invalidInput := []string{
		"localhost",
		"192.168.1.0/",
		"2001:0db8:::1",
		"2001:0db8::/",
	}

	for _, input := range invalidInput {
		allErrs := validateIPorCIDR(input, field.NewPath("ipOrCIDR"))
		if len(allErrs) == 0 {
			t.Errorf("validateIPorCIDR(%q) returned no errors for invalid input", input)
		}
	}
}

func TestValidateRate_PassesOnValidInput(t *testing.T) {
	t.Parallel()

	validInput := []string{
		"10r/s",
		"100r/m",
		"1r/s",
	}

	for _, input := range validInput {
		allErrs := validateRate(input, field.NewPath("rate"))
		if len(allErrs) > 0 {
			t.Errorf("validateRate(%q) returned errors %v for valid input", input, allErrs)
		}
	}
}

func TestValidateRate_ErrorsOnInvalidInput(t *testing.T) {
	t.Parallel()
	invalidInput := []string{
		"10s",
		"10r/",
		"10r/ms",
		"0r/s",
	}

	for _, input := range invalidInput {
		allErrs := validateRate(input, field.NewPath("rate"))
		if len(allErrs) == 0 {
			t.Errorf("validateRate(%q) returned no errors for invalid input", input)
		}
	}
}

func TestValidatePositiveInt_PassesOnValidInput(t *testing.T) {
	t.Parallel()

	validInput := []int{1, 2}

	for _, input := range validInput {
		allErrs := validatePositiveInt(input, field.NewPath("int"))
		if len(allErrs) > 0 {
			t.Errorf("validatePositiveInt(%d) returned errors %v for valid input", input, allErrs)
		}
	}
}

func TestValidatePositiveInt_ErrorsOnInvalidInput(t *testing.T) {
	t.Parallel()

	invalidInput := []int{-1, 0}

	for _, input := range invalidInput {
		allErrs := validatePositiveInt(input, field.NewPath("int"))
		if len(allErrs) == 0 {
			t.Errorf("validatePositiveInt(%d) returned no errors for invalid input", input)
		}
	}
}

func TestValidateRateLimitZoneSize_ErrorsOnInvalidInput(t *testing.T) {
	t.Parallel()

	invalidInput := []string{"", "31", "31k", "0", "0M"}

	for _, test := range invalidInput {
		allErrs := validateRateLimitZoneSize(test, field.NewPath("size"))
		if len(allErrs) == 0 {
			t.Errorf("validateRateLimitZoneSize(%q) didn't return error for invalid input", test)
		}
	}
}

func TestValidateRateLimitZoneSize_PassesOnValidInput(t *testing.T) {
	t.Parallel()

	validInput := []string{"32", "32k", "32K", "10m"}

	for _, test := range validInput {
		allErrs := validateRateLimitZoneSize(test, field.NewPath("size"))
		if len(allErrs) != 0 {
			t.Errorf("validateRateLimitZoneSize(%q) returned an error for valid input", test)
		}
	}
}

func TestValidateRateLimitZoneSize_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()

	invalidInput := []string{"", "31", "31k", "0", "0M"}

	for _, test := range invalidInput {
		allErrs := validateRateLimitZoneSize(test, field.NewPath("size"))
		if len(allErrs) == 0 {
			t.Errorf("validateRateLimitZoneSize(%q) didn't return error for invalid input", test)
		}
	}
}

func TestValidateRateLimitLogLevel_PassesOnValidInput(t *testing.T) {
	t.Parallel()

	validInput := []string{"error", "info", "warn", "notice"}

	for _, test := range validInput {
		allErrs := validateRateLimitLogLevel(test, field.NewPath("logLevel"))
		if len(allErrs) != 0 {
			t.Errorf("validateRateLimitLogLevel(%q) returned an error for valid input", test)
		}
	}
}

func TestValidateRateLimitLogLevel_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()

	invalidInput := []string{"warn ", "info error", ""}

	for _, test := range invalidInput {
		allErrs := validateRateLimitLogLevel(test, field.NewPath("logLevel"))
		if len(allErrs) == 0 {
			t.Errorf("validateRateLimitLogLevel(%q) didn't return error for invalid input", test)
		}
	}
}

func TestValidateJWTToken_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	validTests := []struct {
		token string
		msg   string
	}{
		{
			token: "",
			msg:   "no token set",
		},
		{
			token: "$http_token",
			msg:   "http special variable usage",
		},
		{
			token: "$arg_token",
			msg:   "arg special variable usage",
		},
		{
			token: "$cookie_token",
			msg:   "cookie special variable usage",
		},
	}
	for _, test := range validTests {
		allErrs := validateJWTToken(test.token, field.NewPath("token"))
		if len(allErrs) != 0 {
			t.Errorf("validateJWTToken(%v) returned an error for valid input for the case of %v", test.token, test.msg)
		}
	}
}

func TestValidateJWTToken_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	invalidTests := []struct {
		token string
		msg   string
	}{
		{
			token: "http_token",
			msg:   "missing $ prefix",
		},
		{
			token: "${http_token}",
			msg:   "usage of $ and curly braces",
		},
		{
			token: "$http_token$http_token",
			msg:   "multi variable usage",
		},
		{
			token: "something$http_token",
			msg:   "non variable usage",
		},
		{
			token: "$uri",
			msg:   "non special variable usage",
		},
	}
	for _, test := range invalidTests {
		allErrs := validateJWTToken(test.token, field.NewPath("token"))
		if len(allErrs) == 0 {
			t.Errorf("validateJWTToken(%v) didn't return error for invalid input for the case of %v", test.token, test.msg)
		}
	}
}

func TestValidateIngressMTLS_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ing *v1.IngressMTLS
		msg string
	}{
		{
			ing: &v1.IngressMTLS{
				ClientCertSecret: "mtls-secret",
			},
			msg: "default",
		},
		{
			ing: &v1.IngressMTLS{
				ClientCertSecret: "mtls-secret",
				VerifyClient:     "on",
				VerifyDepth:      new(1),
			},
			msg: "all parameters with default value",
		},
		{
			ing: &v1.IngressMTLS{
				ClientCertSecret: "ingress-mtls-secret",
				VerifyClient:     "optional",
				VerifyDepth:      new(2),
			},
			msg: "optional parameters",
		},
	}
	for _, test := range tests {
		allErrs := validateIngressMTLS(test.ing, field.NewPath("ingressMTLS"))
		if len(allErrs) != 0 {
			t.Errorf("validateIngressMTLS() returned errors %v for valid input for the case of %v", allErrs, test.msg)
		}
	}
}

func TestValidateIngressMTLS_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ing *v1.IngressMTLS
		msg string
	}{
		{
			ing: &v1.IngressMTLS{
				VerifyClient: "on",
			},
			msg: "no secret",
		},
		{
			ing: &v1.IngressMTLS{
				ClientCertSecret: "-foo-",
			},
			msg: "invalid secret name",
		},
		{
			ing: &v1.IngressMTLS{
				ClientCertSecret: "mtls-secret",
				VerifyClient:     "foo",
			},
			msg: "invalid verify client",
		},
		{
			ing: &v1.IngressMTLS{
				ClientCertSecret: "ingress-mtls-secret",
				VerifyClient:     "on",
				VerifyDepth:      new(-1),
			},
			msg: "invalid depth",
		},
	}
	for _, test := range tests {
		allErrs := validateIngressMTLS(test.ing, field.NewPath("ingressMTLS"))
		if len(allErrs) == 0 {
			t.Errorf("validateIngressMTLS() returned no errors for invalid input for the case of %v", test.msg)
		}
	}
}

func TestValidateIngressMTLSVerifyClient_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	validInput := []string{"on", "off", "optional", "optional_no_ca"}

	for _, test := range validInput {
		allErrs := validateIngressMTLSVerifyClient(test, field.NewPath("verifyClient"))
		if len(allErrs) != 0 {
			t.Errorf("validateIngressMTLSVerifyClient(%q) returned errors %v for valid input", allErrs, test)
		}
	}
}

func TestValidateIngressMTLSVerifyClient_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	invalidInput := []string{"true", "false"}

	for _, test := range invalidInput {
		allErrs := validateIngressMTLSVerifyClient(test, field.NewPath("verifyClient"))
		if len(allErrs) == 0 {
			t.Errorf("validateIngressMTLSVerifyClient(%q) didn't return error for invalid input", test)
		}
	}
}

func TestValidateEgressMTLS_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		eg  *v1.EgressMTLS
		msg string
	}{
		{
			eg: &v1.EgressMTLS{
				TLSSecret: "mtls-secret",
			},
			msg: "tls secret",
		},
		{
			eg: &v1.EgressMTLS{
				TrustedCertSecret: "tls-secret",
				VerifyServer:      true,
				VerifyDepth:       new(2),
				ServerName:        false,
			},
			msg: "verify server set to true",
		},
		{
			eg: &v1.EgressMTLS{
				VerifyServer: false,
			},
			msg: "verify server set to false",
		},
		{
			eg: &v1.EgressMTLS{
				SSLName: "foo.com",
			},
			msg: "ssl name",
		},
	}
	for _, test := range tests {
		allErrs := validateEgressMTLS(test.eg, field.NewPath("egressMTLS"))
		if len(allErrs) != 0 {
			t.Errorf("validateEgressMTLS() returned errors %v for valid input for the case of %v", allErrs, test.msg)
		}
	}
}

func TestValidateEgressMTLS_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		eg  *v1.EgressMTLS
		msg string
	}{
		{
			eg: &v1.EgressMTLS{
				VerifyServer: true,
			},
			msg: "verify server set to true",
		},
		{
			eg: &v1.EgressMTLS{
				TrustedCertSecret: "-foo-",
			},
			msg: "invalid secret name",
		},
		{
			eg: &v1.EgressMTLS{
				TrustedCertSecret: "ingress-mtls-secret",
				VerifyServer:      true,
				VerifyDepth:       new(-1),
			},
			msg: "invalid depth",
		},
		{
			eg: &v1.EgressMTLS{
				SSLName: "foo.com;",
			},
			msg: "invalid name",
		},
	}

	for _, test := range tests {
		allErrs := validateEgressMTLS(test.eg, field.NewPath("egressMTLS"))
		if len(allErrs) == 0 {
			t.Errorf("validateEgressMTLS() returned no errors for invalid input for the case of %v", test.msg)
		}
	}
}

func TestValidateOIDC_PassesOnValidOIDC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		oidc *v1.OIDC
		msg  string
	}{
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "https://accounts.google.com/o/oauth2/v2/auth",
				AuthExtraArgs:         []string{"foo=bar", "baz=zot"},
				TokenEndpoint:         "https://oauth2.googleapis.com/token",
				JWKSURI:               "https://www.googleapis.com/oauth2/v3/certs",
				EndSessionEndpoint:    "https://oauth2.googleapis.com/revoke",
				PostLogoutRedirectURI: "/_logout",
				ClientID:              "random-string",
				ClientSecret:          "random-secret",
				Scope:                 "openid",
				RedirectURI:           "/foo",
				ZoneSyncLeeway:        new(20),
				AccessTokenEnable:     true,
			},
			msg: "verify full oidc",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/authorize",
				TokenEndpoint:         "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/token",
				JWKSURI:               "https://login.microsoftonline.com/dd-fff-eee-1234-9be/discovery/v2.0/keys",
				EndSessionEndpoint:    "https://login.microsoftonline.com/dd-fff-eee-1234-9be/discovery/v2.0/logout",
				PostLogoutRedirectURI: "/_logout",
				RedirectURI:           "/_codexch",
				ClientID:              "ff",
				ClientSecret:          "ff",
				Scope:                 "openid+profile",
				AccessTokenEnable:     true,
			},
			msg: "verify azure endpoint",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "http://keycloak.default.svc.cluster.local:8080/realms/master/protocol/openid-connect/auth",
				AuthExtraArgs:         []string{"kc_idp_hint=foo"},
				TokenEndpoint:         "http://keycloak.default.svc.cluster.local:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:               "http://keycloak.default.svc.cluster.local:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint:    "http://keycloak.default.svc.cluster.local:8080/realms/master/protocol/openid-connect/logout",
				PostLogoutRedirectURI: "/_logout",
				RedirectURI:           "/_codexch",
				ClientID:              "bar",
				ClientSecret:          "foo",
				Scope:                 "openid",
				AccessTokenEnable:     true,
			},
			msg: "domain with port number",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				TokenEndpoint:         "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:               "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint:    "http://127.0.0.1:8080/realms/master/protocol/openid-connect/logout",
				PostLogoutRedirectURI: "/_logout",
				RedirectURI:           "/_codexch",
				ClientID:              "client",
				ClientSecret:          "secret",
				Scope:                 "openid",
				AccessTokenEnable:     true,
			},
			msg: "ip address",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				TokenEndpoint:         "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:               "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint:    "http://127.0.0.1:8080/realms/master/protocol/openid-connect/logout",
				PostLogoutRedirectURI: "/_logout",
				RedirectURI:           "/_codexch",
				ClientID:              "client",
				ClientSecret:          "secret",
				Scope:                 "openid+offline_access",
				AccessTokenEnable:     true,
			},
			msg: "offline access scope",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:       "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				TokenEndpoint:      "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:            "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint: "http://127.0.0.1:8080/realms/master/protocol/openid-connect/logout",
				RedirectURI:        "/_codexch",
				ClientID:           "client",
				ClientSecret:       "secret",
				Scope:              "openid",
				AccessTokenEnable:  true,
			},
			msg: "no post logout redirect URI",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:      "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				TokenEndpoint:     "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:           "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				RedirectURI:       "/_codexch",
				ClientID:          "client",
				ClientSecret:      "secret",
				Scope:             "openid",
				AccessTokenEnable: true,
			},
			msg: "no end-session endpoint or post logout redirect URI",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:       "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				TokenEndpoint:      "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:            "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint: "http://127.0.0.1:8080/realms/master/protocol/openid-connect/logout",
				RedirectURI:        "/_codexch",
				ClientID:           "client",
				ClientSecret:       "secret",
				Scope:              "openid",
				AccessTokenEnable:  true,
			},
			msg: "no post logout redirect URI",
		},
	}

	for _, test := range tests {
		allErrs := validateOIDC(test.oidc, field.NewPath("oidc"))
		if len(allErrs) != 0 {
			t.Errorf("validateOIDC() returned errors %v for valid input for the case of %v", allErrs, test.msg)
		}
	}
}

func TestValidateOIDC_FailsOnInvalidOIDC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		oidc      *v1.OIDC
		fieldPath string
		msg       string
	}{
		{
			oidc: &v1.OIDC{
				RedirectURI: "/foo",
			},
			fieldPath: "oidc.authEndpoint",
			msg:       "missing required field auth",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				TokenEndpoint:         "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:               "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint:    "http://127.0.0.1:8080/realms/master/protocol/openid-connect/logout",
				PostLogoutRedirectURI: "/_logout",
				ClientID:              "client",
				ClientSecret:          "secret",
				Scope:                 "bogus",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.scope",
			msg:       "missing openid in scope",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				TokenEndpoint:         "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:               "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint:    "http://127.0.0.1:8080/realms/master/protocol/openid-connect/logout",
				PostLogoutRedirectURI: "/_logout",
				ClientID:              "client",
				ClientSecret:          "secret",
				Scope:                 "openid+bogus\x7f",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.scope",
			msg:       "invalid unicode in scope",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/authorize",
				JWKSURI:               "https://login.microsoftonline.com/dd-fff-eee-1234-9be/discovery/v2.0/keys",
				EndSessionEndpoint:    "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/logout",
				PostLogoutRedirectURI: "/_logout",
				ClientID:              "ff",
				ClientSecret:          "ff",
				Scope:                 "openid+profile",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.tokenEndpoint",
			msg:       "missing required field token",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/authorize",
				TokenEndpoint:         "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/token",
				EndSessionEndpoint:    "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/logout",
				PostLogoutRedirectURI: "/_logout",
				ClientID:              "ff",
				ClientSecret:          "ff",
				Scope:                 "openid+profile",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.jwksURI",
			msg:       "missing required field jwk",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/authorize",
				TokenEndpoint:         "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/token",
				JWKSURI:               "https://login.microsoftonline.com/dd-fff-eee-1234-9be/discovery/v2.0/keys",
				EndSessionEndpoint:    "https://login.microsoftonline.com/dd-fff-eee-1234-9be/discovery/v2.0/logout",
				PostLogoutRedirectURI: "/_logout",
				ClientSecret:          "ff",
				Scope:                 "openid+profile",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.clientID",
			msg:       "missing required field clientid",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/authorize",
				TokenEndpoint:         "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/token",
				JWKSURI:               "https://login.microsoftonline.com/dd-fff-eee-1234-9be/discovery/v2.0/keys",
				EndSessionEndpoint:    "https://login.microsoftonline.com/dd-fff-eee-1234-9be/discovery/v2.0/logout",
				PostLogoutRedirectURI: "/_logout",
				ClientID:              "ff",
				Scope:                 "openid+profile",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.clientSecret",
			msg:       "missing required field client secret",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/authorize",
				TokenEndpoint:         "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/token",
				JWKSURI:               "https://login.microsoftonline.com/dd-fff-eee-1234-9be/discovery/v2.0/keys",
				PostLogoutRedirectURI: "/_logout",
				ClientID:              "ff",
				ClientSecret:          "ff",
				Scope:                 "openid+profile",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.postLogoutRedirectURI",
			msg:       "missing required field end session endpoint when post logout redirect URI is set",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/authorize",
				TokenEndpoint:         "https://login.microsoftonline.com/dd-fff-eee-1234-9be/oauth2/v2.0/token",
				JWKSURI:               "https://login.microsoftonline.com/dd-fff-eee-1234-9be/discovery/v2.0/keys",
				EndSessionEndpoint:    "https://login.microsoftonline.com/dd-fff-eee-1234-9be/discovery/v2.0/logout",
				PostLogoutRedirectURI: "/_logout",
				RedirectURI:           "/_codexch",
				ClientID:              "ff",
				ClientSecret:          "-ff-",
				Scope:                 "openid+profile",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.clientSecret",
			msg:       "invalid secret name",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "http://foo.\bar.com",
				TokenEndpoint:         "http://keycloak.default/",
				JWKSURI:               "http://keycloak.default/",
				EndSessionEndpoint:    "http://keycloak.default/",
				PostLogoutRedirectURI: "/_logout",
				RedirectURI:           "/_codexch",
				ClientID:              "bar",
				ClientSecret:          "foo",
				Scope:                 "openid",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.authEndpoint",
			msg:       "invalid URL",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				TokenEndpoint:         "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:               "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint:    "http://127.0.0.1:8080/realms/master/protocol/openid-connect/logout",
				PostLogoutRedirectURI: "http://foo.bar",
				RedirectURI:           "/_codexch",
				ClientID:              "bar",
				ClientSecret:          "foo",
				Scope:                 "openid",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.postLogoutRedirectURI",
			msg:       "invalid logout redirect URL",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				TokenEndpoint:         "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:               "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint:    "http://127.0.0.1:8080/realms/master/protocol/openid-connect/logout",
				PostLogoutRedirectURI: "/_logout",
				RedirectURI:           "/_codexch",
				ClientID:              "$foo$bar",
				ClientSecret:          "secret",
				Scope:                 "openid",
				AccessTokenEnable:     true,
			},
			fieldPath: "oidc.clientID",
			msg:       "invalid chars in clientID",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				AuthExtraArgs:         []string{"foo;bar"},
				TokenEndpoint:         "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:               "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint:    "http://127.0.0.1:8080/realms/master/protocol/openid-connect/logout",
				PostLogoutRedirectURI: "/_logout",
				RedirectURI:           "/_codexch",
				ClientID:              "foobar",
				ClientSecret:          "secret",
				Scope:                 "openid",
			},
			fieldPath: "oidc.authExtraArgs",
			msg:       "invalid chars in authExtraArgs",
		},
		{
			oidc: &v1.OIDC{
				AuthEndpoint:          "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth",
				TokenEndpoint:         "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
				JWKSURI:               "http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs",
				EndSessionEndpoint:    "http://127.0.0.1:8080/realms/master/protocol/openid-connect/logout",
				PostLogoutRedirectURI: "/_logout",
				RedirectURI:           "/_codexch", ClientID: "foobar",
				ClientSecret:      "secret",
				Scope:             "openid",
				ZoneSyncLeeway:    new(-1),
				AccessTokenEnable: true,
			},
			fieldPath: "oidc.zoneSyncLeeway",
			msg:       "invalid zoneSyncLeeway value",
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			t.Parallel()
			allErrs := validateOIDC(test.oidc, field.NewPath("oidc"))
			if len(allErrs) == 0 {
				t.Errorf("validateOIDC() returned no errors for invalid input for the case of %v", test.msg)
			} else if allErrs[0].Field != test.fieldPath {
				t.Errorf("validateOIDC() returned error on wrong field for the case of %v, want %v, got %v", test.msg, test.fieldPath, allErrs[0].Field)
			}
			t.Log(allErrs)
		})
	}
}

func TestValidateAPIKeyPolicy_PassOnValidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		apiKey *v1.APIKey
		msg    string
	}{
		{
			apiKey: &v1.APIKey{
				SuppliedIn: &v1.SuppliedIn{
					Header: []string{
						"X-API-Key",
					},
				},
				ClientSecret: "secret",
			},
		},
	}

	for _, test := range tests {
		allErrs := validateAPIKey(test.apiKey, field.NewPath("apiKey"))
		if len(allErrs) != 0 {
			t.Errorf("validateAPIKey() returned errors %v for valid input for the case of %v", allErrs, test.msg)
		}
	}
}

func TestValidateAPIKeyPolicy_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		apiKey *v1.APIKey
		msg    string
	}{
		{
			apiKey: &v1.APIKey{
				SuppliedIn: &v1.SuppliedIn{
					Query: []string{
						"api_key",
					},
				},
			},
			msg: "missing secret",
		},
		{
			apiKey: &v1.APIKey{
				SuppliedIn:   &v1.SuppliedIn{},
				ClientSecret: "secret",
			},
			msg: "both  header and query are missing",
		},
		{
			apiKey: &v1.APIKey{
				SuppliedIn: &v1.SuppliedIn{
					Header: []string{
						`api.key"`,
					},
				},
				ClientSecret: "secret",
			},
			msg: "invalid header",
		},
		{
			apiKey: &v1.APIKey{
				SuppliedIn: &v1.SuppliedIn{
					Query: []string{
						`api_key\`,
					},
				},
				ClientSecret: "secret",
			},
			msg: "invalid query",
		},
		{
			apiKey: &v1.APIKey{
				SuppliedIn: &v1.SuppliedIn{
					Query: []string{
						`api_key`,
					},
				},
				ClientSecret: "secret_1",
			},
			msg: "invalid secret name",
		},
		{
			apiKey: &v1.APIKey{
				ClientSecret: "secret_1",
			},
			msg: "no suppliedIn provided",
		},

		{
			apiKey: nil, msg: "no apikey provided",
		},
	}

	for _, test := range tests {
		allErrs := validateAPIKey(test.apiKey, field.NewPath("apiKey"))
		if len(allErrs) == 0 {
			t.Errorf("validateAPIKey() returned no errors for invalid input for the case of %v", test.msg)
		}
	}
}

func TestValidateOIDCScope_ErrorsOnInvalidInput(t *testing.T) {
	t.Parallel()

	invalidInput := []string{
		"",
		" ",
		"openid+scope\x5c",
		"mycustom\x7fscope",
		"openid+myscope\x20",
		"openid+cus\x19tom",
	}

	for _, v := range invalidInput {
		allErrs := validateOIDCScope(v, field.NewPath("scope"))
		if len(allErrs) == 0 {
			t.Error("want err on invalid scope, got no error")
		}
	}
}

func TestValidateOIDCScope_PassesOnValidInput(t *testing.T) {
	t.Parallel()

	validInput := []string{
		"openid",
		"validScope+openid",
		"SecondScope+openid+CustomScope",
		"validScope\x26+openid",
		"openid+my\x33scope",
	}
	for _, v := range validInput {
		allErrs := validateOIDCScope(v, field.NewPath("scope"))
		if len(allErrs) != 0 {
			t.Errorf("want no err, got %v", allErrs)
		}
	}
}

func TestValidatePortNumber_ErrorsOnInvalidPort(t *testing.T) {
	t.Parallel()

	invalidPorts := []string{"bogus", ""}
	for _, p := range invalidPorts {
		allErrs := validatePortNumber(p, field.NewPath("port"))
		if len(allErrs) == 0 {
			t.Errorf("want err on invalid input %q, got nil", p)
		}
	}
}

func TestValidateClientID(t *testing.T) {
	t.Parallel()

	validInput := []string{"myid", "your.id", "id-sf-sjfdj.com", "foo_bar~vni"}

	for _, test := range validInput {
		allErrs := validateClientID(test, field.NewPath("clientID"))
		if len(allErrs) != 0 {
			t.Errorf("validateClientID(%q) returned errors %v for valid input", allErrs, test)
		}
	}
}

func TestValidateClientID_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	invalidInput := []string{"$boo", "foo$bar", `foo_bar"vni`, `client\`}

	for _, test := range invalidInput {
		allErrs := validateClientID(test, field.NewPath("clientID"))
		if len(allErrs) == 0 {
			t.Errorf("validateClientID(%q) didn't return error for invalid input", test)
		}
	}
}

func TestValidateURL_PassesOnValidInput(t *testing.T) {
	t.Parallel()

	validInput := []string{
		"http://google.com/auth",
		"https://foo.bar/baz",
		"http://127.0.0.1/bar",
		"http://openid.connect.com:8080/foo",
	}

	for _, test := range validInput {
		allErrs := validateURL(test, field.NewPath("authEndpoint"))
		if len(allErrs) != 0 {
			t.Errorf("validateURL(%q) returned errors %v for valid input", allErrs, test)
		}
	}
}

func TestValidateURL_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()

	invalidInput := []string{
		"www.google..foo.com",
		"http://{foo.bar",
		`https://google.foo\bar`,
		"http://foo.bar:8080",
		"http://foo.bar:812345/fooo",
		"http://:812345/fooo",
		"",
		"bogusInput",
	}

	for _, test := range invalidInput {
		allErrs := validateURL(test, field.NewPath("authEndpoint"))
		if len(allErrs) == 0 {
			t.Errorf("validateURL(%q) didn't return error for invalid input", test)
		}
	}
}

func TestValidateQueryString_PassesOnValidInput(t *testing.T) {
	t.Parallel()

	validInput := []string{"foo=bar", "foo", "foo=bar&baz=zot", "foo=bar&foo=baz", "foo=bar%3Bbaz"}

	for _, test := range validInput {
		allErrs := validateQueryString(test, field.NewPath("authExtraArgs"))
		if len(allErrs) != 0 {
			t.Errorf("validateQueryString(%q) returned errors %v for valid input", allErrs, test)
		}
	}
}

func TestValidateQueryString_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()

	invalidInput := []string{"foo=bar;baz"}

	for _, test := range invalidInput {
		allErrs := validateQueryString(test, field.NewPath("authExtraArgs"))
		if len(allErrs) == 0 {
			t.Errorf("validateQueryString(%q) didn't return error for invalid input", test)
		}
	}
}

func TestValidateWAF_PassesOnValidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		waf *v1.WAF
		msg string
	}{
		{
			waf: &v1.WAF{
				Enable: true,
			},
			msg: "waf enabled",
		},
		{
			waf: &v1.WAF{
				Enable:   true,
				ApPolicy: "ns1/waf-pol",
			},
			msg: "cross ns reference",
		},
		{
			waf: &v1.WAF{
				Enable: true,
				SecurityLog: &v1.SecurityLog{
					Enable:  true,
					LogDest: "syslog:server=8.7.7.7:517",
				},
			},
			msg: "custom logdest",
		},
	}

	for _, test := range tests {
		allErrs := validateWAF(test.waf, field.NewPath("waf"))
		if len(allErrs) != 0 {
			t.Errorf("validateWAF() returned errors %v for valid input for the case of %v", allErrs, test.msg)
		}
	}
}

func TestValidateWAF_FailsOnPresentBothApBundleAndApPolicy(t *testing.T) {
	t.Parallel()

	waf := &v1.WAF{
		Enable:   true,
		ApBundle: "bundle.tgz",
		ApPolicy: "default/policy_name",
	}

	allErrs := validateWAF(waf, field.NewPath("waf"))
	if len(allErrs) == 0 {
		t.Errorf("want error, got %v", allErrs)
	}
}

func TestValidateWAF_FailsOnInvalidApBundlePath(t *testing.T) {
	t.Parallel()

	tt := []struct {
		waf *v1.WAF
	}{
		{
			waf: &v1.WAF{
				ApBundle: ".",
			},
		},
		{
			waf: &v1.WAF{
				ApBundle: "../bundle.tgz",
			},
		},
		{
			waf: &v1.WAF{
				ApBundle: "/bundle.tgz",
			},
		},
	}

	for _, tc := range tt {
		allErrs := validateWAF(tc.waf, field.NewPath("waf"))
		if len(allErrs) == 0 {
			t.Errorf("want error, got %v", allErrs)
		}
	}
}

func TestValidateWAF_PassesOnValidBundleName(t *testing.T) {
	t.Parallel()

	waf := &v1.WAF{
		Enable:   true,
		ApBundle: "ap-bundle.tgz",
	}
	gotErrors := validateWAF(waf, field.NewPath("waf"))
	if len(gotErrors) != 0 {
		t.Errorf("want no errors, got %v", gotErrors)
	}
}

func TestValidateWAF_FailsOnInvalidApPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		waf *v1.WAF
		msg string
	}{
		{
			waf: &v1.WAF{
				Enable:   true,
				ApPolicy: "ns1/ap-pol/ns2",
			},
			msg: "invalid apPolicy format",
		},
		{
			waf: &v1.WAF{
				Enable: true,
				SecurityLog: &v1.SecurityLog{
					Enable:  true,
					LogDest: "stdout",
				},
			},
			msg: "invalid logdest",
		},
		{
			waf: &v1.WAF{
				Enable: true,
				SecurityLog: &v1.SecurityLog{
					Enable:    true,
					ApLogConf: "ns1/log-conf/ns2",
				},
			},
			msg: "invalid logConf format",
		},
	}

	for _, test := range tests {
		allErrs := validateWAF(test.waf, field.NewPath("waf"))
		if len(allErrs) == 0 {
			t.Errorf("validateWAF() returned no errors for invalid input for the case of %v", test.msg)
		}
	}
}

func TestValidateBasic_PassesOnNotEmptySecret(t *testing.T) {
	t.Parallel()

	errList := validateBasic(&v1.BasicAuth{Realm: "", Secret: "secret"}, field.NewPath("secret"))
	if len(errList) != 0 {
		t.Errorf("want no errors, got %v", errList)
	}
}

func TestValidateBasic_FailsOnMissingSecret(t *testing.T) {
	t.Parallel()

	errList := validateBasic(&v1.BasicAuth{Realm: "realm", Secret: ""}, field.NewPath("secret"))
	if len(errList) == 0 {
		t.Error("want error on invalid input")
	}
}

func TestValidateWAF_FailsOnPresentBothApLogBundleAndApLogConf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		waf   *v1.WAF
		valid bool
	}{
		{
			name: "mutually exclusive fields",
			waf: &v1.WAF{
				Enable:   true,
				ApBundle: "bundle.tgz",
				SecurityLogs: []*v1.SecurityLog{
					{
						ApLogConf:   "confName",
						ApLogBundle: "confName.tgz",
					},
				},
			},
			valid: false,
		},
		{
			name: "apBundle with apLogConf",
			waf: &v1.WAF{
				Enable:   true,
				ApBundle: "bundle.tgz",
				SecurityLogs: []*v1.SecurityLog{
					{
						ApLogConf: "confName",
						LogDest:   "stderr",
					},
				},
			},
			valid: false,
		},
		{
			name: "apPolicy with apLogBundle",
			waf: &v1.WAF{
				Enable:   true,
				ApPolicy: "apPolicy",
				SecurityLogs: []*v1.SecurityLog{
					{
						ApLogBundle: "confName.tgz",
						LogDest:     "stderr",
					},
				},
			},
			valid: false,
		},
		{
			name: "apBundle with apLogBundle",
			waf: &v1.WAF{
				Enable:   true,
				ApBundle: "bundle.tgz",
				SecurityLogs: []*v1.SecurityLog{
					{
						ApLogBundle: "confName.tgz",
						LogDest:     "stderr",
					},
				},
			},
			valid: true,
		},
		{
			name: "apPolicy with apLogConf",
			waf: &v1.WAF{
				Enable:   true,
				ApPolicy: "apPolicy",
				SecurityLogs: []*v1.SecurityLog{
					{
						ApLogConf: "confName",
						LogDest:   "stderr",
					},
				},
			},
			valid: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allErrs := validateWAF(tc.waf, field.NewPath("waf"))
			if len(allErrs) == 0 && !tc.valid {
				t.Errorf("want error, got %v", allErrs)
			} else if len(allErrs) > 0 && tc.valid {
				t.Errorf("got error %v", allErrs)
			}
		})
	}
}

func TestValidateWAF_FailsOnInvalidApLogBundle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		waf   *v1.WAF
		valid bool
	}{
		{
			name: "invalid file name 1",
			waf: &v1.WAF{
				Enable:   true,
				ApBundle: "bundle.tgz",
				SecurityLogs: []*v1.SecurityLog{
					{
						ApLogBundle: ".",
						LogDest:     "stderr",
					},
				},
			},
		},
		{
			name: "invalid file name 2",
			waf: &v1.WAF{
				Enable:   true,
				ApBundle: "bundle.tgz",
				SecurityLogs: []*v1.SecurityLog{
					{
						ApLogBundle: "../bundle.tgz",
						LogDest:     "stderr",
					},
				},
			},
		},
		{
			name: "invalid file name 3",
			waf: &v1.WAF{
				Enable:   true,
				ApBundle: "bundle.tgz",
				SecurityLogs: []*v1.SecurityLog{
					{
						ApLogBundle: "/bundle.tgz",
						LogDest:     "stderr",
					},
				},
			},
		},
		{
			name: "valid securityLog",
			waf: &v1.WAF{
				Enable:   true,
				ApBundle: "bundle.tgz",
				SecurityLog: &v1.SecurityLog{
					ApLogBundle: "bundle.tgz",
					LogDest:     "stderr",
				},
			},
			valid: true,
		},
		{
			name: "valid securityLogs",
			waf: &v1.WAF{
				Enable:   true,
				ApBundle: "bundle.tgz",
				SecurityLogs: []*v1.SecurityLog{
					{
						ApLogBundle: "bundle.tgz",
						LogDest:     "stderr",
					},
				},
			},
			valid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allErrs := validateWAF(tc.waf, field.NewPath("waf"))
			if len(allErrs) == 0 && !tc.valid {
				t.Errorf("want error, got %v", allErrs)
			} else if len(allErrs) > 0 && tc.valid {
				t.Errorf("got error %v", allErrs)
			}
		})
	}
}

func TestValidatePolicy_IsNotValidCachePolicy(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name   string
		policy *v1.Policy
		isPlus bool
	}{
		{
			name: "cache purge not allowed on OSS",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName:   "purgeoss",
						CacheZoneSize:   "10m",
						CachePurgeAllow: []string{"192.168.1.1"},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "invalid IP address in purge allow",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName:   "invalidip",
						CacheZoneSize:   "10m",
						CachePurgeAllow: []string{"invalid-ip"},
					},
				},
			},
			isPlus: true,
		},
		{
			name: "allowedCodes with 'any' mixed with integers",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "test",
						CacheZoneSize: "10m",
						AllowedCodes:  []intstr.IntOrString{intstr.FromString("any"), intstr.FromInt(200)},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "allowedCodes with invalid string",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "test",
						CacheZoneSize: "10m",
						AllowedCodes:  []intstr.IntOrString{intstr.FromString("invalid")},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "allowedCodes with status code below 100",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "test",
						CacheZoneSize: "10m",
						AllowedCodes:  []intstr.IntOrString{intstr.FromInt(99)},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "allowedCodes with status code above 599",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "test",
						CacheZoneSize: "10m",
						AllowedCodes:  []intstr.IntOrString{intstr.FromInt(600)},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "allowedCodes with multiple 'any' strings",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "test",
						CacheZoneSize: "10m",
						AllowedCodes:  []intstr.IntOrString{intstr.FromString("any"), intstr.FromString("any")},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "allowedCodes with valid and invalid status codes",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "test",
						CacheZoneSize: "10m",
						AllowedCodes:  []intstr.IntOrString{intstr.FromInt(200), intstr.FromInt(700)},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with invalid minUses (zero)",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "minuses",
						CacheZoneSize: "10m",
						CacheMinUses:  new(0),
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with invalid manager files (zero)",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "managerbad",
						CacheZoneSize: "10m",
						Manager: &v1.CacheManager{
							Files:     new(0),
							Sleep:     "100ms",
							Threshold: "500ms",
						},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with invalid manager sleep format",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "managersleep",
						CacheZoneSize: "10m",
						Manager: &v1.CacheManager{
							Files:     new(100),
							Sleep:     "invalid",
							Threshold: "500ms",
						},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with invalid manager threshold format",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "managerthreshold",
						CacheZoneSize: "10m",
						Manager: &v1.CacheManager{
							Files:     new(100),
							Sleep:     "100ms",
							Threshold: "bad-time",
						},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with invalid lock timeout format",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "locktimeout",
						CacheZoneSize: "10m",
						Lock: &v1.CacheLock{
							Enable:  true,
							Timeout: "invalid-timeout",
						},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with invalid inactive format",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "inactive",
						CacheZoneSize: "10m",
						Inactive:      "bad-duration",
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with invalid max size format",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "maxsize",
						CacheZoneSize: "10m",
						MaxSize:       "invalid-size",
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with invalid cacheUseStale parameter",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "invalidstaleparameter",
						CacheZoneSize: "10m",
						CacheUseStale: []string{"error", "invalid_param", "timeout"},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with duplicate cacheUseStale parameters",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "duplicatestale",
						CacheZoneSize: "10m",
						CacheUseStale: []string{"error", "timeout", "error"},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with invalid cache key ending with $",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "invalidkey",
						CacheZoneSize: "10m",
						CacheKey:      "$scheme$host$request_uri$", // Invalid: ends with $
					},
				},
			},
			isPlus: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePolicy(tc.policy, PolicyValidationConfig{
				IsPlus: tc.isPlus,
			})
			if err == nil {
				t.Errorf("got no errors on invalid Cache policy spec input")
			}
		})
	}
}

func TestValidatePolicy_IsValidCachePolicy(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name   string
		policy *v1.Policy
		isPlus bool
	}{
		{
			name: "basic cache policy",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "basiccache",
						CacheZoneSize: "10m",
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with all options",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName:         "fullcache",
						CacheZoneSize:         "100m",
						AllowedCodes:          []intstr.IntOrString{intstr.FromString("any")},
						AllowedMethods:        []string{"GET", "HEAD", "POST"},
						Time:                  "2h",
						OverrideUpstreamCache: true,
						Levels:                "1:2",
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with purge (NGINX Plus)",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName:   "purgecache",
						CacheZoneSize:   "50m",
						CachePurgeAllow: []string{"10.0.0.0/8", "192.168.1.100"},
					},
				},
			},
			isPlus: true,
		},
		{
			name: "cache policy with IPv6 purge addresses",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName:   "ipv6cache",
						CacheZoneSize:   "20m",
						CachePurgeAllow: []string{"2001:db8::1", "fe80::/64"},
					},
				},
			},
			isPlus: true,
		},
		{
			name: "cache policy with specific allowed codes",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "codecache",
						CacheZoneSize: "15m",
						AllowedCodes:  []intstr.IntOrString{intstr.FromInt(200), intstr.FromInt(404), intstr.FromInt(500)},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with edge case status codes",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "edgecase",
						CacheZoneSize: "5m",
						AllowedCodes:  []intstr.IntOrString{intstr.FromInt(100), intstr.FromInt(599)},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with purge and CIDR range",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName:   "cidrpurge",
						CacheZoneSize:   "20m",
						CachePurgeAllow: []string{"192.168.1.0/24", "10.0.0.1"},
					},
				},
			},
			isPlus: true,
		},
		{
			name: "cache policy with empty allowed codes",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "emptycode",
						CacheZoneSize: "10m",
						AllowedCodes:  []intstr.IntOrString{},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with extended cache key configuration",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "extended",
						CacheZoneSize: "20m",
						CacheKey:      "${scheme}${host}${request_uri}${args}",
						CacheMinUses:  new(5),
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with full manager configuration",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "managercache",
						CacheZoneSize: "30m",
						Manager: &v1.CacheManager{
							Files:     new(200),
							Sleep:     "100ms",
							Threshold: "500ms",
						},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with lock configuration",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "lockcache",
						CacheZoneSize: "15m",
						Lock: &v1.CacheLock{
							Enable:  true,
							Timeout: "30s",
						},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with conditions configuration",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "conditioncache",
						CacheZoneSize: "25m",
						Conditions: &v1.CacheConditions{
							NoCache: []string{"$cookie_nocache", "$arg_nocache"},
							Bypass:  []string{"$http_pragma", "$http_authorization"},
						},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with all extended fields",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "fullextended",
						CacheZoneSize: "100m",
						CacheKey:      "${scheme}${host}${request_uri}",
						CacheMinUses:  new(3),
						UseTempPath:   false,
						MaxSize:       "2g",
						Inactive:      "7d",
						Manager: &v1.CacheManager{
							Files:     new(500),
							Sleep:     "200ms",
							Threshold: "1s",
						},
						Lock: &v1.CacheLock{
							Enable:  true,
							Timeout: "60s",
						},
						Conditions: &v1.CacheConditions{
							NoCache: []string{"$cookie_admin"},
							Bypass:  []string{"$http_cache_control"},
						},
						CacheBackgroundUpdate: true,
						CacheRevalidate:       true,
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with valid cacheUseStale parameters",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "validstale",
						CacheZoneSize: "10m",
						CacheUseStale: []string{"error", "timeout", "http_502"},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with updating parameter (cache specific)",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "staleupdate",
						CacheZoneSize: "10m",
						CacheUseStale: []string{"error", "timeout", "updating"},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with all valid cacheUseStale parameters",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "stallall",
						CacheZoneSize: "10m",
						CacheUseStale: []string{"error", "timeout", "invalid_header", "updating", "http_500", "http_502", "http_503", "http_504"},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with empty cacheUseStale (should be valid)",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "emptystale",
						CacheZoneSize: "10m",
						CacheUseStale: []string{},
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with unbraced cache key variables",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "unbraced",
						CacheZoneSize: "10m",
						CacheKey:      "$scheme$host$request_uri", // Test unbraced NGINX variable format
						Time:          "15m",
					},
				},
			},
			isPlus: false,
		},
		{
			name: "cache policy with mixed braced and unbraced cache key variables",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					Cache: &v1.Cache{
						CacheZoneName: "mixed",
						CacheZoneSize: "10m",
						CacheKey:      "$scheme${host}$request_uri", // Test mixed format
						Time:          "20m",
					},
				},
			},
			isPlus: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePolicy(tc.policy, PolicyValidationConfig{
				IsPlus: tc.isPlus,
			})
			if err != nil {
				t.Errorf("want no errors, got %+v\n", err)
			}
		})
	}
}

func TestValidateCORS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cors      *v1.CORS
		expectErr bool
		errMsg    string
	}{
		{
			name: "Valid CORS configuration",
			cors: &v1.CORS{
				AllowOrigin:  []string{"https://example.com", "https://app.com"},
				AllowMethods: []string{"GET", "POST", "PUT"},
				AllowHeaders: []string{"Content-Type", "Authorization"},
				MaxAge:       new(86400),
			},
			expectErr: false,
		},
		{
			name: "Valid CORS with wildcard origin (no credentials)",
			cors: &v1.CORS{
				AllowOrigin:      []string{"*"},
				AllowMethods:     []string{"GET", "POST"},
				AllowCredentials: new(false),
			},
			expectErr: false,
		},
		{
			name: "Valid CORS with wildcard subdomain",
			cors: &v1.CORS{
				AllowOrigin:  []string{"https://*.example.com"},
				AllowMethods: []string{"GET", "POST"},
			},
			expectErr: false,
		},
		{
			name: "Valid CORS with multiple wildcard subdomains",
			cors: &v1.CORS{
				AllowOrigin:  []string{"https://*.app.com", "https://*.api.example.org"},
				AllowMethods: []string{"GET", "POST"},
			},
			expectErr: false,
		},
		{
			name: "Valid CORS with mixed exact and wildcard origins",
			cors: &v1.CORS{
				AllowOrigin:  []string{"https://example.com", "https://*.dev.example.com"},
				AllowMethods: []string{"GET", "POST"},
			},
			expectErr: false,
		},
		{
			name: "Valid CORS with HTTP wildcard subdomain",
			cors: &v1.CORS{
				AllowOrigin:  []string{"http://*.localhost.com"},
				AllowMethods: []string{"GET", "POST"},
			},
			expectErr: false,
		},
		{
			name: "Invalid origin format - missing protocol",
			cors: &v1.CORS{
				AllowOrigin: []string{"example.com"}, // Missing http:// or https://
			},
			expectErr: true,
			errMsg:    "must start with http:// or https://",
		},
		{
			name: "Invalid wildcard subdomain - empty domain",
			cors: &v1.CORS{
				AllowOrigin: []string{"https://*."}, // Empty domain after wildcard
			},
			expectErr: true,
			errMsg:    "wildcard subdomain cannot be empty",
		},
		{
			name: "Valid wildcard subdomain - single domain",
			cors: &v1.CORS{
				AllowOrigin: []string{"https://*.dev"}, // Single-label domain is valid per k8s DNS rules
			},
			expectErr: false,
		},
		{
			name: "Invalid wildcard subdomain - multiple wildcards",
			cors: &v1.CORS{
				AllowOrigin: []string{"https://*.*.example.com"}, // Multiple wildcards not supported
			},
			expectErr: true,
			errMsg:    "only single-level wildcard subdomains are supported",
		},
		{
			name: "Invalid wildcard subdomain - wildcard in domain",
			cors: &v1.CORS{
				AllowOrigin: []string{"https://*.exam*le.com"}, // Wildcard in domain part
			},
			expectErr: true,
			errMsg:    "only single-level wildcard subdomains are supported",
		},
		{
			name: "Invalid wildcard position",
			cors: &v1.CORS{
				AllowOrigin: []string{"https://example.*.com"}, // Wildcard not at subdomain position
			},
			expectErr: true,
			errMsg:    "wildcards are only supported in subdomain format",
		},
		{
			name: "Invalid wildcard subdomain - invalid domain character",
			cors: &v1.CORS{
				AllowOrigin: []string{"https://*.exam@ple.com"}, // Parsed as user@host
			},
			expectErr: true,
			errMsg:    "origin must not include @",
		},
		{
			name: "Invalid header name - non-RFC compliant",
			cors: &v1.CORS{
				AllowOrigin:  []string{"https://example.com"},
				AllowHeaders: []string{"Content@Type"}, // @ not allowed in header names
			},
			expectErr: true,
			errMsg:    "RFC 7230 violation",
		},
		{
			name: "Invalid expose header name - non-RFC compliant",
			cors: &v1.CORS{
				AllowOrigin:   []string{"https://example.com"},
				ExposeHeaders: []string{"X-Custom-Header", "Invalid Header Name"}, // Space not allowed
			},
			expectErr: true,
			errMsg:    "RFC 7230 violation",
		},
		{
			name: "Duplicate origins - should be blocked",
			cors: &v1.CORS{
				AllowOrigin: []string{"https://example.com", "https://test.com", "https://example.com"}, // Duplicate origin
			},
			expectErr: true,
			errMsg:    "Duplicate value",
		},
		{
			name: "Valid with all HTTP methods",
			cors: &v1.CORS{
				AllowOrigin:  []string{"https://example.com"},
				AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}, // Removed HEAD to avoid redundancy warning
			},
			expectErr: false,
		},
		{
			name: "Forbidden request header - Host",
			cors: &v1.CORS{
				AllowOrigin:  []string{"https://example.com"},
				AllowHeaders: []string{"Host"}, // Forbidden header
			},
			expectErr: true,
			errMsg:    "forbidden request header",
		},
		{
			name: "Forbidden request header - Cookie",
			cors: &v1.CORS{
				AllowOrigin:  []string{"https://example.com"},
				AllowHeaders: []string{"Cookie"}, // Forbidden header
			},
			expectErr: true,
			errMsg:    "forbidden request header",
		},
		{
			name: "Forbidden request header - Sec- prefix",
			cors: &v1.CORS{
				AllowOrigin:  []string{"https://example.com"},
				AllowHeaders: []string{"Sec-WebSocket-Key"}, // Forbidden header
			},
			expectErr: true,
			errMsg:    "forbidden request header",
		},
		{
			name: "Forbidden response header - Set-Cookie",
			cors: &v1.CORS{
				AllowOrigin:   []string{"https://example.com"},
				ExposeHeaders: []string{"Set-Cookie"}, // Forbidden response header per CORS spec
			},
			expectErr: true,
			errMsg:    "forbidden response header",
		},
		{
			name: "Invalid method combination - HEAD with GET",
			cors: &v1.CORS{
				AllowOrigin:  []string{"https://example.com"},
				AllowMethods: []string{"GET", "HEAD", "POST"}, // HEAD redundant when GET present
			},
			expectErr: true,
			errMsg:    "HEAD method should not be explicitly listed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fieldPath := field.NewPath("spec").Child("cors")
			errs := validateCORS(test.cors, fieldPath)

			if test.expectErr {
				if len(errs) == 0 {
					t.Errorf("Expected error but got none")
				} else {
					found := false
					for _, err := range errs {
						if strings.Contains(err.Error(), test.errMsg) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected error message containing '%s' not found in errors: %v", test.errMsg, errs)
					}
				}
			} else {
				if len(errs) > 0 {
					t.Errorf("Expected no errors but got: %v", errs)
				}
			}
		})
	}
}

// TestCORSMDNCompliance tests that our CORS implementation follows MDN guidelines
func TestCORSMDNCompliance(t *testing.T) {
	t.Parallel()

	validConfigs := []struct {
		name        string
		cors        *v1.CORS
		description string
	}{
		{
			name: "Simple request configuration",
			cors: &v1.CORS{
				AllowOrigin:      []string{"*"},
				AllowMethods:     []string{"GET", "POST"}, // Removed HEAD as it's redundant when GET is present
				AllowHeaders:     []string{"Accept", "Accept-Language", "Content-Language", "Content-Type"},
				AllowCredentials: new(false),
			},
			description: "MDN simple request: wildcard allowed without credentials",
		},
		{
			name: "Credentialed request configuration",
			cors: &v1.CORS{
				AllowOrigin:      []string{"https://example.com"},
				AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowHeaders:     []string{"Content-Type", "Authorization"},
				AllowCredentials: new(true),
			},
			description: "MDN credentialed request: explicit origin required",
		},
		{
			name: "Complex request configuration",
			cors: &v1.CORS{
				AllowOrigin:   []string{"https://app.example.com"},
				AllowMethods:  []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
				AllowHeaders:  []string{"Content-Type", "Authorization", "X-Requested-With"},
				ExposeHeaders: []string{"X-Total-Count", "X-RateLimit-Remaining"},
				MaxAge:        new(3600),
			},
			description: "MDN complex request: comprehensive header configuration",
		},
	}

	for _, config := range validConfigs {
		t.Run(config.name, func(t *testing.T) {
			fieldPath := field.NewPath("cors")
			errs := validateCORS(config.cors, fieldPath)

			if len(errs) != 0 {
				t.Errorf("Expected no validation errors for %s, but got: %v", config.description, errs)
			}
		})
	}
}

func TestValidateExternalAuth_PassesOnValidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		externalAuth *v1.ExternalAuth
		msg          string
	}{
		{
			name: "valid authURI and authServiceName only",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
			},
			msg: "valid relative path for authURI with authServiceName",
		},
		{
			name: "valid authURI with complex path",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/api/v1/auth/validate-user",
				AuthServiceName: "auth-svc",
			},
			msg: "valid relative path with multiple segments",
		},
		{
			name: "valid authURI and authSigninURI",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSigninURI:   "/signin",
			},
			msg: "both authURI and authSigninURI as valid relative paths",
		},
		{
			name: "valid authURI with root path",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/",
				AuthServiceName: "auth-svc",
			},
			msg: "authURI with just root path",
		},
		{
			name: "valid path with dashes and underscores",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth/validate-user_session",
				AuthServiceName: "auth-svc",
			},
			msg: "authURI path with dashes and underscores",
		},
		{
			name: "valid path with numbers",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/api/v2/auth/validate",
				AuthServiceName: "auth-svc",
			},
			msg: "authURI path with version numbers",
		},
		{
			name: "valid authSigninURI with complex path",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSigninURI:   "/oauth2/start",
			},
			msg: "authSigninURI with multi-segment path",
		},
		{
			name: "valid authSigninURI omitted",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
			},
			msg: "authSigninURI is optional and can be omitted",
		},
		{
			name: "valid authSigninRedirectBasePath",
			externalAuth: &v1.ExternalAuth{
				AuthURI:                    "/auth",
				AuthServiceName:            "auth-svc",
				AuthSigninRedirectBasePath: "/custom-oauth",
			},
			msg: "authSigninRedirectBasePath with valid path should pass",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fieldPath := field.NewPath("spec").Child("externalAuth")
			allErrs := validateExternalAuth(test.externalAuth, fieldPath, false)
			if len(allErrs) > 0 {
				t.Errorf("validateExternalAuth() returned errors %v for valid input for the case of %v", allErrs, test.msg)
			}
		})
	}
}

func TestValidateExternalAuth_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		externalAuth *v1.ExternalAuth
		msg          string
		errCount     int
	}{
		{
			name: "empty authURI",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "",
				AuthServiceName: "auth-svc",
			},
			msg:      "empty authURI should fail (required field)",
			errCount: 1,
		},
		{
			name: "authURI with only whitespace",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "   ",
				AuthServiceName: "auth-svc",
			},
			msg:      "authURI with whitespace should fail path validation",
			errCount: 1,
		},
		{
			name: "authURI path with invalid characters - braces",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth/{user}/validate",
				AuthServiceName: "auth-svc",
			},
			msg:      "authURI path containing curly braces should fail",
			errCount: 1,
		},
		{
			name: "authURI path with invalid characters - semicolon",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth;validate",
				AuthServiceName: "auth-svc",
			},
			msg:      "authURI path containing semicolon should fail",
			errCount: 1,
		},
		{
			name: "authURI path with invalid characters - whitespace",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth validate",
				AuthServiceName: "auth-svc",
			},
			msg:      "authURI path containing whitespace should fail",
			errCount: 1,
		},
		{
			name: "authURI path with invalid characters - backslash",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth\\validate",
				AuthServiceName: "auth-svc",
			},
			msg:      "authURI path containing backslash should fail",
			errCount: 1,
		},
		{
			name: "authURI path not starting with slash",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "auth/validate",
				AuthServiceName: "auth-svc",
			},
			msg:      "authURI path not starting with / should fail",
			errCount: 1,
		},
		{
			name: "invalid authServiceName with underscore",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "_invalid_hostname",
			},
			msg:      "authServiceName with underscore should fail DNS-1123 validation",
			errCount: 1,
		},
		{
			name: "invalid authServiceName with port",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-server:8080",
			},
			msg:      "authServiceName containing port should fail DNS-1123 validation",
			errCount: 1,
		},
		{
			name: "invalid authServiceName with space",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth server",
			},
			msg:      "authServiceName containing space should fail DNS-1123 validation",
			errCount: 1,
		},
		{
			name: "authSigninURI with only whitespace",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSigninURI:   "   ",
			},
			msg:      "authSigninURI with only whitespace should fail (not empty, so it's validated)",
			errCount: 1,
		},
		{
			name: "invalid authSigninURI path with braces",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSigninURI:   "/signin/{user}",
			},
			msg:      "authSigninURI path containing curly braces should fail",
			errCount: 1,
		},
		{
			name: "invalid authSigninURI path with semicolon",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSigninURI:   "/signin;redirect",
			},
			msg:      "authSigninURI path containing semicolon should fail",
			errCount: 1,
		},
		{
			name: "both authURI and authSigninURI invalid",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth/{user}",
				AuthServiceName: "auth-svc",
				AuthSigninURI:   "/signin/{redirect}",
			},
			msg:      "both fields invalid should return multiple errors",
			errCount: 2,
		},
		{
			name: "authURI path with backslash and brace",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth\\{user}",
				AuthServiceName: "auth-svc",
			},
			msg:      "authURI path with multiple invalid characters should fail",
			errCount: 1,
		},
		{
			name: "invalid authSigninRedirectBasePath with braces",
			externalAuth: &v1.ExternalAuth{
				AuthURI:                    "/auth",
				AuthServiceName:            "auth-svc",
				AuthSigninRedirectBasePath: "/signin/{redirect}",
			},
			msg:      "authSigninRedirectBasePath with curly braces should fail",
			errCount: 1,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fieldPath := field.NewPath("spec").Child("externalAuth")
			allErrs := validateExternalAuth(test.externalAuth, fieldPath, false)
			if len(allErrs) == 0 {
				t.Errorf("validateExternalAuth() returned no errors for invalid input for the case of %v", test.msg)
			} else if test.errCount > 0 && len(allErrs) != test.errCount {
				t.Errorf("validateExternalAuth() returned %d errors, expected %d errors for the case of %v. Errors: %v", len(allErrs), test.errCount, test.msg, allErrs)
			}
		})
	}
}

func TestValidateExternalAuth_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		externalAuth *v1.ExternalAuth
		expectError  bool
		msg          string
	}{
		{
			name: "empty authSigninURI is valid (optional field)",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSigninURI:   "",
			},
			expectError: false,
			msg:         "empty authSigninURI should be valid as it's an optional field",
		},
		{
			name: "authURI with very long path",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/very/long/path/with/many/segments/to/validate/authentication/request/from/client",
				AuthServiceName: "auth-svc",
			},
			expectError: false,
			msg:         "authURI with very long path should be valid",
		},
		{
			name: "authURI with encoded characters in path",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth/validate%20user",
				AuthServiceName: "auth-svc",
			},
			expectError: false,
			msg:         "authURI with URL-encoded characters should be valid",
		},
		{
			name: "authURI with dots in path",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth/v1.0/validate",
				AuthServiceName: "auth-svc",
			},
			expectError: false,
			msg:         "authURI with dots in path should be valid",
		},
		{
			name: "authURI with multiple slashes",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth//validate",
				AuthServiceName: "auth-svc",
			},
			expectError: false,
			msg:         "authURI with consecutive slashes should be valid (NGINX handles this)",
		},
		{
			name: "authURI with trailing slash",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth/validate/",
				AuthServiceName: "auth-svc",
			},
			expectError: false,
			msg:         "authURI with trailing slash should be valid",
		},
		{
			name: "authSigninURI with query parameters",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSigninURI:   "/oauth2/start?rd=https://example.com",
			},
			expectError: false,
			msg:         "authSigninURI with query parameters should be valid",
		},
		{
			name: "authServiceName with full kubernetes DNS name",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/validate",
				AuthServiceName: "my-auth-service.my-namespace.svc.cluster.local",
			},
			expectError: true,
			msg:         "authServiceName with full Kubernetes service DNS name should not be valid",
		},
		{
			name: "empty authServiceName is valid",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "",
			},
			expectError: true,
			msg:         "empty authServiceName should not be valid (required field)",
		},
		{
			name: "sanity check with all fields valid",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSigninURI:   "/signin",
			},
			expectError: false,
			msg:         "normal case for sanity check",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fieldPath := field.NewPath("spec").Child("externalAuth")
			allErrs := validateExternalAuth(test.externalAuth, fieldPath, false)

			if test.expectError && len(allErrs) == 0 {
				t.Errorf("validateExternalAuth() returned no errors for case that should fail: %v", test.msg)
			} else if !test.expectError && len(allErrs) > 0 {
				t.Errorf("validateExternalAuth() returned errors %v for valid input for the case of %v", allErrs, test.msg)
			}
		})
	}
}

func TestValidateExternalAuth_AuthSnippets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		externalAuth   *v1.ExternalAuth
		enableSnippets bool
		expectError    bool
		msg            string
	}{
		{
			name: "authSnippets allowed when snippets enabled",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSnippets:    "proxy_set_header X-Custom-Header value;",
			},
			enableSnippets: true,
			expectError:    false,
			msg:            "authSnippets with enableSnippets=true should be valid",
		},
		{
			name: "authSnippets rejected when snippets disabled",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSnippets:    "proxy_set_header X-Custom-Header value;",
			},
			enableSnippets: false,
			expectError:    true,
			msg:            "authSnippets with enableSnippets=false should be rejected",
		},
		{
			name: "empty authSnippets allowed when snippets disabled",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSnippets:    "",
			},
			enableSnippets: false,
			expectError:    false,
			msg:            "empty authSnippets should be valid regardless of enableSnippets",
		},
		{
			name: "empty authSnippets allowed when snippets enabled",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				AuthSnippets:    "",
			},
			enableSnippets: true,
			expectError:    false,
			msg:            "empty authSnippets should be valid when enableSnippets=true",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fieldPath := field.NewPath("spec").Child("externalAuth")
			allErrs := validateExternalAuth(test.externalAuth, fieldPath, test.enableSnippets)

			if test.expectError && len(allErrs) == 0 {
				t.Errorf("validateExternalAuth() returned no errors for case that should fail: %v", test.msg)
			} else if !test.expectError && len(allErrs) > 0 {
				t.Errorf("validateExternalAuth() returned errors %v for valid input for the case of %v", allErrs, test.msg)
			}
		})
	}
}

func TestValidatePolicy_ExternalAuthWithSnippets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		policy      *v1.Policy
		cfg         PolicyValidationConfig
		expectError bool
		msg         string
	}{
		{
			name: "externalAuth policy with authSnippets and snippets enabled",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					ExternalAuth: &v1.ExternalAuth{
						AuthURI:         "/auth",
						AuthServiceName: "auth-svc",
						AuthSnippets:    "proxy_set_header X-Custom-Header value;",
					},
				},
			},
			cfg:         PolicyValidationConfig{EnableSnippets: true},
			expectError: false,
			msg:         "externalAuth policy with authSnippets should pass when snippets are enabled",
		},
		{
			name: "externalAuth policy with authSnippets and snippets disabled",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					ExternalAuth: &v1.ExternalAuth{
						AuthURI:         "/auth",
						AuthServiceName: "auth-svc",
						AuthSnippets:    "proxy_set_header X-Custom-Header value;",
					},
				},
			},
			cfg:         PolicyValidationConfig{},
			expectError: true,
			msg:         "externalAuth policy with authSnippets should fail when snippets are disabled",
		},
		{
			name: "externalAuth policy without authSnippets and snippets disabled",
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					ExternalAuth: &v1.ExternalAuth{
						AuthURI:         "/auth",
						AuthServiceName: "auth-svc",
					},
				},
			},
			cfg:         PolicyValidationConfig{},
			expectError: false,
			msg:         "externalAuth policy without authSnippets should pass when snippets are disabled",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePolicy(test.policy, test.cfg)
			if test.expectError && err == nil {
				t.Errorf("ValidatePolicy() returned no error for case: %v", test.msg)
			} else if !test.expectError && err != nil {
				t.Errorf("ValidatePolicy() returned error %v for case: %v", err, test.msg)
			}
		})
	}
}

func TestValidateExternalAuth_SSLFields(t *testing.T) {
	t.Parallel()

	validVerifyDepth := 2

	tests := []struct {
		name         string
		externalAuth *v1.ExternalAuth
		expectError  bool
		msg          string
	}{
		{
			name: "valid SSL configuration with all fields",
			externalAuth: &v1.ExternalAuth{
				AuthURI:           "/auth",
				AuthServiceName:   "auth-svc",
				SSLEnabled:        true,
				SSLVerify:         true,
				SSLVerifyDepth:    &validVerifyDepth,
				TrustedCertSecret: "ca-secret",
			},
			expectError: false,
			msg:         "valid SSL configuration with sslEnabled, sslVerify, sslVerifyDepth, and trustedCertSecret",
		},
		{
			name: "valid SSL configuration with sslEnabled only",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				SSLEnabled:      true,
			},
			expectError: false,
			msg:         "SSL enabled without verification is valid",
		},
		{
			name: "sslVerify without sslEnabled should fail",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				SSLEnabled:      false,
				SSLVerify:       true,
			},
			expectError: true,
			msg:         "sslVerify requires sslEnabled to be true",
		},
		{
			name: "trustedCertSecret without sslVerify should fail",
			externalAuth: &v1.ExternalAuth{
				AuthURI:           "/auth",
				AuthServiceName:   "auth-svc",
				SSLEnabled:        true,
				SSLVerify:         false,
				TrustedCertSecret: "ca-secret",
			},
			expectError: true,
			msg:         "trustedCertSecret requires sslVerify to be true",
		},
		{
			name: "valid sslEnabled and sslVerify without trustedCertSecret",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				SSLEnabled:      true,
				SSLVerify:       true,
			},
			expectError: false,
			msg:         "sslVerify without trustedCertSecret is valid (uses default CA bundle)",
		},
		{
			name: "valid trustedCertSecret with namespace prefix",
			externalAuth: &v1.ExternalAuth{
				AuthURI:           "/auth",
				AuthServiceName:   "auth-svc",
				SSLEnabled:        true,
				SSLVerify:         true,
				TrustedCertSecret: "other-ns/ca-secret",
			},
			expectError: false,
			msg:         "trustedCertSecret with namespace prefix is valid",
		},
		{
			name: "valid sniName with SSL enabled and verify",
			externalAuth: &v1.ExternalAuth{
				AuthURI:         "/auth",
				AuthServiceName: "auth-svc",
				SSLEnabled:      true,
				SSLVerify:       true,
				SNIName:         "auth.example.com",
			},
			expectError: false,
			msg:         "explicit sniName is valid when sslVerify is enabled",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fieldPath := field.NewPath("spec").Child("externalAuth")
			allErrs := validateExternalAuth(test.externalAuth, fieldPath, false)
			if test.expectError && len(allErrs) == 0 {
				t.Errorf("validateExternalAuth() returned no errors for case: %v", test.msg)
			} else if !test.expectError && len(allErrs) > 0 {
				t.Errorf("validateExternalAuth() returned errors %v for case: %v", allErrs, test.msg)
			}
		})
	}
}

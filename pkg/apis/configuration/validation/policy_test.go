package validation

import (
	"testing"

	v1 "github.com/nginx/kubernetes-ingress/pkg/apis/configuration/v1"
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
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePolicy(tc.policy, true, false, false)
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
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePolicy(tc.policy, true, false, false)
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePolicy(tc.policy, true, false, false)
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
		policy           *v1.Policy
		isPlus           bool
		enableOIDC       bool
		enableAppProtect bool
		msg              string
	}{
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					AccessControl: &v1.AccessControl{
						Allow: []string{"127.0.0.1"},
					},
				},
			},
			isPlus:           false,
			enableOIDC:       false,
			enableAppProtect: false,
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
			isPlus:           true,
			enableOIDC:       false,
			enableAppProtect: false,
			msg:              "use jwt(plus only) policy",
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
						ZoneSyncLeeway:        createPointerFromInt(10),
						AccessTokenEnable:     true,
					},
				},
			},
			isPlus:     true,
			enableOIDC: true,
			msg:        "use OIDC (plus only)",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					WAF: &v1.WAF{
						Enable: true,
					},
				},
			},
			isPlus:           true,
			enableOIDC:       false,
			enableAppProtect: true,
			msg:              "use WAF(plus only) policy",
		},
	}
	for _, test := range tests {
		err := ValidatePolicy(test.policy, test.isPlus, test.enableOIDC, test.enableAppProtect)
		if err != nil {
			t.Errorf("ValidatePolicy() returned error %v for valid input for the case of %v", err, test.msg)
		}
	}
}

func TestValidatePolicy_FailsOnInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		policy           *v1.Policy
		isPlus           bool
		enableOIDC       bool
		enableAppProtect bool
		msg              string
	}{
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{},
			},
			isPlus:           false,
			enableOIDC:       false,
			enableAppProtect: false,
			msg:              "empty policy spec",
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
			isPlus:           true,
			enableOIDC:       false,
			enableAppProtect: false,
			msg:              "multiple policies in spec",
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
			isPlus:           false,
			enableOIDC:       false,
			enableAppProtect: false,
			msg:              "jwt(plus only) policy on OSS",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					WAF: &v1.WAF{
						Enable: true,
					},
				},
			},
			isPlus:           false,
			enableOIDC:       false,
			enableAppProtect: false,
			msg:              "WAF(plus only) policy on OSS",
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
			isPlus:     true,
			enableOIDC: false,
			msg:        "OIDC policy with enable OIDC flag disabled",
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
			isPlus:     false,
			enableOIDC: true,
			msg:        "OIDC policy in OSS",
		},
		{
			policy: &v1.Policy{
				Spec: v1.PolicySpec{
					WAF: &v1.WAF{
						Enable: true,
					},
				},
			},
			isPlus:           true,
			enableOIDC:       false,
			enableAppProtect: false,
			msg:              "WAF policy with AP disabled",
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
						ZoneSyncLeeway:        createPointerFromInt(-1),
						AccessTokenEnable:     false,
					},
				},
			},
			isPlus:     true,
			enableOIDC: true,
			msg:        "OIDC policy with invalid ZoneSyncLeeway",
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
			isPlus:     true,
			enableOIDC: true,
			msg:        "OIDC policy with invalid AuthExtraArgs",
		},
	}
	for _, test := range tests {
		err := ValidatePolicy(test.policy, test.isPlus, test.enableOIDC, test.enableAppProtect)
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
	dryRun := true
	noDelay := false

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
				Delay:      createPointerFromInt(5),
				NoDelay:    &noDelay,
				Burst:      createPointerFromInt(10),
				ZoneSize:   "10M",
				DryRun:     &dryRun,
				LogLevel:   "info",
				RejectCode: createPointerFromInt(505),
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
				r.Delay = createPointerFromInt(0)
			}),
			isPlus: false,
			msg:    "invalid rateLimit delay",
		},
		{
			rateLimit: createInvalidRateLimit(func(r *v1.RateLimit) {
				r.Burst = createPointerFromInt(0)
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
				r.RejectCode = createPointerFromInt(600)
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
			t.Errorf("validatePositiveInt(%q) returned errors %v for valid input", input, allErrs)
		}
	}
}

func TestValidatePositiveInt_ErrorsOnInvalidInput(t *testing.T) {
	t.Parallel()

	invalidInput := []int{-1, 0}

	for _, input := range invalidInput {
		allErrs := validatePositiveInt(input, field.NewPath("int"))
		if len(allErrs) == 0 {
			t.Errorf("validatePositiveInt(%q) returned no errors for invalid input", input)
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
				VerifyDepth:      createPointerFromInt(1),
			},
			msg: "all parameters with default value",
		},
		{
			ing: &v1.IngressMTLS{
				ClientCertSecret: "ingress-mtls-secret",
				VerifyClient:     "optional",
				VerifyDepth:      createPointerFromInt(2),
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
				VerifyDepth:      createPointerFromInt(-1),
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
				VerifyDepth:       createPointerFromInt(2),
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
				VerifyDepth:       createPointerFromInt(-1),
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
				ZoneSyncLeeway:        createPointerFromInt(20),
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
				ZoneSyncLeeway:    createPointerFromInt(-1),
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

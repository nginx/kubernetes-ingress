//go:build aws

package main

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidClaims(t *testing.T) {
	iat := *jwt.NewNumericDate(time.Now().Add(time.Hour * -1))

	c := claims{
		"test",
		1,
		"nonce",
		jwt.RegisteredClaims{
			IssuedAt: &iat,
		},
	}
	v := jwt.NewValidator(
		jwt.WithIssuedAt(),
	)
	if err := v.Validate(c); err != nil {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", nil, err)
	}
}

func TestInvalidClaims(t *testing.T) {
	type fields struct {
		leeway       time.Duration
		timeFunc     func() time.Time
		expectedAud  string
		expectAllAud []string
		expectedIss  string
		expectedSub  string
	}
	type args struct {
		claims jwt.Claims
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name:    "missing ProductCode",
			fields:  fields{},
			args:    args{jwt.RegisteredClaims{}},
			wantErr: ErrMissingProductCode,
		},
		{
			name:    "missing Nonce",
			fields:  fields{},
			args:    args{jwt.RegisteredClaims{}},
			wantErr: ErrMissingNonce,
		},
		{
			name:    "missing PublicKeyVersion",
			fields:  fields{},
			args:    args{jwt.RegisteredClaims{}},
			wantErr: ErrMissingKeyVersion,
		},
		{
			name:    "iat is in the future",
			fields:  fields{},
			args:    args{jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Hour * +2))}},
			wantErr: jwt.ErrTokenUsedBeforeIssued,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := jwt.NewValidator(
				jwt.WithLeeway(tt.fields.leeway),
				jwt.WithTimeFunc(tt.fields.timeFunc),
				jwt.WithIssuedAt(),
				jwt.WithAudience(tt.fields.expectedAud),
				jwt.WithAllAudiences(tt.fields.expectAllAud...),
				jwt.WithIssuer(tt.fields.expectedIss),
				jwt.WithSubject(tt.fields.expectedSub),
			)
			if err := v.Validate(tt.args.claims); (err != nil) && !errors.Is(err, tt.wantErr) {
				t.Errorf("validator.Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

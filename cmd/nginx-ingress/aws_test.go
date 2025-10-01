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
	if err := c.Valid(); err != nil {
		t.Fatalf("Failed to verify claims, wanted: %v got %v", nil, err)
	}
}

func TestInvalidClaims(t *testing.T) {
	badClaims := []struct {
		c             claims
		expectedError error
	}{
		{
			claims{
				"",
				1,
				"nonce",
				jwt.RegisteredClaims{
					IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Hour * -1)),
				},
			},
			errors.New("token doesn't include the ProductCode"),
		},
		{
			claims{
				"productCode",
				1,
				"",
				jwt.RegisteredClaims{
					IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Hour * -1)),
				},
			},
			errors.New("token doesn't include the Nonce"),
		},
		{
			claims{
				"productCode",
				0,
				"nonce",
				jwt.RegisteredClaims{
					IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Hour * -1)),
				},
			},
			errors.New("token doesn't include the PublicKeyVersion"),
		},
		{
			claims{
				"test",
				1,
				"nonce",
				jwt.RegisteredClaims{
					IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Hour * +2)),
				},
			},
			errors.New("token used before issued"),
		},
	}

	for _, badC := range badClaims {

		err := badC.c.Valid()
		if err == nil {
			t.Errorf("Valid() returned no error when it should have returned error %q", badC.expectedError)
		} else if err.Error() != badC.expectedError.Error() {
			t.Errorf("Valid() returned error %q when it should have returned error %q", err, badC.expectedError)
		}
	}
}

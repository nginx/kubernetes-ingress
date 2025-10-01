//go:build aws

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering/types"

	"github.com/golang-jwt/jwt/v5"
)

var (
	productCode   string
	pubKeyVersion int32 = 1
	pubKeyString  string
)

func init() {
	startupCheckFn = checkAWSEntitlement
}

func checkAWSEntitlement() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nonce, err := generateRandomString(255)
	if err != nil {
		return err
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("error loading AWS configuration: %w", err)
	}

	mpm := marketplacemetering.NewFromConfig(cfg)

	out, err := mpm.RegisterUsage(ctx, &marketplacemetering.RegisterUsageInput{ProductCode: &productCode, PublicKeyVersion: &pubKeyVersion, Nonce: &nonce})
	if err != nil {
		var notEnt *types.CustomerNotEntitledException
		var invRegion *types.InvalidRegionException
		var platNotSup *types.PlatformNotSupportedException
		if errors.As(err, &notEnt) {
			return fmt.Errorf("user not entitled, code: %v, message: %v, fault: %v", notEnt.ErrorCode(), notEnt.ErrorMessage(), notEnt.ErrorFault().String())
		}
		if errors.As(err, &invRegion) {
			return fmt.Errorf("invalid region, code: %v, message: %v, fault: %v", invRegion.ErrorCode(), invRegion.ErrorMessage(), invRegion.ErrorFault().String())
		}
		if errors.As(err, &platNotSup) {
			return fmt.Errorf("platform not supported, code: %v, message: %v, fault: %v", platNotSup.ErrorCode(), platNotSup.ErrorMessage(), platNotSup.ErrorFault().String())
		}
		return err
	}

	token, err := jwt.ParseWithClaims(*out.Signature, &claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		pk, err := base64.StdEncoding.DecodeString(pubKeyString)
		if err != nil {
			return nil, fmt.Errorf("error decoding Public Key string: %w", err)
		}
		pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pk)
		if err != nil {
			return nil, fmt.Errorf("error parsing Public Key: %w", err)
		}

		return pubKey, nil
	})

	if claims, ok := token.Claims.(*claims); ok && token.Valid {
		if claims.ProductCode != productCode || claims.PublicKeyVersion != pubKeyVersion || claims.Nonce != nonce {
			return fmt.Errorf("the claims in the JWT token don't match the request")
		}
	} else {
		return fmt.Errorf("something is wrong with the JWT token: %w", err)
	}
	return nil
}

type claims struct {
	ProductCode      string `json:"productCode,omitempty"`
	PublicKeyVersion int32  `json:"publicKeyVersion,omitempty"`
	Nonce            string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

func (c claims) Valid() error {
	if c.Nonce == "" {
		return jwt.NewValidationError("token doesn't include the Nonce", jwt.ValidationErrorClaimsInvalid)
	}
	if c.ProductCode == "" {
		return jwt.NewValidationError("token doesn't include the ProductCode", jwt.ValidationErrorClaimsInvalid)
	}
	if c.PublicKeyVersion == 0 {
		return jwt.NewValidationError("token doesn't include the PublicKeyVersion", jwt.ValidationErrorClaimsInvalid)
	}

	if err := c.RegisteredClaims.Valid(); err != nil {
		return err
	}

	return nil
}

func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

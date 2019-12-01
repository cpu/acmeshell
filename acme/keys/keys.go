// package keys offers utility functions for working with crypto.Signers, JWS,
// JWKs and PEM serialization.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	jose "gopkg.in/square/go-jose.v2"
)

func sigAlgForKey(signer crypto.Signer) jose.SignatureAlgorithm {
	switch signer.(type) {
	case *ecdsa.PrivateKey:
		return jose.ES256
	case *rsa.PrivateKey:
		return jose.RS256
	}
	return "unknown"
}

func algForKey(signer crypto.Signer) string {
	switch signer.(type) {
	case *ecdsa.PrivateKey:
		return "ECDSA"
	case *rsa.PrivateKey:
		return "RSA"
	}
	return "unknown"
}

func JWKJSON(signer crypto.Signer) string {
	jwk := JWKForSigner(signer)
	jwkJSON, err := json.Marshal(&jwk)
	if err != nil {
		return ""
	}
	return string(jwkJSON)
}

func JWKThumbprintBytes(signer crypto.Signer) []byte {
	jwk := JWKForSigner(signer)
	thumbBytes, _ := jwk.Thumbprint(crypto.SHA256)
	return thumbBytes
}

func JWKThumbprint(signer crypto.Signer) string {
	thumbprintBytes := JWKThumbprintBytes(signer)
	return base64.RawURLEncoding.EncodeToString(thumbprintBytes)
}

func KeyAuth(signer crypto.Signer, token string) string {
	return fmt.Sprintf("%s.%s", JWKThumbprint(signer), token)
}

func JWKForSigner(signer crypto.Signer) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       signer.Public(),
		Algorithm: algForKey(signer),
	}
}

func SigningKeyForSigner(signer crypto.Signer, keyID string) jose.SigningKey {
	jwk := jose.JSONWebKey{
		Key:       signer,
		Algorithm: string(sigAlgForKey(signer)),
		KeyID:     keyID,
	}
	return jose.SigningKey{
		Key:       jwk,
		Algorithm: sigAlgForKey(signer),
	}
}

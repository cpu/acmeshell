// package keys offers utility functions for working with crypto.Signers, JWS,
// JWKs and PEM serialization.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
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
	return fmt.Sprintf("%s.%s", token, JWKThumbprint(signer))
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

func MarshalSigner(signer crypto.Signer) ([]byte, string, error) {
	var keyBytes []byte
	var keyType string
	var err error
	switch k := signer.(type) {
	case *ecdsa.PrivateKey:
		keyType = "ecdsa"
		keyBytes, err = x509.MarshalECPrivateKey(k)
	case *rsa.PrivateKey:
		keyType = "rsa"
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
	default:
		err = fmt.Errorf("signer was unknown type: %T", k)
	}
	if err != nil {
		return nil, "", err
	}
	return keyBytes, keyType, nil
}

func UnmarshalSigner(keyBytes []byte, keyType string) (crypto.Signer, error) {
	var privKey crypto.Signer
	var err error
	switch keyType {
	case "ecdsa":
		privKey, err = x509.ParseECPrivateKey(keyBytes)
	case "rsa":
		privKey, err = x509.ParsePKCS1PrivateKey(keyBytes)
	default:
		err = fmt.Errorf("unknown key type %q", keyType)
	}
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func SignerToPEM(signer crypto.Signer) (string, error) {
	var keyBytes []byte
	var keyHeader string
	var err error
	switch k := signer.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(k)
		keyHeader = "EC PRIVATE KEY"
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
		keyHeader = "RSA PRIVATE KEY"
	default:
		err = fmt.Errorf("unknown key type: %T", k)
	}
	if err != nil {
		return "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  keyHeader,
		Bytes: keyBytes,
	})
	return string(pemBytes), nil
}

func NewSigner(keyType string) (crypto.Signer, error) {
	var randKey crypto.Signer
	var err error
	switch keyType {
	case "ecdsa":
		randKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		randKey, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		err = fmt.Errorf("unknown key type: %q", keyType)
	}
	if err != nil {
		return nil, err
	}
	return randKey, nil
}

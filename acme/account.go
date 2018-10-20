package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	jose "gopkg.in/square/go-jose.v2"
)

type Account struct {
	ID         string
	Contact    []string
	PrivateKey *ecdsa.PrivateKey

	Orders []string
}

func (a Account) String() string {
	return a.ID
}

func NewAccount(emails []string, privKey *ecdsa.PrivateKey) (*Account, error) {
	var contacts []string
	if len(emails) > 0 {
		for _, e := range emails {
			if e == "" {
				continue
			}
			contacts = append(contacts, fmt.Sprintf("mailto:%s", e))
		}
	}

	if privKey == nil {
		randKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		privKey = randKey
	}

	return &Account{
		Contact:    contacts,
		PrivateKey: privKey,
	}, nil
}

type SignOptions struct {
	PrintJWS       bool
	PrintJWSObject bool
	PrintJSON      bool
	EmbedKey       bool
	KeyID          string
	Key            *ecdsa.PrivateKey
	NonceSource    jose.NonceSource
}

func (opts *SignOptions) validate() error {
	if opts.KeyID != "" && opts.EmbedKey {
		return fmt.Errorf("SignOptions validate: cannot specify both KeyID and EmbedKey")
	}
	if opts.KeyID == "" && !opts.EmbedKey {
		return fmt.Errorf("SignOptions validate: you must specify a KeyID or EmbedKey")
	}
	if opts.NonceSource == nil {
		return fmt.Errorf("SignOptions validate: you must specify a NonceSource")
	}
	if opts.Key == nil {
		return fmt.Errorf("SignOptions validate: you must specify a private key")
	}
	return nil
}

func (acct *Account) Sign(url string, data []byte, opts SignOptions) ([]byte, error) {
	if opts.Key == nil {
		opts.Key = acct.PrivateKey
	}

	if !opts.EmbedKey && opts.KeyID == "" {
		opts.KeyID = acct.ID
	}

	if err := opts.validate(); err != nil {
		return nil, err
	}

	if opts.EmbedKey {
		return signEmbedded(url, data, opts)
	}

	return signKeyID(url, data, opts)
}

func signEmbedded(url string, data []byte, opts SignOptions) ([]byte, error) {
	privKey := opts.Key
	if privKey == nil {
		return nil, fmt.Errorf("signEmbedded: account has a nil privateKey")
	}

	// TODO(@cpu): Figure out a way to log to the client Printf
	if opts.PrintJSON {
		log.Printf("Request JSON Body: \n%s\n", string(data))
	}

	signingKey := jose.SigningKey{
		Key:       privKey,
		Algorithm: jose.ES256,
	}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{
		NonceSource: opts.NonceSource,
		EmbedJWK:    true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	})
	if err != nil {
		return nil, err
	}

	return sign(signer, data, opts)
}

func signKeyID(url string, data []byte, opts SignOptions) ([]byte, error) {
	privKey := opts.Key
	if opts.KeyID == "" {
		return nil, fmt.Errorf("sign: empty KeyID")
	}

	jwk := &jose.JSONWebKey{
		Key:       privKey,
		Algorithm: "ECDSA",
		KeyID:     opts.KeyID,
	}

	signerKey := jose.SigningKey{
		Key:       jwk,
		Algorithm: jose.ES256,
	}

	joseOpts := &jose.SignerOptions{
		NonceSource: opts.NonceSource,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	signer, err := jose.NewSigner(signerKey, joseOpts)
	if err != nil {
		return nil, err
	}

	return sign(signer, data, opts)
}

func sign(signer jose.Signer, data []byte, opts SignOptions) ([]byte, error) {
	signed, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}

	postBody := []byte(signed.FullSerialize())

	// Reparse the serialized body to get a fully populated JWS object to log
	var parsedJWS *jose.JSONWebSignature
	parsedJWS, err = jose.ParseSigned(string(postBody))
	if err != nil {
		return nil, err
	}

	// TODO(@cpu): Figure out a way to log to the client Printf
	if opts.PrintJWSObject {
		log.Printf("Request JWS Object: \n%#v\n", parsedJWS)
	}
	if opts.PrintJWS {
		log.Printf("Request JWS Body: \n%s\n", string(postBody))
	}

	return postBody, nil
}

type rawAccount struct {
	ID         string
	Contact    []string
	PrivateKey []byte
}

func (acct *Account) save() ([]byte, error) {
	k, err := x509.MarshalECPrivateKey(acct.PrivateKey)
	if err != nil {
		return nil, err
	}

	rawAcct := rawAccount{
		ID:         acct.ID,
		Contact:    acct.Contact,
		PrivateKey: k,
	}
	frozenAcct, err := json.MarshalIndent(rawAcct, "", "  ")
	if err != nil {
		return nil, err
	}
	return frozenAcct, nil
}

func (acct *Account) restore(frozenAcct []byte) error {
	var rawAcct rawAccount

	err := json.Unmarshal(frozenAcct, &rawAcct)
	if err != nil {
		return err
	}

	privKey, err := x509.ParseECPrivateKey(rawAcct.PrivateKey)
	if err != nil {
		return err
	}

	acct.ID = rawAcct.ID
	acct.Contact = rawAcct.Contact
	acct.PrivateKey = privKey
	return nil
}

func RestoreAccount(path string) (*Account, error) {
	acct := &Account{}
	frozenBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return acct, err
	}

	err = acct.restore(frozenBytes)
	return acct, err
}

func SaveAccount(path string, account *Account) error {
	frozenBytes, err := account.save()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, frozenBytes, os.ModePerm)
}

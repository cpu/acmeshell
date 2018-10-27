// Package resources provides types for representing and interacting with ACME
// protocol resources.
package resources

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	jose "gopkg.in/square/go-jose.v2"
)

// Account holds information related to a single ACME Account resource. If the
// account has an empty ID it has not yet been created server-side with the ACME
// server using the client.CreateAccount function.
//
// The ID field holds the server assigned Account ID that is assigned at the
// time of account creation and used as the JWS KeyID for authenticating ACME
// requests with the Account's registered keypair.
//
// The Contact field is either nil or a slice of one or more email addresses
// to be used as the ACME Account's "mailto://" Contact addresses.
//
// The PrivateKey field is a pointer to a private key used for the ACME
// account's keypair. The public component is computed from this private key
// automatically.
//
// The Orders field is either nil or a slice of one or more Order resource URLs.
// These URLs correspond to Orders that the Account created with the ACME
// server.
type Account struct {
	// The server assigned Account ID. This is used for the JWS KeyID when
	// authenticating ACME requests using the Account's registered keypair.
	ID string
	// If not nil, a slice of one or more email addresses to be used as the ACME
	// Account's "mailto://" Contact addresses.
	Contact []string
	// A pointer to a private key used for the ACME account's
	// keypair.
	//
	// TODO(@cpu): This should be using the right interface instead of restricting
	// usage to ECDSA instances.
	PrivateKey *ecdsa.PrivateKey
	// If not nil, a slice of URLs for Order resources the Account created with
	// the ACME server.
	Orders []string
}

// String returns the Account's ID or an empty string if it has not been created
// with the ACME server.
func (a Account) String() string {
	return a.ID
}

// NewAccount creates an ACME account in-memory. *Important:* the
// created Account is *not* registered with the ACME server until
// it is explicitly "created" server-side using a Client instance's
// CreateAccount function.
//
// the emails argument is a slice of zero or more email addresses that should be
// used as the Account's Contact information.
//
// the privKey argument is a pointer to a private key that should be used for
// the Account keypair. It will be used to create JWS for requests when the
// Account is a Client's ActiveAccount. If the privKey argument is nil a new
// randomly generated private key will be used for the Account key.
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

// SaveAccount persists the given Account object (which must not be nil) to the
// given file path. If any errors occur serializing the account it will be
// returned.
func SaveAccount(path string, account *Account) error {
	if account == nil {
		return fmt.Errorf("account must not be nil")
	}
	// serialize the account
	frozenBytes, err := account.save()
	if err != nil {
		return err
	}
	// write the serialized data to the provided filepath
	return ioutil.WriteFile(path, frozenBytes, os.ModePerm)
}

// RestoreAccount loads a previously saved Account object from the given file
// path. This file should have been created using SaveAccount in a previous
// session. If any errors occur deserializing an Account from the data in the
// provided filepath a nil Account instance and a non-nil error will be
// returned.
func RestoreAccount(path string) (*Account, error) {
	acct := &Account{}
	frozenBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return acct, err
	}

	err = acct.restore(frozenBytes)
	return acct, err
}

// SigningOptions allows specifying signature related options when calling an
// Account's Sign function.
type SigningOptions struct {
	// If true, embed the Account's public key as a JWK in the signed JWS instead
	// of using a KeyID header. This is useful for endpoints like NewAccount.
	// Setting EmbedKey to true is mutually exclusive with a non-empty KeyID.
	EmbedKey bool
	// If not-empty, a KeyID value to use for the JWS Key ID header to identify the ACME
	// account. If empty the Account's ID field will be used. Providing a KeyID is
	// mutually exclusive with setting EmbedKey to true.
	KeyID string
	// If not-nil, a PrivateKey to use to sign the JWS. The associated public key
	// will be computed and used for the embedded JWK if EmbedKey is true. If nil
	// the PrivateKey is assumed to be the Account's key.
	Key *ecdsa.PrivateKey
	// NonceSource is a jose.NonceSource implementation that provides the
	// Replay-Nonce header value for the produced JWS. Often this will be a Client
	// instance.
	NonceSource jose.NonceSource
}

// validate checks that the SigningOptions are sensible. This enforces the mutually
// exclusive KeyID and EmbedKey options and ensures that the NonceSource and Key
// are not nil. Because it checks that the Key field is not nil it must only be
// called after populating a default (like an Account's key).
func (opts *SigningOptions) validate() error {
	if opts.KeyID != "" && opts.EmbedKey {
		return fmt.Errorf("SigningOptions validate: cannot specify both KeyID and EmbedKey")
	}
	if opts.KeyID == "" && !opts.EmbedKey {
		return fmt.Errorf("SigningOptions validate: you must specify a KeyID or EmbedKey")
	}
	if opts.NonceSource == nil {
		return fmt.Errorf("SigningOptions validate: you must specify a NonceSource")
	}
	if opts.Key == nil {
		return fmt.Errorf("SigningOptions validate: you must specify a private key")
	}
	return nil
}

// SignResult holds the input and output from a Sign operation.
type SignResult struct {
	// The url argument given to Sign.
	InputURL string
	// The data argument given to sign.
	InputData []byte
	// The JWS produced by signing the given data.
	JWS *jose.JSONWebSignature
	// The JWS in serialized form.
	SerializedJWS []byte
}

// Sign produces a SignResult for the given data. The url argument will be used
// as the result JWS' protected "url" header. The provided opts allow
// customizing the JWS, including whether a JWK is embedded or a protected KeyID
// header is used. If the SigningOptions specify a nil PrivateKey the Account's key
// will be used, otherwise the SigningOptions key takes precedence. If the
// SigningOptions do not specify a KeyID or that JWK embedding should be used then
// the Key ID will default to the Account's ID.
func (acct *Account) Sign(url string, data []byte, opts SigningOptions) (*SignResult, error) {
	// If there is no key specified, use the account key by default
	if opts.Key == nil {
		opts.Key = acct.PrivateKey
	}

	// If there is no request to embed a JWK in the options and there is no
	// explicit KeyID provided use the Account's ID as the KeyID
	if !opts.EmbedKey && opts.KeyID == "" {
		opts.KeyID = acct.ID
	}

	// Now that the defaults are populated check that the resulting options are
	// valid.
	if err := opts.validate(); err != nil {
		return nil, err
	}

	if opts.EmbedKey {
		return signEmbedded(url, data, opts)
	}
	return signKeyID(url, data, opts)
}

func signEmbedded(url string, data []byte, opts SigningOptions) (*SignResult, error) {
	privKey := opts.Key
	if privKey == nil {
		return nil, fmt.Errorf("signEmbedded: account has a nil privateKey")
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

	return sign(signer, url, data, opts)
}

func signKeyID(url string, data []byte, opts SigningOptions) (*SignResult, error) {
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

	return sign(signer, url, data, opts)
}

func sign(signer jose.Signer, url string, data []byte, opts SigningOptions) (*SignResult, error) {
	signed, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}

	serialized := []byte(signed.FullSerialize())

	// Reparse the serialized body to get a fully populated JWS object to log
	var parsedJWS *jose.JSONWebSignature
	parsedJWS, err = jose.ParseSigned(string(serialized))
	if err != nil {
		return nil, err
	}

	return &SignResult{
		InputURL:      url,
		InputData:     data,
		JWS:           parsedJWS,
		SerializedJWS: serialized,
	}, nil
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

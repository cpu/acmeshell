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
	"log"
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

// SignOptions allows specifying signature related options when calling an
// Account's Sign function.
//
// TODO(@cpu): There should be a response object from Sign that contains data
// that we would want to print to stdout that we can bubble up instead of
// printing in the client package and coupling this to one output format/sink.
//
// TODO(@cpu): This should be renamed to "SigningOptions" to read more
// naturally.
type SignOptions struct {
	// Print the JSON representation of the signed JWS to stdout.
	PrintJWS bool
	// Print the go-jose JWS object to stdout.
	PrintJWSObject bool
	// Print the input data that is being signed to stdout.
	// TODO(@cpu): This should be renamed from PrintJSON to PrintData or something
	// similar.
	PrintJSON bool
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

// validate checks that the SignOptions are sensible. This enforces the mutually
// exclusive KeyID and EmbedKey options and ensures that the NonceSource and Key
// are not nil. Because it checks that the Key field is not nil it must only be
// called after populating a default (like an Account's key).
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

// Sign produces a serialized JWS for the given data. The url argument will be
// used as the JWS' protected "url" header. The provided opts allow customizing
// the output and options for the JWS, including whether a JWK is embedded or
// a protected KeyID header is used. If the SignOptions specify a nil PrivateKey
// the Account's key will be used, otherwise the SignOptions key takes
// precedence. If the SignOptions do not specify a KeyID or that JWK embedding
// should be used then the Key ID will default to the Account's ID.
//
// TODO(@cpu): This should return a struct object that has the JWS object, the
// signing options and request data that were used, and the serialized
// representation of the JWS. That will allow removing the stdout printing and
// provide more flexibility.
func (acct *Account) Sign(url string, data []byte, opts SignOptions) ([]byte, error) {
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

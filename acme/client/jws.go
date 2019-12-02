package client

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/cpu/acmeshell/acme/keys"

	jose "gopkg.in/square/go-jose.v2"
)

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
	// A Signer to use to sign the JWS. The associated public key
	// will be computed and used for the embedded JWK if EmbedKey is true.
	Signer crypto.Signer
	// NonceSource is a jose.NonceSource implementation that provides the
	// Replay-Nonce header value for the produced JWS. Often this will be a Client
	// instance.
	NonceSource jose.NonceSource
}

// validate checks that the SigningOptions are sensible. This enforces the mutually
// exclusive KeyID and EmbedKey options and ensures that the NonceSource and Signer
// are not nil. Because it checks that the Signer field is not nil it must only be
// called after populating a default (like an Account's signer).
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
	if opts.Signer == nil {
		return fmt.Errorf("SigningOptions validate: you must specify a signer")
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

// Sign produces a SignResult by Signing the provided data (with a protected URL
// header) according to the SigningOptions provided. If no Signer is specified in
// the SigningOptions then the ActiveAccount's Signer is used. If the
// SigningOptions specify not to embed a JWK but do not specify a Key ID to use
// then the ActiveAccount's ID is used as the JWS Key ID. If the SigningOptions
// do not specify an explicit NonceSource the Client is used as the NonceSource.
func (c *Client) Sign(url string, data []byte, opts *SigningOptions) (*SignResult, error) {
	if opts == nil {
		opts = &SigningOptions{}
	}
	// If there is no Signer and no ActiveAccount we can't proceed
	if opts.Signer == nil && c.ActiveAccount == nil {
		return nil, errors.New(
			"ActiveAccount is nil and no Signer was specified in SigningOptions")
	} else if opts.Signer == nil && c.ActiveAccount != nil {
		// If there is no specified Signer, use the ActiveAccount's signer
		opts.Signer = c.ActiveAccount.Signer
	}

	// If there is no EmbedKey specified and there is no KeyID specified, and
	// there is no ActiveAccount, we can't proceed.
	if !opts.EmbedKey && opts.KeyID == "" && c.ActiveAccount == nil {
		return nil, errors.New(
			"SigningOptions EmbedKey was false, no KeyID was specified, and " +
				"there is no ActiveAccount")
	} else if !opts.EmbedKey && opts.KeyID == "" && c.ActiveAccount != nil {
		opts.KeyID = c.ActiveAccount.ID
	}

	// If there is no explicit NonceSource specified, use the client.
	if opts.NonceSource == nil {
		opts.NonceSource = c
	}

	// If there is no request to embed a JWK in the options and there is no
	// explicit KeyID provided use the Account's ID as the KeyID
	if !opts.EmbedKey && opts.KeyID == "" {
		return nil, errors.New("SigningOptions did not specify EmbedKey or include a KeyID")
	}

	// Now that the defaults are populated check that the resulting options are
	// valid.
	if err := opts.validate(); err != nil {
		return nil, err
	}

	if c.Output.PrintSignedData {
		c.Printf("Signing:\n%s\n", data)
	}

	var signResult *SignResult
	var err error
	if opts.EmbedKey {
		signResult, err = signEmbedded(url, data, *opts)
	} else {
		signResult, err = signKeyID(url, data, *opts)
	}

	if err == nil && c.Output.PrintJWS {
		c.Printf("JWS:\n%s\n", string(signResult.SerializedJWS))
	}
	return signResult, err
}

func signEmbedded(url string, data []byte, opts SigningOptions) (*SignResult, error) {
	privKey := opts.Signer
	if privKey == nil {
		return nil, fmt.Errorf("signEmbedded: account has a nil Signer")
	}

	signingKey := keys.SigningKeyForSigner(privKey, "")

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
	privKey := opts.Signer
	if opts.KeyID == "" {
		return nil, fmt.Errorf("sign: empty KeyID")
	}

	signerKey := keys.SigningKeyForSigner(privKey, opts.KeyID)

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

// Package client provides a low-level ACME v2 client.
package client

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"net/mail"
	"net/url"
	"strings"

	resources "github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/cmd"
	acmenet "github.com/cpu/acmeshell/net"
)

// Client allows interaction with an ACME server. A client may have many
// Accounts, each corresponding to a keypair and corresponding server-side
// Account resource. Each client uses the ActiveAccount to authenticate
// requests to the ACME server. In addition to Accounts a client maintains
// a map of Keys containing private keys that can be used for signing CSRs
// when finalizing orders. Internally the Client uses the
// https://godoc.org/cpu/acmeshell/net package to perform HTTP requests to the ACME
// server.
//
// The Client's DirectoryURL field is a parsed *url.URL for the ACME server's
// directory. The client configures itself with the correct URLs for ACME
// operations using the directory resource accessed at this URL. See
// https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.7.1.1
//
// The Client's ActiveAccount field is a pointer to an Account that should be
// used for authenticating ACME requests with JSON Web Signatures (JWS).
// Switching the ActiveAccount between entries from the Accounts array allows
// performing complex multi-user tests (e.g. verifying access control
// restrictions on resources) with an ACME server.
//
// The Client's Keys field is a map of private keys that can be used for signing
// operations that should not use the ActiveAccount's keypair. One example of
// this being helpful is for certificate signing requests (CSRs) used during
// order finalization which SHOULD NOT be the account keypair (see
// https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.11.1).
// Each private key is indexed in the Keys map by a string key identifier
// which will often be a human readable name (e.g. "example-key",
// "cpu-throwaway"). The key identifier for the Keys entry has no relation to
// ACME JWS key identifiers.
//
// The Client's Accounts field is a slice of Account object pointers. These are
// the available Accounts that have been registered by the client with the ACME
// server, or loaded from a previous session.
type Client struct {
	// A parsed *url.URL pointer for the ACME server's directory URL.
	DirectoryURL *url.URL
	// A pointer to the Account object that is considered currently active for
	// signing JWS for ACME requests.
	ActiveAccount *resources.Account
	// A map of key identifiers to private keys. These keys are used for signing
	// operations that shouldn't use an Account's associated key.
	Keys map[string]*ecdsa.PrivateKey
	// A slice of Account object pointers. The ActiveAccount is selected from this
	// list of available accounts.
	Accounts []*resources.Account
	// Options controlling the Client's output.
	Output OutputOptions
	// Use POST-as-GET requests instead of GET
	PostAsGet bool
	// the net object is used to make HTTP GET/POST/HEAD requests to the ACME
	// server.
	net *acmenet.ACMENet
	// directory is an in-memory representation of the ACME server's directory
	// object.
	directory map[string]interface{}
	// nonce is the value of the last-seen ReplayNonce header from the ACME
	// server's HTTP responses. It will be used for the next signing operation.
	nonce string
}

// OutputOptions holds runtime output settings for a client.
type OutputOptions struct {
	// Print all HTTP requests made to the ACME server.
	PrintRequests bool
	// Print all HTTP responses from the ACME server.
	PrintResponses bool
	// Print all the input to JWS produced.
	PrintSignedData bool
	// Print the JSON serialization of all JWS produced.
	PrintJWS bool
}

// ClientConfig contains configuration options provided to NewClient when
// creating a Client instance.
//
// The DirectoryURL field is a string containing the URL for the
// ACME server's directory endpoint. This field is mandatory and must not be
// empty. It should be a fully qualified URL with
// a HTTP/HTTPS protocol prefix ("http://" or "https://"). See
// https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.7.1.1
// for more information about the ACME directory resource.
//
// The CACert field is an optional string containing a file path to a file
// containing one or more PEM encoded CA certificate that should be used as
// trust roots for HTTPS requests to the ACME server. If empty the default
// system roots are used.  For example, if you are using Pebble as the ACME
// server, it should be the file path to the "test/certs/pebble.minica.pem" file
// from the Pebble source directory. If you are using a public ACME server with
// a trusted HTTPS certificate you should provide the path to a file containing
// the combination of all of the PEM encoded system trusted root CA
// certificates.  Often this is something like "/etc/ssl/certs.pem".
//
// The ContactEmail field is a string expected to contain a single email
// address or to be empty. It will be used as a "mailto://" contact address when
// auto-registering an ACME account. Because this field is only referenced
// during auto-registering an Account it is only used when AutoRegister is true.
// You can not include multiple email addresses in the ContactEmail field. For
// more complex account creation set AutoRegister to false and use the
// "newAccount" shell command.
//
// The AccountPath field is a string expected to contain a file path for
// a previously saved Account, or to be empty. If the AccountPath field is
// populated NewClient will not auto-register an account (even when AutoRegister
// is true) and will instead load the Account serialized in the provided
// filepath. It will be the ActiveAccount once loaded.
type ClientConfig struct {
	// A fully qualified URL for the ACME server's directory resource. Must
	// include an HTTP/HTTPS protocol prefix.
	DirectoryURL string
	// An optional file path to one or more PEM encoded CA certificates to be used
	// as trust roots for HTTPS requests to the ACME server.
	CACert string
	// An optional email address to use if AutoRegister is true and an Account is
	// created with the ACME server. It should not have a protocol prefix,
	// acmeshell will automatically add a "mailto://" prefix. This field only
	// supports one email address.
	ContactEmail string
	// An optional file path to a previously saved ACME Shell account. It will be
	// loaded and used as the ActiveAccount. If provided this field takes
	// precedence over AutoRegister and will prevent an account from being
	// auto-registered even if AutoRegister is true.
	AccountPath string
	// If AutoRegister is true NewClient will automatically create a new Account
	// with the ACME server and use it as the ActiveAccount. If ContactEmail is
	// specified it will be used as the new ACME account's Contact mailto address.
	AutoRegister bool
	// If POSTAsGET is true then GET requests to Orders, Authorizations,
	// Challenges and Certificates will be made as POST-as-GET requests. If using
	// a Pebble server this requires `-strict` be enabled.
	POSTAsGET bool
	// Initial OutputOptions settings
	InitialOutput OutputOptions
}

// normalize validates a ClientConfig.
func (conf *ClientConfig) normalize() error {
	// Clean up any junk whitespace that might have snuck in
	conf.DirectoryURL = strings.TrimSpace(conf.DirectoryURL)
	conf.ContactEmail = strings.TrimSpace(conf.ContactEmail)
	conf.AccountPath = strings.TrimSpace(conf.AccountPath)

	if conf.DirectoryURL == "" {
		return fmt.Errorf("DirectoryURL must not be empty")
	}

	if _, err := url.Parse(conf.DirectoryURL); err != nil {
		return fmt.Errorf("DirectoryURL invalid: %s", err.Error())
	}

	if conf.ContactEmail != "" {
		addr, err := mail.ParseAddress(conf.ContactEmail)
		if err != nil {
			return fmt.Errorf("ContactEmail is invalid: %s", err.Error())
		}
		conf.ContactEmail = addr.Address
	}

	return nil
}

// NewClient creates a Client instance from the given ClientConfig. If the
// config is not valid or if another error occurs it will be returned along with
// a nil Client.
//
// TODO(@cpu): This function is way too long/messy. Refactor ASAP!
func NewClient(config ClientConfig) (*Client, error) {
	// Validate the ClientConfig has no errors when normalized.
	if err := config.normalize(); err != nil {
		return nil, err
	}

	// Create the ACME net client
	net, err := acmenet.New(config.CACert)
	cmd.FailOnError(err, "Unable to create ACME net client")

	// NOTE(@cpu): Its safe to throw away the returned err here because we check
	// that `url.Parse` will succeed in `config.normalize()` above.
	dirURL, _ := url.Parse(config.DirectoryURL)

	// Create a base client
	client := &Client{
		DirectoryURL: dirURL,
		PostAsGet:    config.POSTAsGET,
		Keys:         map[string]*ecdsa.PrivateKey{},
		Output:       config.InitialOutput,
		net:          net,
	}
	if client.PostAsGet {
		log.Printf("Using POST-as-GET requests\n")
	}

	// If requested, try to load an existing account from disk
	if config.AccountPath != "" {
		log.Printf("Trying to restore account from %q\n", config.AccountPath)
		acct, err := resources.RestoreAccount(config.AccountPath)

		// if there was an error loading the account and auto-register is not
		// specified then return an error. We have no account to use.
		if err != nil && !config.AutoRegister {
			return nil, fmt.Errorf("error restoring account from %q : %s",
				config.AccountPath, err)
		} else if err != nil && config.AutoRegister {
			log.Printf("No account restored\n")
		}

		// If there was no error, populate the active account
		if err == nil {
			client.Keys[acct.ID] = acct.PrivateKey
			log.Printf("Restored private key for ID %q\n", acct.ID)
			client.Accounts = append(client.Accounts, acct)
			client.ActiveAccount = acct
			log.Printf("Restored account with ID %q (Contact %s)\n",
				acct.ID, acct.Contact)
		}
	}

	// If there is no active account and auto-register is enabled then create
	// a new account.
	if config.AutoRegister && client.ActiveAccountID() == "" {
		log.Printf("AutoRegister is enabled and there is no loaded account. " +
			"Creating a new account\n")
		// Make the account object
		acct, err := resources.NewAccount([]string{config.ContactEmail}, nil)
		if err != nil {
			return nil, err
		}
		// store the account object
		client.Accounts = append(client.Accounts, acct)
		// use the auto-registered account as the active account
		client.ActiveAccount = acct
		// create the account with the ACME server
		err = client.CreateAccount(acct)
		if err != nil {
			return nil, err
		}
		// store the account key
		client.Keys[acct.ID] = acct.PrivateKey
		log.Printf("Created private key for ID %q\n", acct.ID)

		// if there is an account path configured, save the account we just made to
		// that path
		if config.AccountPath != "" {
			err := resources.SaveAccount(config.AccountPath, client.ActiveAccount)
			if err != nil {
				return nil, fmt.Errorf("error saving account to %q : %s",
					config.AccountPath, err)
			}
			log.Printf("Saved account data to %q", config.AccountPath)
		}
	} else if config.AutoRegister && client.ActiveAccountID() != "" {
		// If there is an active account AND auto-register is enabled print
		// a message to explain that we aren't creating an account.
		log.Printf("AutoRegister is enabled but there is a loaded account (ID: %q). "+
			"Skipping creating a new account\n", client.ActiveAccount.ID)
	} else {
		// Otherwise, autoregister is disabled.
		log.Printf("AutoRegister is disabled\n")
	}

	if client.directory == nil {
		if err := client.UpdateDirectory(); err != nil {
			return nil, err
		}
	}

	if client.nonce == "" {
		if err := client.RefreshNonce(); err != nil {
			return nil, err
		}
	}

	if acctID := client.ActiveAccountID(); acctID != "" {
		log.Printf("Active account: %q\n", acctID)
	}

	return client, nil
}

// TODO(@cpu): This is stupid
func (c *Client) Printf(format string, vals ...interface{}) {
	log.Printf(format, vals...)
}

// ActiveAccountID returns the ID of the ActiveAccount. If the ActiveAccount is
// nil, an empty string is returned. If the ActiveAccount has not yet been
// created with the ACME server an empty string is returned.
func (c *Client) ActiveAccountID() string {
	if c.ActiveAccount == nil {
		return ""
	}

	return c.ActiveAccount.ID
}

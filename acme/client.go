// Package acme provides a low-level ACME v2 client and associated types.
package acme

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/cpu/acmeshell/cmd"
	acmenet "github.com/cpu/acmeshell/net"
)

const (
	// See https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.7.1.1
	// The ACME directory key for the newNonce endpoint
	NEW_NONCE_ENDPOINT = "newNonce"
	// The ACME directory key for the newAccount endpoint.
	NEW_ACCOUNT_ENDPOINT = "newAccount"
	// The ACME directory key for the newOrder endpoint.
	NEW_ORDER_ENDPOINT = "newOrder"
	// The HTTP response header used by ACME to communicate a fresh nonce. See
	// https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.6.5.1
	REPLAY_NONCE_HEADER = "Replay-Nonce"
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
	ActiveAccount *Account
	// A map of key identifiers to private keys. These keys are used for signing
	// operations that shouldn't use an Account's associated key.
	Keys map[string]*ecdsa.PrivateKey
	// A slice of Account object pointers. The ActiveAccount is selected from this
	// list of available accounts.
	Accounts []*Account
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
// The CACert field is a string containing a file path to a file containing one
// or more PEM encoded CA certificate that should be used as trust roots for
// HTTPS requests to the ACME server. This field is mandatory and must not be
// empty. For instance, if you are using Pebble as the ACME server, it should be
// the file path to the "test/certs/pebble.minica.pem" file from the Pebble
// source directory. If you are using a public ACME server with a trusted HTTPS
// certificate you should provide the path to a file containing the
// concatination of all of the PEM encoded system trusted root CA certificates.
// Often this is something like "/etc/ssl/certs.pem".
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
	// A file path to one or more PEM encoded CA certificates to be used as trust
	// roots for HTTPS requests to the ACME server.
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
	net, err := acmenet.New(acmenet.Config{
		CABundlePath: config.CACert,
	})
	cmd.FailOnError(err, "Unable to create ACME net client")

	// NOTE(@cpu): Its safe to throw away the returned err here because we check
	// that `url.Parse` will succeed in `config.normalize()` above.
	dirURL, _ := url.Parse(config.DirectoryURL)

	// Create a base client
	client := &Client{
		DirectoryURL: dirURL,
		net:          net,
		Keys:         map[string]*ecdsa.PrivateKey{},
	}

	// If requested, try to load an existing account from disk
	if config.AccountPath != "" {
		log.Printf("Restoring account from %q\n", config.AccountPath)
		acct, err := RestoreAccount(config.AccountPath)

		// if there was an error loading the account and auto-register is not
		// specified then return an error. We have no account to use.
		if err != nil && !config.AutoRegister {
			return nil, fmt.Errorf("error restoring account from %q : %s",
				config.AccountPath, err)
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
		acct, err := NewAccount([]string{config.ContactEmail}, nil)
		if err != nil {
			return nil, err
		}
		// store the account object
		client.Accounts = append(client.Accounts, acct)
		// use the auto-registered account as the active account
		client.ActiveAccount = acct
		// create the account with the ACME server
		acct, err = client.CreateAccount(acct, nil)
		if err != nil {
			return nil, err
		}
		// store the account key
		client.Keys[acct.ID] = acct.PrivateKey
		log.Printf("Created private key for ID %q\n", acct.ID)

		// if there is an account path configured, save the account we just made to
		// that path
		if config.AccountPath != "" {
			err := SaveAccount(config.AccountPath, client.ActiveAccount)
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

func (c *Client) getDirectory() (map[string]interface{}, error) {
	url := c.DirectoryURL.String()

	respBody, _, err := c.net.GetURL(url)
	if err != nil {
		return nil, err
	}

	var directory map[string]interface{}
	err = json.Unmarshal(respBody, &directory)
	if err != nil {
		return nil, err
	}

	return directory, nil
}

// Directory fetches the ACME Directory resource from the ACME server and
// returns it deserialized as a map.
//
// See
// https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.7.1.1
func (c *Client) Directory() (map[string]interface{}, error) {
	if c.directory == nil {
		if err := c.UpdateDirectory(); err != nil {
			return nil, err
		}
	}

	return c.directory, nil
}

// UpdateDirectory updates the Client's cached directory used when referencing
// the endpoints for updating nonces, creating accounts, and creating orders.
//
// TODO(@cpu): I don't think it makes sense for both Directory and
// UpdateDirectory to be exported/defined on the client.
func (c *Client) UpdateDirectory() error {
	newDir, err := c.getDirectory()
	if err != nil {
		return err
	}

	c.directory = newDir
	log.Printf("Updated directory")
	return nil
}

// GetEndpintURL gets a URL for a specific ACME endpoint URL by first fetching
// the ACME server's directory and then checking that directory resource for the
// a key with the given name. If the key is found its value is returned along
// with a true bool. If the key is not found an empty string is returned with
// a false bool.
func (c *Client) GetEndpointURL(name string) (string, bool) {
	dir, err := c.Directory()
	if err != nil {
		return "", false
	}
	rawURL, ok := dir[name]
	if !ok {
		return "", false
	}
	switch v := rawURL.(type) {
	case string:
		if v == "" {
			return "", false
		}
		return v, true
	}
	return "", false
}

// Nonce satisfies the JWS "NonceSource" interface by using a nonce stored by
// the client from previous responses. That nonce value will be returned after
// first getting a replacement nonce to store from the ACME server's NewNonce
// endpoint. This ensures a constant supply of fresh nonces by always fetching
// a replacement at the same time we use the old nonce.
func (c *Client) Nonce() (string, error) {
	n := c.nonce
	err := c.RefreshNonce()
	if err != nil {
		return n, err
	}
	return n, nil
}

// RefreshNonce fetches a new nonce from the ACME server's NewNonce endpoint and
// stores it in the client's memory to be used in subsequent Nonce calls.
func (c *Client) RefreshNonce() error {
	nonceURL, ok := c.GetEndpointURL(NEW_NONCE_ENDPOINT)
	if !ok {
		return fmt.Errorf(
			"Missing %q entry in ACME server directory", NEW_NONCE_ENDPOINT)
	}

	resp, err := c.net.HeadURL(nonceURL)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%q returned HTTP status %d, expected %d\n",
			NEW_NONCE_ENDPOINT, resp.StatusCode, http.StatusOK)
	}

	nonce := resp.Header.Get(REPLAY_NONCE_HEADER)
	if nonce == "" {
		return fmt.Errorf("%q returned no %q header value",
			NEW_NONCE_ENDPOINT, REPLAY_NONCE_HEADER)
	}

	if nonce == c.nonce {
		return fmt.Errorf("%q returned the nonce %q more than once",
			NEW_NONCE_ENDPOINT, REPLAY_NONCE_HEADER)
	}

	c.nonce = nonce
	log.Printf("Updated nonce to %q", nonce)
	return nil
}

// CreateAccount creates the given Account resource with the ACME server. A pointer to the Account is returned with a populated ID field if the NewAccount operation is successful, otherwise an error is returned.
//
// Important: This function always unconditionally agrees to the server's terms
// of service (e.g. it sends "termsOfServiceAgreed:"true" in all account
// creation requests). This is one of MANY reasons why you should not be using
// ACME Shell for anything except development and testing!
//
// See
// https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.7.3
// for more information on account creation.
func (c *Client) CreateAccount(acct *Account, opts *HTTPPostOptions) (*Account, error) {
	if c.nonce == "" {
		if err := c.RefreshNonce(); err != nil {
			return nil, err
		}
	}
	if acct.ID != "" {
		return nil, fmt.Errorf(
			"create: account already exists under ID %q\n", acct.ID)
	}
	if opts == nil {
		opts = defaultHTTPPostOptions
	}

	newAcctReq := struct {
		Contact   []string `json:",omitempty"`
		ToSAgreed bool     `json:"termsOfServiceAgreed"`
	}{
		Contact:   acct.Contact,
		ToSAgreed: true,
	}

	reqBody, err := json.Marshal(&newAcctReq)
	if err != nil {
		return nil, err
	}

	newAcctURL, ok := c.GetEndpointURL(NEW_ACCOUNT_ENDPOINT)
	if !ok {
		return nil, fmt.Errorf(
			"create: ACME server missing %q endpoint in directory",
			NEW_ACCOUNT_ENDPOINT)
	}

	signedBody, err := acct.Sign(newAcctURL, reqBody, SignOptions{
		EmbedKey:       true,
		NonceSource:    c,
		PrintJWS:       opts.PrintJWS,
		PrintJWSObject: opts.PrintJWSObject,
		PrintJSON:      opts.PrintJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("create: %s\n", err)
	}

	log.Printf("Sending %q request (contact: %s) to %q",
		NEW_ACCOUNT_ENDPOINT, acct.Contact, newAcctURL)
	respCtx := c.PostURL(newAcctURL, signedBody, &opts.HTTPOptions)
	if respCtx.Err != nil {
		return nil, err
	}

	if respCtx.Resp.StatusCode != http.StatusCreated {
		c.Printf("Response: \n%s\n", respCtx.Body)
		return nil, fmt.Errorf("create: server returned status code %d, expected %d",
			respCtx.Resp.StatusCode, http.StatusCreated)
	}

	locHeader := respCtx.Resp.Header.Get("Location")
	if locHeader == "" {
		return nil, fmt.Errorf("create: server returned response with no Location header")
	}

	// Store the Location header as the Account's ID
	acct.ID = locHeader
	log.Printf("Created account with ID %q\n", acct.ID)
	return acct, nil
}

// CreateOrder creates the given Order resource with the ACME server. If the
// operation is successful a pointer to the Order with a populated ID field is
// returned. Otherwise a nil Order and a non-nil error are returned.
//
// For more information on Order creation see "Applying for Certificate
// Issuance" in the ACME specification:
// https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.7.4
func (c *Client) CreateOrder(order *Order, opts *HTTPPostOptions) (*Order, error) {
	if c.nonce == "" {
		if err := c.RefreshNonce(); err != nil {
			return nil, err
		}
	}
	if c.ActiveAccountID() == "" {
		return nil, fmt.Errorf("createOrder: active account is nil or has not been created")
	}
	if opts == nil {
		opts = defaultHTTPPostOptions
	}

	req := struct {
		Identifiers []Identifier
	}{
		Identifiers: order.Identifiers,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	newOrderURL, ok := c.GetEndpointURL(NEW_ORDER_ENDPOINT)
	if !ok {
		return nil, fmt.Errorf(
			"createOrder: ACME server missing %q endpoint in directory",
			NEW_ORDER_ENDPOINT)
	}

	// Save the account that will create this order
	order.Account = c.ActiveAccount
	signedBody, err := c.ActiveAccount.Sign(newOrderURL, reqBody, SignOptions{
		NonceSource:    c,
		PrintJWS:       opts.PrintJWS,
		PrintJWSObject: opts.PrintJWSObject,
		PrintJSON:      opts.PrintJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("createOrder: %s\n", err)
	}

	respCtx := c.PostURL(newOrderURL, signedBody, &opts.HTTPOptions)
	if respCtx.Err != nil {
		return nil, err
	}

	if respCtx.Resp.StatusCode != http.StatusCreated {
		c.Printf("Response body: \n%s\n", respCtx.Body)
		return nil, fmt.Errorf("createOrder: server returned status code %d, expected %d",
			respCtx.Resp.StatusCode, http.StatusCreated)
	}

	locHeader := respCtx.Resp.Header.Get("Location")
	if locHeader == "" {
		return nil, fmt.Errorf("create: server returned response with no Location header")
	}

	// Unmarshal the updated order
	err = json.Unmarshal(respCtx.Body, &order)
	if err != nil {
		return nil, fmt.Errorf("create: server returned invalid JSON: %s", err)
	}

	// Store the Location header as the Order's ID
	order.ID = locHeader
	log.Printf("Created new order with ID %q\n", order.ID)
	// Save the order for the account
	c.ActiveAccount.Orders = append(c.ActiveAccount.Orders, order.ID)
	return order, nil
}

// UpdateOrder refreshes a given Order by fetching its ID URL from the ACME
// server. If this is successful a pointer to the updated Order is returned.
// Otherwise a nil Order and a non-nil error are returned.
//
// Calling UpdateOrder is required to refresh an Order's Status field to
// synchronize the resource with the server-side representation.
func (c *Client) UpdateOrder(order *Order, opts *HTTPOptions) (*Order, error) {
	if order == nil {
		return nil, fmt.Errorf("updateOrder: order must not be nil")
	}
	if order.ID == "" {
		return nil, fmt.Errorf("updateOrder: order must have an ID")
	}
	if opts == nil {
		opts = defaultHTTPOptions
	}

	respCtx := c.GetURL(order.ID, opts)
	if respCtx.Err != nil {
		return nil, respCtx.Err
	}

	err := json.Unmarshal(respCtx.Body, &order)
	if err != nil {
		return nil, err
	}

	return order, nil
}

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
	NEW_NONCE_ENDPOINT   = "newNonce"
	NEW_ACCOUNT_ENDPOINT = "newAccount"
	NEW_ORDER_ENDPOINT   = "newOrder"
	REPLAY_NONCE_HEADER  = "Replay-Nonce"
)

type Client struct {
	DirectoryURL  *url.URL
	ActiveAccount *Account
	Keys          map[string]*ecdsa.PrivateKey
	Accounts      []*Account
	net           *acmenet.ACMENet
	directory     map[string]interface{}
	nonce         string
}

// TODO(@cpu): This is stupid
func (c *Client) Printf(format string, vals ...interface{}) {
	log.Printf(format, vals...)
}

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

func (c *Client) Directory() (map[string]interface{}, error) {
	if c.directory == nil {
		if err := c.UpdateDirectory(); err != nil {
			return nil, err
		}
	}

	return c.directory, nil
}

func (c *Client) UpdateDirectory() error {
	newDir, err := c.getDirectory()
	if err != nil {
		return err
	}

	c.directory = newDir
	log.Printf("Updated directory")
	return nil
}

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

// Nonce satisfies the JWS "NonceSource" interface
func (c *Client) Nonce() (string, error) {
	n := c.nonce
	err := c.RefreshNonce()
	if err != nil {
		return n, err
	}
	return n, nil
}

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

type ClientConfig struct {
	DirectoryURL string
	CACert       string
	ContactEmail string
	AccountPath  string
	AutoRegister bool
}

func (conf *ClientConfig) normalize() error {
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

// TODO(@cpu): This function is way too long
func NewClient(config ClientConfig) (*Client, error) {
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

package client

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/cpu/acmeshell/acme"
	"github.com/cpu/acmeshell/acme/keys"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/net"

	jose "gopkg.in/square/go-jose.v2"
)

// CreateAccount creates the given Account resource with the ACME server.
// The Account is updated with the ID returned in the server's response's
// Location header if the operation is successful, otherwise an error is
// returned.
//
// Important: This function always unconditionally agrees to the server's terms
// of service (e.g. it sends "termsOfServiceAgreed:"true" in all account
// creation requests). This is one of MANY reasons why you should not be using
// ACME Shell for anything except development and testing!
//
// For more information on account creation see
// https://tools.ietf.org/html/rfc8555#section-7.3
func (c *Client) CreateAccount(acct *resources.Account) error {
	if c.nonce == "" {
		if err := c.RefreshNonce(); err != nil {
			return err
		}
	}
	if acct.ID != "" {
		return fmt.Errorf(
			"create: account already exists under ID %q\n", acct.ID)
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
		return err
	}

	newAcctURL, ok := c.GetEndpointURL(acme.NEW_ACCOUNT_ENDPOINT)
	if !ok {
		return fmt.Errorf(
			"create: ACME server missing %q endpoint in directory",
			acme.NEW_ACCOUNT_ENDPOINT)
	}

	signResult, err := c.Sign(
		newAcctURL,
		reqBody,
		&SigningOptions{
			EmbedKey: true,
			Signer:   acct.Signer,
		})
	if err != nil {
		return fmt.Errorf("create: %s\n", err)
	}

	log.Printf("Sending %q request (contact: %s) to %q",
		acme.NEW_ACCOUNT_ENDPOINT, acct.Contact, newAcctURL)
	resp, err := c.PostURL(newAcctURL, signResult.SerializedJWS)
	if err != nil {
		return err
	}

	respOb := resp.Response
	if respOb.StatusCode != http.StatusCreated {
		return fmt.Errorf("create: server returned status code %d, expected %d",
			respOb.StatusCode, http.StatusCreated)
	}

	locHeader := respOb.Header.Get("Location")
	if locHeader == "" {
		return fmt.Errorf("create: server returned response with no Location header")
	}

	// Store the Location header as the Account's ID
	acct.ID = locHeader
	log.Printf("Created account with ID %q\n", acct.ID)
	return nil
}

func (c *Client) Rollover(newKey crypto.Signer) error {
	acctID := c.ActiveAccountID()
	if c.ActiveAccountID() == "" {
		return fmt.Errorf("active account is nil or has not been created")
	}

	account := c.ActiveAccount
	oldKey := keys.JWKForSigner(account.Signer)

	rolloverRequest := struct {
		Account string
		OldKey  jose.JSONWebKey
	}{
		Account: account.ID,
		OldKey:  oldKey,
	}

	rolloverRequestJSON, err := json.Marshal(&rolloverRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal rollover request to JSON: %v", err)
	}

	innerSignOpts := &SigningOptions{
		Signer:   newKey,
		EmbedKey: true,
	}

	targetURL, ok := c.GetEndpointURL("keyChange")
	if !ok {
		return fmt.Errorf("no keyChange endpoint in server's directory response")
	}

	innerSignResult, err := c.Sign(targetURL, rolloverRequestJSON, innerSignOpts)
	if err != nil {
		return fmt.Errorf("error signing inner JWS: %v", err)
	}

	outerSignResult, err := c.Sign(targetURL, innerSignResult.SerializedJWS, nil)
	if err != nil {
		return fmt.Errorf("error signing outer JWS: %v", err)
	}

	log.Printf("Rolling over account %q to use new key\n", acctID)
	resp, err := c.PostURL(targetURL, outerSignResult.SerializedJWS)
	if err != nil {
		return fmt.Errorf("rollover POST request failed: %v", err)
	}

	respOb := resp.Response
	if respOb.StatusCode != http.StatusOK {
		return fmt.Errorf("rollover POST request failed. Status code: %d", respOb.StatusCode)
	}

	c.Keys[account.ID] = newKey
	c.ActiveAccount.Signer = newKey
	log.Printf("Rollover for %q completed\n", acctID)
	return nil
}

// CreateOrder creates the given Order resource with the ACME server. If the
// operation is successful the Order's ID field is populated with the value of
// the server's reply's Location header. Otherwise a non-nil error is returned.
//
// For more information on Order creation see "Applying for Certificate
// Issuance" in RFC 8555:
// https://tools.ietf.org/html/rfc8555#section-7.4
func (c *Client) CreateOrder(order *resources.Order) error {
	if c.nonce == "" {
		if err := c.RefreshNonce(); err != nil {
			return err
		}
	}
	if c.ActiveAccountID() == "" {
		return fmt.Errorf("createOrder: active account is nil or has not been created")
	}

	req := struct {
		Identifiers []resources.Identifier
	}{
		Identifiers: order.Identifiers,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return err
	}

	newOrderURL, ok := c.GetEndpointURL(acme.NEW_ORDER_ENDPOINT)
	if !ok {
		return fmt.Errorf(
			"createOrder: ACME server missing %q endpoint in directory",
			acme.NEW_ORDER_ENDPOINT)
	}

	// Sign the new order request with the active account
	signResult, err := c.Sign(newOrderURL, reqBody, nil)
	if err != nil {
		return fmt.Errorf("createOrder: %s\n", err)
	}

	resp, err := c.PostURL(newOrderURL, signResult.SerializedJWS)
	if err != nil {
		return err
	}

	respOb := resp.Response
	if respOb.StatusCode != http.StatusCreated {
		return fmt.Errorf("createOrder: server returned status code %d, expected %d",
			respOb.StatusCode, http.StatusCreated)
	}

	locHeader := respOb.Header.Get("Location")
	if locHeader == "" {
		return fmt.Errorf("create: server returned response with no Location header")
	}

	// Unmarshal the updated order
	err = json.Unmarshal(resp.RespBody, &order)
	if err != nil {
		return fmt.Errorf("create: server returned invalid JSON: %s", err)
	}

	// Store the Location header as the Order's ID
	order.ID = locHeader
	log.Printf("Created new order with ID %q\n", order.ID)
	// Save the order for the account
	c.ActiveAccount.Orders = append(c.ActiveAccount.Orders, order.ID)
	return nil
}

// UpdateOrder refreshes a given Order by fetching its ID URL from the ACME
// server. If this is successful the Order is mutated in place. Otherwise a nil
// Order and a non-nil error are returned.
//
// Calling UpdateOrder is required to refresh an Order's Status field to
// synchronize the resource with the server-side representation.
func (c *Client) UpdateOrder(order *resources.Order) error {
	if order == nil {
		return fmt.Errorf("updateOrder: order must not be nil")
	}
	if order.ID == "" {
		return fmt.Errorf("updateOrder: order must have an ID")
	}

	var resp *net.NetResponse
	var err error
	if c.PostAsGet {
		resp, err = c.PostAsGetURL(order.ID)
	} else {
		resp, err = c.GetURL(order.ID)
	}
	if err != nil {
		return err
	}

	err = json.Unmarshal(resp.RespBody, &order)
	if err != nil {
		return err
	}

	return nil
}

// UpdateAuthz refreshes a given Authz by fetching its ID URL from the ACME
// server. If this is successful the Authz is updated in place. Otherwise an
// error is returned.
//
// Calling UpdateAuthz is required to refresh an Authz's Status field to
// synchronize the resource with the server-side representation.
func (c *Client) UpdateAuthz(authz *resources.Authorization) error {
	if authz == nil {
		return fmt.Errorf("UpdateAuthz: authz must not be nil")
	}
	if authz.ID == "" {
		return fmt.Errorf("UpdateAuthz: authz must have an ID")
	}

	var resp *net.NetResponse
	var err error
	if c.PostAsGet {
		resp, err = c.PostAsGetURL(authz.ID)
	} else {
		resp, err = c.GetURL(authz.ID)
	}
	if err != nil {
		return err
	}

	err = json.Unmarshal(resp.RespBody, &authz)
	if err != nil {
		return err
	}

	return nil
}

// UpdateChallenge refreshes a given Challenge by fetching its URL from the ACME
// server. If this is successful the Challenge is updated in place. Otherwise an
// error is returned.
func (c *Client) UpdateChallenge(chall *resources.Challenge) error {
	if chall == nil {
		return fmt.Errorf("UpdateChallenge: chall must not be nil")
	}
	if chall.URL == "" {
		return fmt.Errorf("UpdateChallenge: chall must have a URL")
	}

	var resp *net.NetResponse
	var err error
	if c.PostAsGet {
		resp, err = c.PostAsGetURL(chall.URL)
	} else {
		resp, err = c.GetURL(chall.URL)
	}
	if err != nil {
		return err
	}

	err = json.Unmarshal(resp.RespBody, &chall)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) OrderByIndex(index int) (*resources.Order, error) {
	if c.ActiveAccountID() == "" {
		return nil, errors.New(
			"OrderByIndex: active account is nil or has not been created")
	}

	// Find the Order URL
	orderURL, err := c.ActiveAccount.OrderURL(index)
	if err != nil {
		return nil, err
	}

	// Fetch the full Order object
	order := &resources.Order{ID: orderURL}
	if err := c.UpdateOrder(order); err != nil {
		return nil, err
	}
	return order, nil
}

func (c *Client) AuthzByIdentifier(order *resources.Order, identifier string) (*resources.Authorization, error) {
	if order == nil {
		return nil, errors.New("AuthzByIdentifier: Order was nil")
	}
	if len(order.Authorizations) == 0 {
		return nil, errors.New("AuthzByIdentifier: Order has no authorizations")
	}

	// Loop through the order's authorization URLs, fetching the authz object for
	// each. Stop when an authz with the requested identifier is found.
	for _, authzURL := range order.Authorizations {
		authz := &resources.Authorization{ID: authzURL}
		if err := c.UpdateAuthz(authz); err != nil {
			return nil, err
		}
		if authz.Identifier.Value == identifier {
			return authz, nil
		}
	}
	return nil, fmt.Errorf(
		"AuthzByIdentifier: Order %q has no authz with identifier %q",
		order.ID,
		identifier)
}

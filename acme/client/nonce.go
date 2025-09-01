package client

import (
	"fmt"
	"log"
	"net/http"

	"github.com/cpu/acmeshell/acme"
)

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
//
// See https://tools.ietf.org/html/rfc8555#section-7.2
func (c *Client) RefreshNonce() error {
	nonceURL, ok := c.GetEndpointURL(acme.NEW_NONCE_ENDPOINT)
	if !ok {
		return fmt.Errorf(
			"missing %q entry in ACME server directory", acme.NEW_NONCE_ENDPOINT)
	}

	if c.Output.PrintNonceUpdates {
		log.Printf("Sending HTTP HEAD request to %q\n", nonceURL)
	}

	resp, err := c.net.HeadURL(nonceURL)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%q returned HTTP status %d, expected %d",
			acme.NEW_NONCE_ENDPOINT, resp.StatusCode, http.StatusOK)
	}

	nonce := resp.Header.Get(acme.REPLAY_NONCE_HEADER)
	if nonce == "" {
		return fmt.Errorf("%q returned no %q header value",
			acme.NEW_NONCE_ENDPOINT, acme.REPLAY_NONCE_HEADER)
	}

	if nonce == c.nonce {
		return fmt.Errorf("%q returned the nonce %q more than once",
			acme.NEW_NONCE_ENDPOINT, acme.REPLAY_NONCE_HEADER)
	}

	c.nonce = nonce
	if c.Output.PrintNonceUpdates {
		log.Printf("Updated nonce to %q", nonce)
	}
	return nil
}

// Package acme provides ACME protocol constants. See RFC 8555.
package acme

const (
	// Directory constants
	// See https://tools.ietf.org/html/rfc8555#section-9.7.5

	// The ACME directory key for the newNonce endpoint
	NEW_NONCE_ENDPOINT = "newNonce"
	// The ACME directory key for the newAccount endpoint.
	NEW_ACCOUNT_ENDPOINT = "newAccount"
	// The ACME directory key for the newOrder endpoint.
	NEW_ORDER_ENDPOINT = "newOrder"

	// The HTTP response header used by ACME to communicate a fresh nonce. See
	// https://tools.ietf.org/html/rfc8555#section-9.3
	REPLAY_NONCE_HEADER = "Replay-Nonce"
)

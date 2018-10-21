// Package acme provides ACME protocol constants.
package acme

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

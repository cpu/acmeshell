package resources

// The Order resource represents a collection of identifiers that an account
// wishes to create a Certificate for.
//
// See https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.7.1.3
//
// To understand the Status changes specified by ACME for the Order resource see
// https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#rfc.section.7.1.6
//
type Order struct {
	// The server-assigned ID (a URL) identifying the Order.
	ID string
	// The Status of the Order.
	Status string
	// The Identifiers the Order wishes to finalize a Certificate for once the
	// Order is ready.
	Identifiers []Identifier
	// The Account that is creating the Order. (Note: This is an ACME Shell field
	// pointing to the in-memory Account that created the Order and is not an ACME
	// specified field used in ACME requests/responses).
	Account *Account
	// A list of URLs for Authorization resources the server specifies for the
	// Order Identifiers.
	Authorizations []string
	// A URL used to Finalize the Order with a CSR once the Order has a status of
	// "ready".
	Finalize string
	// A URL used to fetch the Certificate issued by the server for the Order
	// after being Finalized. The Certificate field should be present and
	// not-empty when the Order has a status of "valid".
	Certificate string
}

// String returns the Order's ID URL.
func (o Order) String() string {
	return o.ID
}

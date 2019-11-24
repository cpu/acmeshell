package resources

// The Order resource represents a collection of identifiers that an account
// wishes to create a Certificate for.
//
// See https://tools.ietf.org/html/rfc8555#section-7.1.3
//
// To understand the Status changes specified by RFC 8555 for the Order resource
// see https://tools.ietf.org/html/rfc8555#section-7.1.6
//
type Order struct {
	// The server-assigned ID (a URL) identifying the Order.
	ID string
	// The Status of the Order.
	Status string
	// The Error associated with an invalid order
	Error *Problem `json:",omitempty"`
	// The Identifiers the Order wishes to finalize a Certificate for once the
	// Order is ready.
	Identifiers []Identifier
	// A list of URLs for Authorization resources the server specifies for the
	// Order Identifiers.
	Authorizations []string
	// A URL used to Finalize the Order with a CSR once the Order has a status of
	// "ready".
	Finalize string
	// A URL used to fetch the Certificate issued by the server for the Order
	// after being Finalized. The Certificate field should be present and
	// not-empty when the Order has a status of "valid".
	Certificate string `json:",omitempty"`
}

// String returns the Order's ID URL.
func (o Order) String() string {
	return o.ID
}

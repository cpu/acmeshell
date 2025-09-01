package resources

// The ACME Challenge resource represents an action that the client must take to
// authorize a given account for a specific identifier in order to issue
// a certificate containing that identifier.
//
// For information about the Challenge resource see
// https://tools.ietf.org/html/rfc8555#section-7.1.5
//
// To understand the Challenge types specified by RFC 8555 see
// https://tools.ietf.org/html/rfc8555#section-8
//
// To understand the Challenge Status changes specified by RFC 8555 see
// https://tools.ietf.org/html/rfc8555#section-7.1.6
type Challenge struct {
	// The Type of the challenge (expected values include "http-01", "dns-01", "tls-alpn-01")
	Type string `json:"type"`
	// The URL/ID of the challenge (provided by the server in the associated
	// Authorization)
	//
	// TODO(@cpu): This should be renamed to ID for consistency with
	// Authorization, Order and Account.
	URL string `json:"url"`
	// The Token used for constructing the challenge response for this challenge.
	Token string `json:"token"`
	// The Status of the challenge.
	Status string `json:"status"`
	// The Error associated with an invalid challenge
	Error *Problem `json:"error,omitempty"`
}

// String returns the URL of the Challenge.
func (c Challenge) String() string {
	return c.URL
}

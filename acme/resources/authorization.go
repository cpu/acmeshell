package resources

// The Identifier resource represents a subject identifier that can be included
// in a certificate.
//
// See:
// https://tools.ietf.org/html/rfc8555#section-7.5
// https://tools.ietf.org/html/rfc8555#section-9.7.7
//
// In practice most ACME servers only support "DNS" type identifiers where the
// value specifies a fully qualified domain name.
//
// A DNS type identifier that is used in a NewOrder request is allowed to
// contain a wildcard prefix (e.g. "*."). A DNS type identifier that is used in
// an Authorization resource is *not* allowed to contain a wildcard prefix and
// should instead have the Wildcard field of the Authorization set to true and
// the identifier value represented without the "*." prefix.
type Identifier struct {
	// The Type of the Identifier value.
	Type string
	// The Identifier value.
	Value string
}

// The ACME Authorization resource represents an Account's authorization to
// issue for a specified identifier, based on interactions with associated
// Challenges. Authorization for an identifier allows issuing certificates
// containing that identifier.
//
// For information about the Authorization resource see
// https://tools.ietf.org/html/rfc8555#section-7.1.4
//
// To understand the Authorization Status changes specified by ACME see
// https://tools.ietf.org/html/rfc8555#section-7.1.6
type Authorization struct {
	// The server-assigned ID (typically a URL) identifying the Authorization.
	ID string
	// The status of this authorization. Possible values are: “pending”, “valid”,
	// “invalid”, “deactivated”, “expired”, and “revoked”.
	// See:
	// https://tools.ietf.org/html/rfc8555#section-7.1.6
	Status string
	// The identifier that the account holding this Authorization is authorized to
	// represent
	Identifier Identifier
	// For pending authorizations, the challenges that the client can fulfill in
	// order to prove possession of the identifier. For valid authorizations, the
	// challenge that was validated. For invalid authorizations, the challenge
	// that was attempted and failed.
	Challenges []Challenge
	// A string representing a RFC 3339 date at which time the Authorization is
	// considered expired by the server.
	Expires string
	// For authorizations created as a result of a newOrder request containing
	// a DNS identifier with a value that contained a wildcard prefix this field
	// MUST be present, and true
	Wildcard bool
}

// String returns the Authorization's server-assigned ID.
func (a Authorization) String() string {
	return a.ID
}

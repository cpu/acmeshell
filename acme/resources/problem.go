package resources

// Problem is a struct representing a problem document from the server.
//
// TODO(@cpu): implement RFC 8555 subproblem support
type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

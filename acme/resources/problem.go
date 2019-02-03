package resources

// Problem is a struct representing a problem document from the server.
type Problem struct {
	Type   string
	Detail string
	Status int
}

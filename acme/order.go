package acme

type Identifier struct {
	Type  string
	Value string
}

type Order struct {
	ID             string
	Status         string
	Identifiers    []Identifier
	Account        *Account
	Authorizations []string
	Finalize       string
	Certificate    string
}

func (o Order) String() string {
	return o.ID
}

type Authorization struct {
	ID         string
	Status     string
	Identifier Identifier
	Challenges []Challenge
	Expires    string
	Wildcard   bool
}

func (a Authorization) String() string {
	return a.ID
}

type Challenge struct {
	Type   string
	URL    string
	Token  string
	Status string
}

func (c Challenge) String() string {
	return c.URL
}

package newOrder

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type newOrderCmd struct {
	commands.BaseCmd
}

var NewOrderCommand = newOrderCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "newOrder",
			Func:     newOrderHandler,
			Help:     "Create a new ACME order",
			LongHelp: `TODO(@cpu): Write this!`,
		},
	},
}

func (a newOrderCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return NewOrderCommand.Cmd, nil
}

func createOrder(fqdns []string, c *ishell.Context, opts *acmeclient.HTTPPostOptions) {
	var idents []resources.Identifier
	// Convert the fqdns to DNS identifiers
	for _, ident := range fqdns {
		val := strings.TrimSpace(ident)
		if val == "" {
			continue
		}
		idents = append(idents, resources.Identifier{
			Type:  "dns",
			Value: val,
		})
	}

	client := commands.GetClient(c)
	orderRequest := &resources.Order{
		Identifiers: idents,
	}
	_, err := client.CreateOrder(orderRequest, opts)
	if err != nil {
		c.Printf("newOrder: error creating new order with ACME server: %s\n", err)
		return
	}
}

func readIdentifiers(c *ishell.Context) string {
	c.SetPrompt(commands.BasePrompt + "FQDN > ")
	defer c.SetPrompt(commands.BasePrompt)
	terminator := "."
	c.Printf("Input fully qualified domain name identifiers for your order. "+
		" End by sending '%s'\n", terminator)
	return strings.TrimSuffix(c.ReadMultiLines(terminator), terminator)
}

func newOrderHandler(c *ishell.Context) {
	newOrderFlags := flag.NewFlagSet("newOrder", flag.ContinueOnError)
	identifiersArg := newOrderFlags.String("identifiers", "", "Comma separated list of DNS identifiers")

	httpOpts := &acmeclient.HTTPPostOptions{}

	newOrderFlags.BoolVar(&httpOpts.PrintHeaders, "headers", false, "Print HTTP response headers")
	newOrderFlags.BoolVar(&httpOpts.PrintStatus, "status", true, "Print HTTP response status code")
	newOrderFlags.BoolVar(&httpOpts.PrintJWS, "jwsBody", false, "Print JWS body before POSTing")
	newOrderFlags.BoolVar(&httpOpts.PrintJWSObject, "jwsObj", false, "Print JWS object before POSTing")
	newOrderFlags.BoolVar(&httpOpts.PrintJSON, "jsonBody", false, "Print JSON body before signing")

	err := newOrderFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("newOrder: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if *identifiersArg != "" {
		rawIdentifiers := strings.Split(*identifiersArg, ",")
		if len(rawIdentifiers) > 0 {
			createOrder(rawIdentifiers, c, httpOpts)
			return
		}
	}

	inputIdentifiers := readIdentifiers(c)
	if inputIdentifiers == "" {
		c.Printf("No identifiers provided.\n")
		return
	}

	createOrder(strings.Split(inputIdentifiers, "\n"), c, httpOpts)
}

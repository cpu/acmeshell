package newOrder

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type newOrderOptions struct {
	rawIdentifiers string
}

var (
	opts = newOrderOptions{}
)

func init() {
	registerNewOrderCmd()
}

func registerNewOrderCmd() {
	newOrderFlags := flag.NewFlagSet("newOrder", flag.ContinueOnError)
	newOrderFlags.StringVar(&opts.rawIdentifiers, "identifiers", "", "Comma separated list of DNS identifiers")

	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "newOrder",
			Help:     "Create a new ACME order",
			LongHelp: `TODO(@cpu): Write this!`,
		},
		nil,
		newOrderHandler,
		newOrderFlags)
}

func newOrderHandler(c *ishell.Context, leftovers []string) {
	defer func() {
		opts = newOrderOptions{}
	}()

	if opts.rawIdentifiers != "" {
		rawIdentifiers := strings.Split(opts.rawIdentifiers, ",")
		if len(rawIdentifiers) > 0 {
			createOrder(c, rawIdentifiers)
			return
		}
	}

	inputIdentifiers := readIdentifiers(c)
	if inputIdentifiers == "" {
		c.Printf("No identifiers provided.\n")
		return
	}

	createOrder(c, strings.Split(inputIdentifiers, "\n"))
}

func readIdentifiers(c *ishell.Context) string {
	c.SetPrompt(commands.BasePrompt + "FQDN > ")
	defer c.SetPrompt(commands.BasePrompt)
	terminator := "."
	c.Printf("Input fully qualified domain name identifiers for your order. "+
		" End by sending '%s'\n", terminator)
	return strings.TrimSuffix(c.ReadMultiLines(terminator), terminator)
}

func createOrder(c *ishell.Context, fqdns []string) {
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
	order := &resources.Order{
		Identifiers: idents,
	}
	err := client.CreateOrder(order)
	if err != nil {
		c.Printf("newOrder: error creating new order with ACME server: %s\n", err)
		return
	}
}

package orders

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "orders",
			Help:     "Show ACME orders created in this session by the active account",
			LongHelp: `TODO(@cpu): write this`,
			Func:     ordersHandler,
		},
		nil)
}

type ordersOptions struct {
	printID          bool
	printIdentifiers bool
	status           string
}

func ordersHandler(c *ishell.Context) {
	opts := ordersOptions{}
	ordersFlags := flag.NewFlagSet("orders", flag.ContinueOnError)
	ordersFlags.BoolVar(&opts.printID, "showID", true, "Print order IDs")
	ordersFlags.BoolVar(&opts.printIdentifiers, "showIdents", true, "Print order identifiers")
	ordersFlags.StringVar(&opts.status, "status", "", "Print orders only if they are in the given status")

	if _, err := commands.ParseFlagSetArgs(c.Args, ordersFlags); err != nil {
		return
	}

	if !opts.printID && !opts.printIdentifiers {
		c.Printf("orders: -showID and -showIdents can not both be false\n")
		return
	}

	client := commands.GetClient(c)
	orders := client.ActiveAccount.Orders
	if len(orders) == 0 {
		c.Printf("orders: the active account has no orders\n")
		return
	}

	for i, orderURL := range orders {
		order := &resources.Order{
			ID: orderURL,
		}
		err := client.UpdateOrder(order)
		if err != nil {
			c.Printf("orders: error getting order object: %s\n", err.Error())
			return
		}
		if opts.status != "" && order.Status != opts.status {
			continue
		}
		c.Printf("%3d)", i)
		if opts.printID {
			c.Printf("\t%#q", order.ID)
		}
		if opts.printIdentifiers {
			var domains []string
			for _, d := range order.Identifiers {
				domains = append(domains, d.Value)
			}
			c.Printf("\t%s", strings.Join(domains, ","))
		}
		c.Printf("\t%s", order.Status)
		c.Printf("\n")
	}
}

package shell

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
)

type ordersCmd struct {
	cmd *ishell.Cmd
}

type ordersOptions struct {
	printID          bool
	printIdentifiers bool
	status           string
}

var Orders ordersCmd = ordersCmd{
	cmd: &ishell.Cmd{
		Name:     "orders",
		Func:     ordersHandler,
		Help:     "Show ACME orders created in this session by the active account",
		LongHelp: `TODO(@cpu): write this`,
	},
}

func (a ordersCmd) New(client *acmeclient.Client) *ishell.Cmd {
	return Orders.cmd
}

func ordersHandler(c *ishell.Context) {
	opts := ordersOptions{}
	ordersFlags := flag.NewFlagSet("orders", flag.ContinueOnError)
	ordersFlags.BoolVar(&opts.printID, "showID", true, "Print order IDs")
	ordersFlags.BoolVar(&opts.printIdentifiers, "showIdents", true, "Print order identifiers")
	ordersFlags.StringVar(&opts.status, "status", "", "Print orders only if they are in the given status")

	err := ordersFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("orders: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if !opts.printID && !opts.printIdentifiers {
		c.Printf("orders: -showID and -showIdents can not both be false\n")
		return
	}

	client := getClient(c)

	orders := client.ActiveAccount.Orders
	if len(orders) == 0 {
		c.Printf("orders: the active account has no orders\n")
		return
	}

	/*
		for i, o := range orders {
			// Use a hardcoded HTTPOptions because this is a background operation and
			// we never want to print headers/status
			_, err := client.UpdateOrder(o, &acmeclient.HTTPOptions{
				PrintHeaders: false,
				PrintStatus:  false,
			})
			if err != nil {
				c.Printf("orders: error updating order %d id %q : %s\n", i, o.ID, err)
				return
			}
		}
	*/

	for i, orderURL := range orders {
		order, err := getOrderObject(client, orderURL, nil)
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

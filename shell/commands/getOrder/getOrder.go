package getOrder

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type getOrderCmd struct {
	commands.BaseCmd
}

type getOrderOptions struct {
	acmeclient.HTTPOptions
	orderIndex int
}

var GetOrderCommand = getOrderCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "getOrder",
			Aliases:  []string{"order"},
			Func:     getOrderHandler,
			Help:     "Get an ACME order URL",
			LongHelp: `TODO(@cpu): Write this!`,
		},
	},
}

func (g getOrderCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return GetOrderCommand.Cmd, nil
}

func getOrderHandler(c *ishell.Context) {
	opts := getOrderOptions{}
	getOrderFlags := flag.NewFlagSet("getOrder", flag.ContinueOnError)
	getOrderFlags.BoolVar(&opts.PrintHeaders, "headers", false, "Print HTTP response headers")
	getOrderFlags.BoolVar(&opts.PrintStatus, "status", true, "Print HTTP response status code")
	getOrderFlags.BoolVar(&opts.PrintResponse, "response", true, "Print HTTP response body")
	getOrderFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")

	err := getOrderFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("getOrder: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	client := commands.GetClient(c)

	var orderURL string
	if len(getOrderFlags.Args()) == 0 {
		var order *resources.Order
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order.ID = orderURL
			err = client.UpdateOrder(order, nil)
			if err != nil {
				c.Printf("getOrder: error getting order: %s\n", err.Error())
				return
			}
		} else {
			order, err = commands.PickOrder(c)
			if err != nil {
				c.Printf("getOrder: error picking order: %s\n", err.Error())
				return
			}
		}
		orderURL = order.ID
	} else {
		templateText := strings.Join(getOrderFlags.Args(), " ")
		rendered, err := commands.EvalTemplate(
			templateText,
			commands.TemplateCtx{
				Client: client,
				Acct:   client.ActiveAccount,
			})
		if err != nil {
			c.Printf("getOrder: order URL templating error: %s\n", err.Error())
			return
		}
		orderURL = rendered
	}

	order := &resources.Order{
		ID: orderURL,
	}
	err = client.UpdateOrder(order, nil)
	if err != nil {
		c.Printf("getOrder: error getting order: %s\n", err.Error())
		return
	}
}

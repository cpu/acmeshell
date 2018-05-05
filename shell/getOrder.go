package shell

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
)

type getOrderOptions struct {
	acme.HTTPOptions
	orderIndex int
}

type getOrderCmd struct {
	cmd *ishell.Cmd
}

var getOrder getOrderCmd = getOrderCmd{
	cmd: &ishell.Cmd{
		Name:     "getOrder",
		Aliases:  []string{"order"},
		Func:     getOrderHandler,
		Help:     "Get an ACME order URL",
		LongHelp: `TODO(@cpu): Write this!`,
	},
}

func (g getOrderCmd) New(client *acme.Client) *ishell.Cmd {
	return getOrder.cmd
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

	client := getClient(c)

	var orderURL string
	if len(getOrderFlags.Args()) == 0 {
		var order *acme.Order
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order, err = getOrderObject(client, orderURL, nil)
			if err != nil {
				c.Printf("getOrder: error getting order: %s\n", err.Error())
				return
			}
		} else {
			order, err = pickOrder(c)
			if err != nil {
				c.Printf("getOrder: error picking order: %s\n", err.Error())
				return
			}
		}
		orderURL = order.ID
	} else {
		templateText := strings.Join(getOrderFlags.Args(), " ")
		rendered, err := evalTemplate(templateText, tplCtx{
			client: client,
			acct:   client.ActiveAccount,
		})
		if err != nil {
			c.Printf("getOrder: order URL templating error: %s\n", err.Error())
			return
		}
		orderURL = rendered
	}

	_, err = getOrderObject(client, orderURL, &opts.HTTPOptions)
	if err != nil {
		c.Printf("getOrder: error getting order: %s\n", err.Error())
		return
	}
}

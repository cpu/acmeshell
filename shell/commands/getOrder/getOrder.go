package getOrder

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
			Name:     "getOrder",
			Aliases:  []string{"order"},
			Help:     "Get an ACME order URL",
			LongHelp: `TODO(@cpu): Write this!`,
			Func:     getOrderHandler,
		},
		nil)
}

type getOrderOptions struct {
	orderIndex int
}

func getOrderHandler(c *ishell.Context) {
	opts := getOrderOptions{}
	getOrderFlags := flag.NewFlagSet("getOrder", flag.ContinueOnError)
	getOrderFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")

	leftovers, err := commands.ParseFlagSetArgs(c.Args, getOrderFlags)
	if err != nil {
		return
	}

	client := commands.GetClient(c)

	var targetURL string
	if len(leftovers) > 0 {
		templateText := strings.Join(leftovers, " ")
		targetURL, err = commands.ClientTemplate(client, templateText)
	} else {
		targetURL, err = commands.FindOrderURL(c, nil, opts.orderIndex)
	}
	if err != nil {
		c.Printf("getAuthz: error getting order URL: %v\n", err)
		return
	}
	order := &resources.Order{
		ID: targetURL,
	}
	err = client.UpdateOrder(order)
	if err != nil {
		c.Printf("getOrder: error getting order: %v\n", err)
		return
	}

	orderStr, err := commands.PrintJSON(order)
	if err != nil {
		c.Printf("getOrder: error serializing order: %v\n", err)
		return
	}
	c.Printf("%s\n", orderStr)
}

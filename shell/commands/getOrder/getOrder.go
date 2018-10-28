package getOrder

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type getOrderOptions struct {
	orderIndex int
}

var (
	opts = getOrderOptions{}
)

func init() {
	registerGetOrderCmd()
}

func registerGetOrderCmd() {
	getOrderFlags := flag.NewFlagSet("getOrder", flag.ContinueOnError)
	getOrderFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")

	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "getOrder",
			Aliases:  []string{"order"},
			Help:     "Get an ACME order URL",
			LongHelp: `TODO(@cpu): Write this!`,
		},
		nil,
		getOrderHandler,
		getOrderFlags)
}

func getOrderHandler(c *ishell.Context, leftovers []string) {
	defer func() {
		opts = getOrderOptions{
			orderIndex: -1,
		}
	}()
	client := commands.GetClient(c)

	var targetURL string
	var err error
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

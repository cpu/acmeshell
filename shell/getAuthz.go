package shell

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
)

type getAuthzOptions struct {
	acmeclient.HTTPOptions
	orderIndex int
	identifier string
}

type getAuthzCmd struct {
	cmd *ishell.Cmd
}

var getAuthz getAuthzCmd = getAuthzCmd{
	cmd: &ishell.Cmd{
		Name:     "getAuthz",
		Aliases:  []string{"authz", "authorization"},
		Func:     getAuthzHandler,
		Help:     "Get an ACME authz URL",
		LongHelp: `TODO(@cpu): Write this!`,
	},
}

func (g getAuthzCmd) New(client *acmeclient.Client) *ishell.Cmd {
	return getAuthz.cmd
}

func getAuthzHandler(c *ishell.Context) {
	opts := getAuthzOptions{}
	getAuthzFlags := flag.NewFlagSet("getAuthz", flag.ContinueOnError)
	getAuthzFlags.BoolVar(&opts.PrintHeaders, "headers", false, "Print HTTP response headers")
	getAuthzFlags.BoolVar(&opts.PrintStatus, "status", true, "Print HTTP response status code")
	getAuthzFlags.BoolVar(&opts.PrintResponse, "response", true, "Print HTTP response body")
	getAuthzFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")
	getAuthzFlags.StringVar(&opts.identifier, "identifier", "", "identifier of authorization")

	err := getAuthzFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("getAuthz: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if opts.orderIndex != -1 && len(getAuthzFlags.Args()) > 0 {
		c.Printf("-order can not be used with a URL\n")
		return
	}

	client := getClient(c)

	var authzURL string
	if len(getAuthzFlags.Args()) == 0 {
		var order *resources.Order
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order, err = getOrderObject(client, orderURL, nil)
			if err != nil {
				c.Printf("getAuthz: error getting order: %s\n", err.Error())
				return
			}
		} else {
			order, err = pickOrder(c)
			if err != nil {
				c.Printf("getAuthz: error picking order: %s\n", err.Error())
				return
			}
		}
		var authz *resources.Authorization
		if opts.identifier != "" {
			for _, authURL := range order.Authorizations {
				a, err := getAuthzObject(client, authURL, nil)
				if err != nil {
					c.Printf("getAuthz: error matching authorization: %s\n", err.Error())
					return
				}
				if a.Identifier.Value == opts.identifier {
					authz = a
					break
				}
			}
			if authz == nil {
				c.Printf("getAuthz: order %q has no authz for identifier %q\n", order.ID, opts.identifier)
				return
			}
		} else {
			authz, err = pickAuthz(c, order)
			if err != nil {
				c.Printf("getAuthz: error picking authz: %s\n", err.Error())
				return
			}
		}
		authzURL = authz.ID
	} else {
		templateText := strings.Join(getAuthzFlags.Args(), " ")
		rendered, err := evalTemplate(templateText, tplCtx{
			client: client,
			acct:   client.ActiveAccount,
		})
		if err != nil {
			c.Printf("getAuthz: order URL templating error: %s\n", err.Error())
			return
		}
		authzURL = rendered
	}

	_, err = getAuthzObject(client, authzURL, &opts.HTTPOptions)
	if err != nil {
		c.Printf("getAuthz: error getting authz: %s\n", err.Error())
		return
	}
}

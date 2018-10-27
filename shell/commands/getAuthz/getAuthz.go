package getauthz

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type getAuthzCmd struct {
	commands.BaseCmd
}

type getAuthzOptions struct {
	orderIndex int
	identifier string
}

var GetAuthzCommand = getAuthzCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "getAuthz",
			Aliases:  []string{"authz", "authorization"},
			Func:     getAuthzHandler,
			Help:     "Get an ACME authz URL",
			LongHelp: `TODO(@cpu): Write this!`,
		},
	},
}

func (g getAuthzCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return GetAuthzCommand.Cmd, nil
}

func getAuthzHandler(c *ishell.Context) {
	opts := getAuthzOptions{}
	getAuthzFlags := flag.NewFlagSet("getAuthz", flag.ContinueOnError)
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

	client := commands.GetClient(c)

	var authzURL string
	if len(getAuthzFlags.Args()) == 0 {
		order := &resources.Order{}
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order.ID = orderURL
			err = client.UpdateOrder(order)
			if err != nil {
				c.Printf("getAuthz: error getting order: %s\n", err.Error())
				return
			}
		} else {
			order, err = commands.PickOrder(c)
			if err != nil {
				c.Printf("getAuthz: error picking order: %s\n", err.Error())
				return
			}
		}
		authz := &resources.Authorization{}
		if opts.identifier != "" {
			var found bool
			for _, authURL := range order.Authorizations {
				authz.ID = authURL
				err := client.UpdateAuthz(authz)
				if err != nil {
					c.Printf("getAuthz: error matching authorization: %s\n", err.Error())
					return
				}
				if authz.Identifier.Value == opts.identifier {
					found = true
					break
				}
			}
			if !found {
				c.Printf("getAuthz: order %q has no authz for identifier %q\n", order.ID, opts.identifier)
				return
			}
		} else {
			authz, err = commands.PickAuthz(c, order)
			if err != nil {
				c.Printf("getAuthz: error picking authz: %s\n", err.Error())
				return
			}
		}
		authzURL = authz.ID
	} else {
		templateText := strings.Join(getAuthzFlags.Args(), " ")
		rendered, err := commands.EvalTemplate(
			templateText,
			commands.TemplateCtx{
				Client: client,
				Acct:   client.ActiveAccount,
			})
		if err != nil {
			c.Printf("getAuthz: order URL templating error: %s\n", err.Error())
			return
		}
		authzURL = rendered
	}

	var authz = &resources.Authorization{
		ID: authzURL,
	}
	err = client.UpdateAuthz(authz)
	if err != nil {
		c.Printf("getAuthz: error getting authz: %s\n", err.Error())
		return
	}

	authzStr, err := commands.PrintJSON(authz)
	if err != nil {
		c.Printf("getAuthz: error serializing authz: %v\n", err)
		return
	}
	c.Printf("%s\n", authzStr)
}

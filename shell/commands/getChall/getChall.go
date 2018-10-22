package getChall

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type getChallCmd struct {
	commands.BaseCmd
}

type getChallOptions struct {
	acmeclient.HTTPOptions
	orderIndex int
	identifier string
	challType  string
}

var GetChallCommand = getChallCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "getChall",
			Aliases:  []string{"challenge", "chall"},
			Func:     getChallHandler,
			Help:     "Get an ACME challenge URL",
			LongHelp: `TODO(@cpu): Write this!`,
		},
	},
}

func (g getChallCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return GetChallCommand.Cmd, nil
}

func getChallHandler(c *ishell.Context) {
	opts := getChallOptions{}
	getChallFlags := flag.NewFlagSet("getChall", flag.ContinueOnError)
	getChallFlags.BoolVar(&opts.PrintHeaders, "headers", false, "Print HTTP response headers")
	getChallFlags.BoolVar(&opts.PrintStatus, "status", true, "Print HTTP response status code")
	getChallFlags.BoolVar(&opts.PrintResponse, "response", true, "Print HTTP response body")
	getChallFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")
	getChallFlags.StringVar(&opts.identifier, "identifier", "", "identifier of authorization")
	getChallFlags.StringVar(&opts.challType, "type", "", "challenge type to get")

	err := getChallFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("getChall: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	client := commands.GetClient(c)

	var challURL string
	if len(getChallFlags.Args()) == 0 {
		var order *resources.Order
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order.ID = orderURL
			err = client.UpdateOrder(order, nil)
			if err != nil {
				c.Printf("getChall: error getting challenge: %s\n", err.Error())
				return
			}
		} else {
			order, err = commands.PickOrder(c)
			if err != nil {
				c.Printf("getChall: error picking order: %s\n", err.Error())
				return
			}
		}
		var authz *resources.Authorization
		if opts.identifier != "" {
			for _, authzURL := range order.Authorizations {
				authz.ID = authzURL
				err := client.UpdateAuthz(authz, nil)
				if err != nil {
					c.Printf("getChall: error matching authorization: %s\n", err.Error())
					return
				}
				if authz.Identifier.Value == opts.identifier {
					break
				}
			}
			if authz == nil {
				c.Printf("getChall: order %q has no authz for identifier %q\n", order.ID, opts.identifier)
				return
			}
		} else {
			authz, err = commands.PickAuthz(c, order)
			if err != nil {
				c.Printf("getChall: error picking authz: %s\n", err.Error())
				return
			}
		}

		var chall *resources.Challenge
		if opts.challType != "" {
			for _, c := range authz.Challenges {
				if c.Type == opts.challType {
					chall = &c
					break
				}
			}
			if chall == nil {
				c.Printf("getChall: authz %q has no challenge with type %q\n", authz.ID, opts.challType)
				return
			}
		} else {
			chall, err = commands.PickChall(c, authz)
			if err != nil {
				c.Printf("getChall: error picking challenge: %s\n", err.Error())
			}
		}
		challURL = chall.URL
	} else {
		templateText := strings.Join(getChallFlags.Args(), " ")
		rendered, err := commands.EvalTemplate(
			templateText,
			commands.TemplateCtx{
				Client: client,
				Acct:   client.ActiveAccount,
			})
		if err != nil {
			c.Printf("getChall: chall URL templating error: %s\n", err.Error())
			return
		}
		challURL = rendered
	}

	chall := &resources.Challenge{
		URL: challURL,
	}
	err = client.UpdateChallenge(chall, nil)
	if err != nil {
		c.Printf("getChall: error getting authz: %s\n", err.Error())
		return
	}
}

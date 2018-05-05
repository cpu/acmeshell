package shell

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
)

type getChallOptions struct {
	acme.HTTPOptions
	orderIndex int
	identifier string
	challType  string
}

type getChallCmd struct {
	cmd *ishell.Cmd
}

var getChall getChallCmd = getChallCmd{
	cmd: &ishell.Cmd{
		Name:     "getChall",
		Aliases:  []string{"challenge", "chall"},
		Func:     getChallHandler,
		Help:     "Get an ACME challenge URL",
		LongHelp: `TODO(@cpu): Write this!`,
	},
}

func (g getChallCmd) New(client *acme.Client) *ishell.Cmd {
	return getChall.cmd
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

	client := getClient(c)

	var challURL string
	if len(getChallFlags.Args()) == 0 {
		var order *acme.Order
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order, err = getOrderObject(client, orderURL, nil)
			if err != nil {
				c.Printf("getChall: error getting challenge: %s\n", err.Error())
				return
			}
		} else {
			order, err = pickOrder(c)
			if err != nil {
				c.Printf("getChall: error picking order: %s\n", err.Error())
				return
			}
		}
		var authz *acme.Authorization
		if opts.identifier != "" {
			for _, authURL := range order.Authorizations {
				a, err := getAuthzObject(client, authURL, nil)
				if err != nil {
					c.Printf("getChall: error matching authorization: %s\n", err.Error())
					return
				}
				if a.Identifier.Value == opts.identifier {
					authz = a
					break
				}
			}
			if authz == nil {
				c.Printf("getChall: order %q has no authz for identifier %q\n", order.ID, opts.identifier)
				return
			}
		} else {
			authz, err = pickAuthz(c, order)
			if err != nil {
				c.Printf("getChall: error picking authz: %s\n", err.Error())
				return
			}
		}

		var chall *acme.Challenge
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
			chall, err = pickChall(c, authz)
			if err != nil {
				c.Printf("getChall: error picking challenge: %s\n", err.Error())
			}
		}
		challURL = chall.URL
	} else {
		templateText := strings.Join(getChallFlags.Args(), " ")
		rendered, err := evalTemplate(templateText, tplCtx{
			client: client,
			acct:   client.ActiveAccount,
		})
		if err != nil {
			c.Printf("getChall: chall URL templating error: %s\n", err.Error())
			return
		}
		challURL = rendered
	}

	_, err = getChallengeObject(client, challURL, &opts.HTTPOptions)
	if err != nil {
		c.Printf("getChall: error getting authz: %s\n", err.Error())
		return
	}
}

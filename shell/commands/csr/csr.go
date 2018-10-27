package csr

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type csrCmd struct {
	commands.BaseCmd
}

type csrOptions struct {
	commonName string
	keyID      string
	pem        bool
	b64url     bool
}

var CSRCommand csrCmd = csrCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "csr",
			Func:     csrHandler,
			Help:     "Generate a CSR",
			LongHelp: `TODO(@cpu): write this`,
		},
	},
}

func (c csrCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return CSRCommand.Cmd, nil
}

func csrHandler(c *ishell.Context) {
	opts := csrOptions{}
	csrFlags := flag.NewFlagSet("csr", flag.ContinueOnError)
	csrFlags.StringVar(&opts.commonName, "cn", "", "CSR Subject Common Name (CN)")
	csrFlags.BoolVar(&opts.pem, "pem", false, "Output CSR in PEM format")
	csrFlags.BoolVar(&opts.b64url, "b64url", true, "Output CSR in base64 URL encoding")
	csrFlags.StringVar(&opts.keyID, "keyID", "", "Existing key ID to use for CSR (Empty to generate and save new key)")
	identifiersArg := csrFlags.String("identifiers", "", "Comma separated list of DNS identifiers")

	err := csrFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("csr: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if *identifiersArg != "" && len(csrFlags.Args()) != 0 {
		c.Printf("csr: can not specify -identifiers and an order URL\n")
		return
	}

	client := commands.GetClient(c)

	var order *resources.Order
	if len(csrFlags.Args()) == 0 && *identifiersArg == "" {
		orders := client.ActiveAccount.Orders
		if len(orders) == 0 {
			c.Printf("csr: the active account has no orders to create a CSR for\n")
			return
		}

		if !opts.pem && !opts.b64url {
			c.Printf("csr: must set either pem or b64url output to true\n")
			return
		}

		orderList := make([]string, len(client.ActiveAccount.Orders))
		for i, order := range client.ActiveAccount.Orders {
			line := fmt.Sprintf("%3d)", i)
			line += fmt.Sprintf("\t%#q", order)

			// TODO(@cpu): Restore the identifiers here
			/*
				var domains []string
				for _, d := range order.Identifiers {
					domains = append(domains, d.Value)
				}
				line += fmt.Sprintf("\t%s", strings.Join(domains, ","))
			*/
			orderList[i] = line
		}

		choice := c.MultiChoice(orderList, "Which order would you like to create a CSR for?")
		order, err = getOrderObject(client, orderList[choice])
		if err != nil {
			c.Printf("csr: error getting order: %s", err.Error())
			return
		}
	} else if *identifiersArg == "" {
		templateText := strings.Join(csrFlags.Args(), " ")
		rendered, err := commands.EvalTemplate(
			templateText,
			commands.TemplateCtx{
				Client: client,
				Acct:   client.ActiveAccount,
			})
		if err != nil {
			c.Printf("csr: order URL templating error: %s\n", err.Error())
			return
		}
		order, err = getOrderObject(client, rendered)
		if err != nil {
			c.Printf("csr: error getting order: %s", err.Error())
			return
		}
	}

	var idents []string
	if *identifiersArg == "" {
		// shouldn't happen
		if order == nil {
			c.Printf("csr: order was nil\n")
			return
		}
		names := make([]string, len(order.Identifiers))
		for i, ident := range order.Identifiers {
			names[i] = ident.Value
		}
		idents = names
	} else {
		idents = strings.Split(*identifiersArg, ",")
	}

	b64CSR, pemCSR, err := client.CSR(opts.commonName, idents, opts.keyID)
	if err != nil {
		c.Printf("csr: error creating CSR for identifiers %v: %s\n",
			idents, err.Error())
		return
	}

	if opts.b64url {
		c.Printf("Base64URL: \n%s\n", b64CSR)
	}

	if opts.pem {
		c.Printf("PEM: \n%s\n", pemCSR)
	}
}

// TODO(@cpu): Delete this - it's redundant with client methods
func getOrderObject(client *acmeclient.Client, orderURL string) (*resources.Order, error) {
	var order resources.Order
	resp, err := client.GetURL(orderURL)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(resp.RespBody, &order)
	if err != nil {
		return nil, err
	}
	order.ID = orderURL
	return &order, nil
}

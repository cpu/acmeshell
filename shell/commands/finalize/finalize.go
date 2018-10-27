package finalize

import (
	"encoding/json"
	"flag"
	"net/http"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type finalizeCmd struct {
	commands.BaseCmd
}

type finalizeOptions struct {
	csr        string
	keyID      string
	commonName string
	orderIndex int
}

var FinalizeCommand = finalizeCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "finalize",
			Aliases:  []string{"finalizeOrder"},
			Func:     finalizeHandler,
			Help:     "Finalize an ACME order with a CSR",
			LongHelp: `TODO(@cpu): Write this!`,
		},
	},
}

func (fc finalizeCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return FinalizeCommand.Cmd, nil
}

func finalizeHandler(c *ishell.Context) {
	opts := finalizeOptions{}
	finalizeFlags := flag.NewFlagSet("finalize", flag.ContinueOnError)
	finalizeFlags.StringVar(&opts.csr, "csr", "", "base64url encoded CSR")
	finalizeFlags.StringVar(&opts.keyID, "keyID", "", "keyID to use for generating a CSR")
	finalizeFlags.StringVar(&opts.commonName, "cn", "", "subject common name (CN) for generated CSR")
	finalizeFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")

	err := finalizeFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("finalize: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if opts.csr != "" && opts.keyID != "" {
		c.Printf("finalize: -csr and -keyID are mutually exclusive\n")
		return
	}

	if opts.csr != "" && opts.commonName != "" {
		c.Printf("finalize: -csr and -cn are mutually exclusive\n")
		return
	}

	client := commands.GetClient(c)

	var orderURL string
	if len(finalizeFlags.Args()) == 0 {
		order := &resources.Order{}
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order.ID = orderURL
			err = client.UpdateOrder(order)
			if err != nil {
				c.Printf("finalize: error getting order: %s\n", err.Error())
				return
			}
		} else {
			order, err = commands.PickOrder(c)
			if err != nil {
				c.Printf("finalize: error picking order to finalize: %s\n", err.Error())
				return
			}
		}
		orderURL = order.ID
	} else {
		templateText := strings.Join(finalizeFlags.Args(), " ")
		rendered, err := commands.EvalTemplate(
			templateText, commands.TemplateCtx{
				Client: client,
				Acct:   client.ActiveAccount,
			})
		if err != nil {
			c.Printf("finalize: order URL templating error: %s\n", err.Error())
			return
		}
		orderURL = rendered
	}

	var order = &resources.Order{
		ID: orderURL,
	}
	err = client.UpdateOrder(order)
	if err != nil {
		c.Printf("finalize: error getting order: %s\n", err.Error())
		return
	}

	var b64csr string
	if opts.csr != "" {
		b64csr = opts.csr
	} else {
		names := make([]string, len(order.Identifiers))
		for i, ident := range order.Identifiers {
			names[i] = ident.Value
		}
		csr, _, err := client.CSR(opts.commonName, names, opts.keyID)
		if err != nil {
			c.Printf("finalize: error creating csr: %s\n", err.Error())
			return
		}
		b64csr = string(csr)
	}

	finalizeRequest := struct {
		CSR string
	}{
		CSR: b64csr,
	}
	finalizeRequestJSON, _ := json.Marshal(&finalizeRequest)

	signResult, err := client.Sign(order.Finalize, finalizeRequestJSON, nil)
	if err != nil {
		c.Printf("finalize: failed to sign finalize POST body: %s\n", err.Error())
		return
	}

	resp, err := client.PostURL(order.Finalize, signResult.SerializedJWS)
	if err != nil {
		c.Printf("finalize: failed to POST order finalization URL %q: %v\n", order.Finalize, err)
		return
	}
	respOb := resp.Response
	if respOb.StatusCode != http.StatusOK {
		c.Printf("finalize: failed to POST order finalization URL %q . Status code: %d\n", order.Finalize, respOb.StatusCode)
		c.Printf("finalize: response body: %s\n", resp.RespBody)
		return
	}
	c.Printf("order %q finalization requested\n", order.ID)
}

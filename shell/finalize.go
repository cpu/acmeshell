package shell

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
)

type finalizeOptions struct {
	csr        string
	keyID      string
	commonName string
	orderIndex int
}

type finalizeCmd struct {
	cmd *ishell.Cmd
}

var finalize finalizeCmd = finalizeCmd{
	cmd: &ishell.Cmd{
		Name:     "finalize",
		Aliases:  []string{"finalizeOrder"},
		Func:     finalizeHandler,
		Help:     "Finalize an ACME order with a CSR",
		LongHelp: `TODO(@cpu): Write this!`,
	},
}

func (fc finalizeCmd) New(client *acmeclient.Client) *ishell.Cmd {
	return finalize.cmd
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

	client := getClient(c)

	var orderURL string
	if len(finalizeFlags.Args()) == 0 {
		var order *resources.Order
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order, err = getOrderObject(client, orderURL, nil)
			if err != nil {
				c.Printf("finalize: error getting order: %s\n", err.Error())
				return
			}
		} else {
			order, err = pickOrder(c)
			if err != nil {
				c.Printf("finalize: error picking order to finalize: %s\n", err.Error())
				return
			}
		}
		orderURL = order.ID
	} else {
		templateText := strings.Join(finalizeFlags.Args(), " ")
		rendered, err := evalTemplate(templateText, tplCtx{
			client: client,
			acct:   client.ActiveAccount,
		})
		if err != nil {
			c.Printf("finalize: order URL templating error: %s\n", err.Error())
			return
		}
		orderURL = rendered
	}

	order, err := getOrderObject(client, orderURL, nil)
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
		csr, _, err := csr(client, csrOptions{
			keyID:      opts.keyID,
			commonName: opts.commonName,
		}, names)
		if err != nil {
			c.Printf("finalize: error creating csr: %s\n", err.Error())
			return
		}
		b64csr = csr
	}

	finalizeRequest := struct {
		CSR string
	}{
		CSR: b64csr,
	}
	finalizeRequestJSON, _ := json.Marshal(&finalizeRequest)

	signedBody, err := client.ActiveAccount.Sign(order.Finalize, finalizeRequestJSON, resources.SignOptions{
		NonceSource:    client,
		PrintJWS:       false,
		PrintJWSObject: false,
		PrintJSON:      false,
	})
	if err != nil {
		c.Printf("finalize: failed to sign finalize POST body: %s\n", err.Error())
		return
	}

	postOpts := &acmeclient.HTTPOptions{
		PrintHeaders:  false,
		PrintStatus:   false,
		PrintResponse: false,
	}

	respCtx := client.PostURL(order.Finalize, signedBody, postOpts)
	if respCtx.Err != nil {
		c.Printf("finalize: failed to POST order finalization URL %q: %s\n", order.Finalize, respCtx.Err.Error())
		return
	}
	if respCtx.Resp.StatusCode != http.StatusOK {
		c.Printf("finalize: failed to POST order finalization URL %q . Status code: %d\n", order.Finalize, respCtx.Resp.StatusCode)
		c.Printf("finalize: response body: %s\n", respCtx.Body)
		return
	}
	c.Printf("order %q finalization requested\n", order.ID)
}

func pickOrder(c *ishell.Context) (*resources.Order, error) {
	client := getClient(c)
	if len(client.ActiveAccount.Orders) == 0 {
		return nil, fmt.Errorf("active account has no orders")
	}

	orderList := make([]string, len(client.ActiveAccount.Orders))
	for i, order := range client.ActiveAccount.Orders {
		line := fmt.Sprintf("%3d)", i)
		line += fmt.Sprintf("\t%#q", order)

		// TODO(@cpu): Restore identifiers
		/*
			var domains []string
			for _, d := range order.Identifiers {
				domains = append(domains, d.Value)
			}
			line += fmt.Sprintf("\t%s", strings.Join(domains, ","))
		*/
		orderList[i] = line
	}

	choice := c.MultiChoice(orderList, "Select an order")
	orderURL := client.ActiveAccount.Orders[choice]
	order, err := getOrderObject(client, orderURL, nil)
	if err != nil {
		return nil, err
	}
	return order, nil
}

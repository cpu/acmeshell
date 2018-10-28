package finalize

import (
	"encoding/json"
	"flag"
	"net/http"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type finalizeOptions struct {
	csr        string
	keyID      string
	commonName string
	orderIndex int
}

var (
	opts finalizeOptions
)

const (
	longHelp = `TODO(@cpu): Write longHelp for finalize cmd`
)

func init() {
	registerFinalizeCmd()
}

func registerFinalizeCmd() {
	finalizeFlags := flag.NewFlagSet("finalize", flag.ContinueOnError)
	finalizeFlags.StringVar(&opts.csr, "csr", "", "base64url encoded CSR")
	finalizeFlags.StringVar(&opts.keyID, "keyID", "", "keyID to use for generating a CSR")
	finalizeFlags.StringVar(&opts.commonName, "cn", "", "subject common name (CN) for generated CSR")
	finalizeFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")

	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "finalize",
			Aliases:  []string{"finalizeOrder"},
			Help:     "Finalize an ACME order with a CSR",
			LongHelp: longHelp,
		},
		nil,
		finalizeHandler,
		finalizeFlags)
}

func finalizeHandler(c *ishell.Context, leftovers []string) {
	defer func() {
		opts = finalizeOptions{
			orderIndex: -1,
		}
	}()

	if opts.csr != "" && opts.keyID != "" {
		c.Printf("finalize: -csr and -keyID are mutually exclusive\n")
		return
	}

	if opts.csr != "" && opts.commonName != "" {
		c.Printf("finalize: -csr and -cn are mutually exclusive\n")
		return
	}

	client := commands.GetClient(c)

	targetURL, err := commands.FindOrderURL(c, leftovers, opts.orderIndex)
	if err != nil {
		c.Printf("finalize: error getting order URL: %v\n", err)
		return
	}

	order := &resources.Order{
		ID: targetURL,
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

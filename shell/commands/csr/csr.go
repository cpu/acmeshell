package csr

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type csrOptions struct {
	rawIdentifiers string
	commonName     string
	keyID          string
	pem            bool
	b64url         bool
	orderIndex     int
}

var (
	opts = csrOptions{}
)

func init() {
	registerCSRCmd()
}

func registerCSRCmd() {
	csrFlags := flag.NewFlagSet("csr", flag.ContinueOnError)
	csrFlags.StringVar(&opts.commonName, "cn", "", "CSR Subject Common Name (CN)")
	csrFlags.BoolVar(&opts.pem, "pem", false, "Output CSR in PEM format")
	csrFlags.BoolVar(&opts.b64url, "b64url", true, "Output CSR in base64 URL encoding")
	csrFlags.StringVar(&opts.keyID, "keyID", "", "Existing key ID to use for CSR (Empty to generate and save new key)")
	csrFlags.StringVar(&opts.rawIdentifiers, "identifiers", "", "Comma separated list of DNS identifiers")
	csrFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "csr",
			Help:     "Generate a CSR",
			LongHelp: `TODO(@cpu): write this`,
		},
		nil,
		csrHandler,
		csrFlags)
}

func csrHandler(c *ishell.Context, leftovers []string) {
	defer func() {
		opts = csrOptions{
			b64url:     true,
			orderIndex: -1,
		}
	}()

	if opts.rawIdentifiers != "" && len(leftovers) != 0 {
		c.Printf("csr: can not specify -identifiers and an order URL\n")
		return
	}

	if !opts.pem && !opts.b64url {
		c.Printf("csr: must set either pem or b64url output to true\n")
		return
	}

	client := commands.GetClient(c)

	var idents []string
	if opts.rawIdentifiers == "" {
		orderURL, err := commands.FindOrderURL(c, leftovers, opts.orderIndex)
		if err != nil {
			c.Printf("csr: error getting order URL: %v\n", err)
			return
		}
		order := &resources.Order{
			ID: orderURL,
		}
		err = client.UpdateOrder(order)
		if err != nil {
			c.Printf("csr: error getting order URL: %v\n", err)
			return
		}
		for _, ident := range order.Identifiers {
			idents = append(idents, ident.Value)
		}
	} else {
		idents = strings.Split(opts.rawIdentifiers, ",")
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

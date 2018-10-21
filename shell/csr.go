package shell

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
)

type csrCmd struct {
	cmd *ishell.Cmd
}

type csrOptions struct {
	commonName string
	keyID      string
	pem        bool
	b64url     bool
}

var CSR csrCmd = csrCmd{
	cmd: &ishell.Cmd{
		Name:     "csr",
		Func:     csrHandler,
		Help:     "Generate a CSR",
		LongHelp: `TODO(@cpu): write this`,
	},
}

func (c csrCmd) New(client *acmeclient.Client) *ishell.Cmd {
	return CSR.cmd
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

	client := getClient(c)

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
		order, err = getOrderObject(client, orderList[choice], nil)
		if err != nil {
			c.Printf("csr: error getting order: %s", err.Error())
			return
		}
	} else if *identifiersArg == "" {
		templateText := strings.Join(csrFlags.Args(), " ")
		rendered, err := evalTemplate(templateText, tplCtx{
			client: client,
			acct:   client.ActiveAccount,
		})
		if err != nil {
			c.Printf("csr: order URL templating error: %s\n", err.Error())
			return
		}
		order, err = getOrderObject(client, rendered, nil)
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

	b64CSR, pemCSR, err := csr(client, opts, idents)
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

func csr(client *acmeclient.Client, opts csrOptions, names []string) (string, string, error) {
	if len(names) == 0 {
		return "", "", fmt.Errorf("no names specified")
	}

	if opts.commonName == "" {
		opts.commonName = names[0]
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: opts.commonName,
		},
		DNSNames: names,
	}

	var privateKey *ecdsa.PrivateKey
	if opts.keyID != "" {
		if key, found := client.Keys[opts.keyID]; !found {
			return "", "", fmt.Errorf("no existing key in shell for key ID %q", opts.keyID)
		} else {
			privateKey = key
		}
	} else {
		// save a new random key for the names
		privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		client.Keys[strings.Join(names, ",")] = privateKey
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", "", err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBytes,
	})

	return base64.RawURLEncoding.EncodeToString(csrBytes), string(pemBytes), nil
}

func getOrderObject(client *acmeclient.Client, orderURL string, opts *acmeclient.HTTPOptions) (*resources.Order, error) {
	var order resources.Order
	if opts == nil {
		opts = &acmeclient.HTTPOptions{
			PrintHeaders:  false,
			PrintStatus:   false,
			PrintResponse: false,
		}
	}
	respCtx := client.GetURL(orderURL, opts)
	if respCtx.Err != nil {
		return nil, respCtx.Err
	}
	err := json.Unmarshal(respCtx.Body, &order)
	if err != nil {
		return nil, err
	}
	order.ID = orderURL
	return &order, nil
}

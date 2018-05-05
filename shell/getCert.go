package shell

import (
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
)

type getCertOptions struct {
	printPEM   bool
	pemPath    string
	orderIndex int
}

type getCertCmd struct {
	cmd *ishell.Cmd
}

var getCert getCertCmd = getCertCmd{
	cmd: &ishell.Cmd{
		Name:     "getCert",
		Aliases:  []string{"cert", "getCertificate", "certificate"},
		Func:     getCertHandler,
		Help:     "Get an order's certificate",
		LongHelp: `TODO(@cpu): Write this!`,
	},
}

func (gc getCertCmd) New(client *acme.Client) *ishell.Cmd {
	return getCert.cmd
}

func getCertHandler(c *ishell.Context) {
	opts := getCertOptions{}
	getCertFlags := flag.NewFlagSet("getCert", flag.ContinueOnError)
	getCertFlags.BoolVar(&opts.printPEM, "pem", true, "print PEM certificate chain output")
	getCertFlags.StringVar(&opts.pemPath, "path", "", "file path to save PEM certificate chain output to")
	getCertFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")

	err := getCertFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("getCert: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if !opts.printPEM && opts.pemPath == "" {
		c.Printf("getCert: one of -pem or -path must be provided\n")
		return
	}

	client := getClient(c)

	var orderURL string
	if len(getCertFlags.Args()) == 0 {
		var order *acme.Order
		if opts.orderIndex >= 0 && opts.orderIndex < len(client.ActiveAccount.Orders) {
			orderURL := client.ActiveAccount.Orders[opts.orderIndex]
			order, err = getOrderObject(client, orderURL, nil)
			if err != nil {
				c.Printf("getCert: error getting order: %s\n", err.Error())
				return
			}
		} else {
			order, err = pickOrder(c)
			if err != nil {
				c.Printf("getCert: error picking order: %s\n", err.Error())
				return
			}
		}
		orderURL = order.ID
	} else {
		templateText := strings.Join(getCertFlags.Args(), " ")
		rendered, err := evalTemplate(templateText, tplCtx{
			client: client,
			acct:   client.ActiveAccount,
		})
		if err != nil {
			c.Printf("getCert: order URL templating error: %s\n", err.Error())
			return
		}
		orderURL = rendered
	}

	order, err := getOrderObject(client, orderURL, nil)
	if err != nil {
		c.Printf("getCert: error getting order: %s\n", err.Error())
		return
	}

	if order.Status != "valid" {
		c.Printf("getCert: order %q is status %q, not \"valid\"\n", order.ID, order.Status)
		return
	}

	if order.Certificate == "" {
		c.Printf("getCert: order %q has no Certificate URL\n", order.ID)
		return
	}

	httpOpts := &acme.HTTPOptions{
		PrintHeaders:  false,
		PrintStatus:   false,
		PrintResponse: false,
	}
	respCtx := client.GetURL(order.Certificate, httpOpts)
	if respCtx.Err != nil {
		c.Printf("getCert: failed to GET order certificate URL %q : %d\n", order.Certificate, respCtx.Err.Error())
		return
	}
	if respCtx.Resp.StatusCode != http.StatusOK {
		c.Printf("getCert: failed to GET order certificate URL %q . Status code: %d\n", order.Certificate, respCtx.Resp.StatusCode)
		c.Printf("getCert: response body: %s\n", respCtx.Body)
		return
	}

	if opts.printPEM {
		c.Printf("%s", string(respCtx.Body))
	}

	if opts.pemPath != "" {
		err := ioutil.WriteFile(opts.pemPath, respCtx.Body, os.ModePerm)
		if err != nil {
			c.Printf("getCert: error writing pem to %q: %s\n", opts.pemPath, err.Error())
			return
		}
		c.Printf("getCert: cert chain saved to %q\n", opts.pemPath)
	}
}

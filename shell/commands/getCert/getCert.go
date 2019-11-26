package getCert

import (
	"flag"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/net"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "getCert",
			Aliases:  []string{"cert", "getCertificate", "certificate"},
			Help:     "Get an order's certificate",
			LongHelp: `TODO(@cpu): Write this!`,
		},
		nil,
		getCertHandler,
		nil)
}

type getCertOptions struct {
	printPEM   bool
	pemPath    string
	orderIndex int
}

func getCertHandler(c *ishell.Context, args []string) {
	opts := getCertOptions{}
	getCertFlags := flag.NewFlagSet("getCert", flag.ContinueOnError)
	getCertFlags.BoolVar(&opts.printPEM, "pem", true, "print PEM certificate chain output")
	getCertFlags.StringVar(&opts.pemPath, "path", "", "file path to save PEM certificate chain output to")
	getCertFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")

	leftovers, err := commands.ParseFlagSetArgs(args, getCertFlags)
	if err != nil {
		return
	}

	if !opts.printPEM && opts.pemPath == "" {
		c.Printf("getCert: one of -pem or -path must be provided\n")
		return
	}

	client := commands.GetClient(c)

	targetURL, err := commands.FindOrderURL(c, leftovers, opts.orderIndex)
	if err != nil {
		c.Printf("getCert: error getting order URL: %v\n", err)
		return
	}

	order := &resources.Order{
		ID: targetURL,
	}
	err = client.UpdateOrder(order)
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

	var resp *net.NetResponse
	if client.PostAsGet {
		resp, err = client.PostAsGetURL(order.Certificate)
	} else {
		resp, err = client.GetURL(order.Certificate)
	}
	if err != nil {
		c.Printf("getCert: failed to GET order certificate URL %q : %v\n", order.Certificate, err)
		return
	}
	respOb := resp.Response
	if respOb.StatusCode != http.StatusOK {
		c.Printf("getCert: failed to GET order certificate URL %q . Status code: %d\n", order.Certificate, respOb.StatusCode)
		c.Printf("getCert: response body: %s\n", resp.RespBody)
		return
	}

	if opts.printPEM {
		c.Printf("%s", string(resp.RespBody))
	}

	if opts.pemPath != "" {
		err := ioutil.WriteFile(opts.pemPath, resp.RespBody, os.ModePerm)
		if err != nil {
			c.Printf("getCert: error writing pem to %q: %s\n", opts.pemPath, err.Error())
			return
		}
		c.Printf("getCert: cert chain saved to %q\n", opts.pemPath)
	}
}

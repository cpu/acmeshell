// Package post implements an ACMEShell command for POSTing requests to an ACME
// server.
package post

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

type postOptions struct {
	postBodyString string
	templateBody   bool
	sign           bool
	noData         bool
}

var (
	opts = postOptions{}
)

const (
	longHelp = `
	post [acme endpoint]:
		Send an HTTP POST request to the URL that is contained in the ACME server's
		directory object under the specified endpoint name. You will be prompted
		interactively for the POST body (unless specified).

		Examples:
			post newOrder
				Send an HTTP POST to the "newOrder" key from the ACME server's directory
				object. The POST body will be read from stdin interactively.

			post -body='{"identifiers":[{"type":"dns", "value":"localhost.com"}]}' newOrder
				Send an HTTP POST with the given JSON body to the "newOrder" key from
				the ACME server's directory object.

	post [url]:
		Send an HTTP POST request to the URL specified.

		Examples:
			post https://acme-staging-v02.api.letsencrypt.org/acme/newOrder
				Send an HTTP POST to the Let's Encrypt V2 API's newOrder URL.
	`
)

func init() {
	registerPostCommand()
}

func registerPostCommand() {
	postFlags := flag.NewFlagSet("post", flag.ContinueOnError)
	postFlags.StringVar(&opts.postBodyString, "body", "", "HTTP POST request body")
	postFlags.BoolVar(&opts.templateBody, "templateBody", true, "Template HTTP POST body")
	postFlags.BoolVar(&opts.sign, "sign", true, "Sign body with active account key")
	postFlags.BoolVar(&opts.noData, "noData", false, "Skip -body and assume no data POST-as-GET")

	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "post",
			Aliases:  []string{"postURL"},
			Help:     "Send an HTTP POST to a ACME endpoint or a URL",
			LongHelp: longHelp,
		},
		commands.DirectoryAutocompleter,
		postHandler,
		postFlags)
}

func postHandler(c *ishell.Context, leftovers []string) {
	// Reset options to default after handling
	defer func() {
		opts = postOptions{
			templateBody: true,
			sign:         true,
		}
	}()

	client := commands.GetClient(c)

	targetURL, err := commands.FindURL(client, leftovers)
	if err != nil {
		c.Printf("post: error finding URL: %v", err)
		return
	}

	// Check the URL and make sure it is valid-ish
	if !commands.OkURL(targetURL) {
		c.Printf("post: illegal url argument %q\n", targetURL)
		return
	}

	trimmedBodyArg := strings.TrimSpace(opts.postBodyString)
	var body []byte

	if len(trimmedBodyArg) > 0 && opts.noData {
		c.Printf("post: -body and -noData are mutually exclusive\n")
		return
	} else if len(trimmedBodyArg) > 0 {
		body = []byte(trimmedBodyArg)
	} else if !opts.noData {
		// Otherwise, read the POST body interactively
		inputJSON := commands.ReadJSON(c)
		if inputJSON == "" {
			c.Printf("post: no POST body provided\n")
			return
		}
		body = []byte(inputJSON)
	} else {
		body = []byte("")
	}

	if opts.templateBody {
		// Render the body input as a template
		rendered, err := commands.ClientTemplate(client, string(body))
		if err != nil {
			c.Printf("post: warning: target URL templating error: %s\n", err.Error())
			return
		}
		body = []byte(rendered)
	}

	postURL(c, targetURL, body, opts.sign)
}

func postURL(c *ishell.Context, targetURL string, body []byte, sign bool) {
	client := commands.GetClient(c)
	account := client.ActiveAccount

	if sign {
		if account == nil {
			c.Printf("post: no active ACME account to authenticate POST requests\n")
			return
		}
		signResult, err := client.Sign(targetURL, body, nil)
		if err != nil {
			c.Printf("post: error signing POST request body: %s\n", err)
			return
		}
		body = signResult.SerializedJWS
	}

	resp, err := client.PostURL(targetURL, body)
	if err != nil {
		c.Printf("post: error POSTing signed request body to URL: %v\n", err)
		return
	}
	c.Printf("%s\n", resp.RespBody)
}
